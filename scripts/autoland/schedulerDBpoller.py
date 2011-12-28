try:
    import json
except ImportError:
    import simplejson as json
import sys, os, traceback, urllib2, urllib, re
from time import time, strftime, strptime, localtime, mktime, gmtime
from argparse import ArgumentParser
from utils.db_handler import DBHandler
import ConfigParser
import utils.bz_utils as bz_utils
import utils.mq_utils as mq_utils
import logging, logging.handlers

FORMAT="%(asctime)s - %(module)s - %(funcName)s - %(message)s"
LOGFILE='schedulerDBpoller.log'
POSTED_BUGS='postedbugs.log'
POLLING_INTERVAL=14400 # 4 hours
TIMEOUT=21600 # 6 hours
MAX_POLLING_INTERVAL=172800 # 48 hours
COMPLETION_THRESHOLD=600 # 10 minutes
MAX_ORANGE = 2

# console logging, formatted
logging.basicConfig(format=FORMAT)
# sets up a rotating logfile that's written to the working dir
log = logging.getLogger(LOGFILE)

class SchedulerDBPoller():

    def __init__(self, branch, cache_dir, config,
                user=None, password=None, dry_run=False, verbose=False):

        self.config = ConfigParser.ConfigParser()
        self.config.read(config)
        self.branch = branch
        self.cache_dir = cache_dir
        self.dry_run = dry_run
        self.verbose = verbose
        
        # Set up the message queue
        self.mq = mq_utils.mq_util()
        self.mq.set_host(self.config.get('mq', 'host'))
        self.mq.set_exchange(self.config.get('mq', 'exchange'))
        
        # Set up bugzilla api connection
        self.bz_url = self.config.get('bz', 'url')
        self.bz = bz_utils.bz_util(self.config.get('bz', 'api_url'), self.config.get('bz', 'url'),
                        None, self.config.get('bz', 'username'), self.config.get('bz', 'password'))

        # Set up Self-Serve API
        self.self_serve_api_url = self.config.get('self_serve', 'url')
        if user != None:
            self.user = user
        else:
            self.user = self.config.get('self_serve', 'user')
        
        if password !=None:
            self.password = password
        else:
            self.password = self.config.get('self_serve', 'password')

        # Set up database handler
        self.scheduler_db = DBHandler(self.config.get('databases', 'scheduler_db_url'))

    def revisionTimedOut(self, revision, timeout=TIMEOUT):
        """ Read the cache file for a revision and return if the build has timed out """
        timed_out = False
        now = time()
        revisions, completed_revisions = self.LoadCache()
        if revision in revisions.keys():
            filename = os.path.join(self.cache_dir, revision)
            if os.path.exists(filename):
                try:
                    f = open(filename, 'r')
                    entries = f.readlines()
                    f.close()
                except IOError, e:
                    log.error("Couldn't open cache file for rev: %s" % revision)
                    raise
                first_entry = mktime(strptime(entries[0].split('|')[0], "%a, %d %b %Y %H:%M:%S %Z"))
                diff = now - first_entry
                if diff > timeout:
                    log.debug("Timeout on rev: %s " % revision)
                    timed_out = True
        return timed_out

    def OrangeFactorHandling(self, buildrequests):
        """ Checks buildrequests results if all success except # warnings is <= MAX_ORANGE
    
            * Check if the buildername with warning result is duplicated in requests
            * If not, triggers a rebuild using self-serve API of that buildernames's buildid
            * If yes, check the results of the pair and report back success/fail based on:
                orange:green == Success, intermittent orange
                orange:orange == Failed on retry
        
        returns: 
            is_complete {True,False} 
            final_status {'success', 'failure', None}
        """
        is_complete = None
        final_status = None
        results = self.CalculateResults(buildrequests)
        if self.verbose:
            log.debug("RESULTS (OrangeFactorHandling): %s" % results)
        if results['total_builds'] == results['success'] + results['failure'] + results['other'] + results['skipped'] + results['exception']:
            # It's really complete, now check for success
            if results['total_builds'] == results['success']:
                is_complete = True
                final_status = "success"
                if self.verbose:
                    log.debug("Complete and a success")
            else:
                is_complete = True
                final_status = "failure"
                if self.verbose:
                    log.debug("Complete and a failure")
        elif results['total_builds'] - results['warnings'] == results['success'] and results['warnings'] <= (MAX_ORANGE * 2):
                # Get buildernames where result was warnings
                buildernames = {}
                for key, value in buildrequests.items():
                    br = value.to_dict()
                    # Collect duplicate buildernames
                    if not buildernames.has_key(br['buildername']):
                        buildernames[br['buildername']] = [(br['results_str'], br['branch'], br['bid'])]
                    else:
                        buildernames[br['buildername']].append((br['results_str'], br['branch'], br['bid']))
                retry_count = 0
                retry_pass = 0
                for name, info in buildernames.items():
                    # If we have more than one result for a builder name, compare the results
                    if len(info) == 2:
                        if self.verbose:
                            log.debug("WE HAVE A DUPE: %s" % name)
                        retry_count += 1
                        c =  zip(info[0],info[1])
                        if len(set(c[0])) > 1:
                            if self.verbose:
                                log.debug("We have a mismatch in %s" % set(c[0]))
                            # We have a mismatch of results - is one a success?
                            if 'success' in c[0]:
                                if self.verbose:
                                    log.debug("There's a success, incrementing retry_pass")
                                retry_pass += 1
                    # Unique buildername with warnings, attempt a rebuild
                    else:
                        for result, branch, bid in info:
                            if result == 'warnings':
                                if self.verbose:
                                    log.debug("Attempting to retry branch: %s bid: %s" % (branch, bid))
                                try:
                                    post = self.SelfServeRebuild(bid)
                                    is_complete = False
                                    final_status = "retrying"
                                except:
                                    is_complete = True
                                    final_status = "failure"
                # Passed on Retry
                if retry_count != 0 and retry_pass == retry_count:
                    is_complete = True
                    final_status = "success"
                # Failed on Retry
                elif retry_count != 0:
                    is_complete = True
                    final_status = "failure"
        else:
            # too many warnings, no point retrying builds
            if self.verbose:
                log.debug("Too many warnings! Final = failure")
            is_complete = True
            final_status = "failure"

        return is_complete, final_status
    
    def SelfServeRebuild(self, buildid):
        """ Uses self-serve API to retrigger the buildid/branch sent in with a POST request"""        
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None,
                                  uri=self.self_serve_api_url,
                                  user=self.user,
                                  passwd=self.password)
        auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        opener = urllib2.build_opener(auth_handler, urllib2.HTTPSHandler())       
        opener.addheaders = [
         ('Content-Type', 'application/json'),
         ('Accept', 'application/json'),
         ]
        urllib2.install_opener(opener)
        data = urllib.urlencode({"build_id": buildid})
        url = self.self_serve_api_url + "/" + self.branch
        try:
            req = urllib2.Request(url, data)
            req.method = "POST"
            return json.loads(opener.open(req).read())
        except urllib2.HTTPError, e:
            log.debug("FAIL attempted rebuild for %s:%s -- %s" % (self.branch, buildid, e))
            raise
    
    def GetSingleAuthor(self, buildrequests):
        """Look through a list of buildrequests and return only one author from the changes if one exists"""
        author = None
        for key, value in buildrequests.items():
          br = value.to_dict()
          if author == None:
              author = br['authors']
        # if there's one author return it
        if len(author) == 1:
            return ''.join(author)
        elif author != None:
            log.error("More than one author for: %s" % br)
    
    def GetBugNumbers(self, buildrequests):
        """Look through a list of buildrequests and return bug number from push comments"""
        bugs = []
        for key,value in buildrequests.items():
            br = value.to_dict()
            for comment in br['comments']:
                # we only want the bug specified in try syntax
                if len(comment.split('try: ')) > 1:
                    comment = comment.split('try: ')[1]
                    bugs = self.bz.bugs_from_comments(comment)
        return bugs
    
    def ProcessPushType(self, revision, buildrequests):
        """ Search buildrequest comments for try syntax and query autoland_db 
            
       returns type as "try", "auto", or None
        
            try: if "try: --post-to-bugzilla" is present in the comments of a buildrequest
            auto: if a check for 'autoland-' in the comments returns True (for future branch landings)
            None: if not try request and Autoland system isn't tracking it
        """
    
        type = None
        for key,value in buildrequests.items():
            br = value.to_dict()
            for comments in br['comments']:
                if 'try: ' in comments and '--post-to-bugzilla' in comments:
                    type = "try"
                if 'autoland-' in comments:
                    type = "auto"
        return type
    
    def CalculateResults(self, buildrequests):
        """ Returns dictionary of the results for the buildrequests passed in """
    
        results = {
            'success': 0,
            'warnings': 0,
            'failure': 0,
            'skipped': 0,
            'exception': 0,
            'other': 0,
            'total_builds': 0
        }
        for key,value in buildrequests.items():
            br = value.to_dict()
            # Do the tallying of statuses
            if br['results_str'].lower() in results.keys():
                results[br['results_str'].lower()] += 1
            else:
                results['other'] += 1
        results['total_builds'] = sum(results.values())
        return results
    
    def GenerateResultReportMessage(self, revision, report, author=None):
        """ Returns formatted message of revision report"""
        if self.verbose:
            log.debug("REPORT: %s" % report)

        message = """Try run for %s is complete.
Detailed breakdown of the results available here:
    https://tbpl.mozilla.org/?tree=%s&rev=%s
Results (out of %d total builds):\n""" % (revision, self.branch.title(), 
                                            revision, report['total_builds'])
        for key, value in report.items():
            if value > 0 and key != 'total_builds':
                message += "    %s: %d\n" % (key, value)
        if author != None:
            message += """Builds (or logs if builds failed) available at:
http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/%(author)s-%(revision)s""" % locals()
        return message
    
    def WriteToBuglist(self, revision, bug, filename=POSTED_BUGS):
        """ Writes a bug #, timestamp, and build's info to the BUGLIST to track what has been posted 
            Also calls RemoveCache on the revision once it's been posted
        """
        if self.dry_run:
            log.debug("DRY_RUN: WRITING TO %s: %s" % (filename, revision))
        else:
            try:
                f = open(filename, 'a')
                f.write("%s|%s|%d|%s\n" % (bug, revision, time(), strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())))
                f.close()
                if self.verbose:
                    log.debug("WROTE TO %s: %s" % (filename, revision))
                self.RemoveCache(revision)
            except:
                traceback.print_exc(file=sys.stdout)
        
    def RemoveCache(self, revision):
        # attach '.done' to the cache file so we're not tracking it anymore
        cache_file = os.path.join(self.cache_dir, revision)
        if os.path.exists(cache_file):
            os.rename(cache_file, cache_file + '.done')
            if os.path.exists(cache_file):
                os.remove(cache_file)
            if self.verbose:
                log.debug("MOVING %s CACHE FILE to %s" % (cache_file, cache_file + '.done'))

    def LoadCache(self):
        """ Search for cache dir, return dict of all filenames (revisions) in the dir
            and a list of completed revisions to knock out of poll run
        """
        revisions = {}
        completed_revisions = []
        if self.verbose:
            log.debug("Checking for existing cache files...")
            
        if os.path.isdir(self.cache_dir):
            cache_revs = os.listdir(self.cache_dir)
            for revision in cache_revs:
                if '.done' in revision:
                    completed_revisions.append(revision.split('.')[0])
                else:
                    revisions[revision] = {}
            if self.verbose:
                log.debug("INCOMPLETE REVISIONS IN CACHE %s" % (revisions))
        return revisions, completed_revisions
    
    def WriteToCache(self, incomplete):
        """ Writes results of incomplete build to cache dir in a file that is named with the revision """
        try:
            assert isinstance(incomplete, dict)
        except AssertionError, e:
            log.error("Incomplete should be type:dict")
            raise

        if not os.path.isdir(self.cache_dir):
            if not self.dry_run:
                os.mkdir(self.cache_dir)
                if self.verbose:
                    log.debug("CREATED DIR: %s" % self.cache_dir)
            else:
                log.debug("DRY RUN: WOULD CREATE DIR: %s" % self.cache_dir) 
        
        for revision, results in incomplete.items():
            filename = os.path.join(self.cache_dir, revision)
            if self.dry_run:
                log.debug("DRY RUN: WOULD WRITE TO %s: %s|%s\n" % (filename, strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
            else:
                try:                    
                    f = open(filename, 'a')
                    f.write("%s|%s\n" % (strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                    if self.verbose:
                        log.debug("WROTE TO %s: %s|%s\n" % (filename, strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                    f.close()
                except:
                    log.error(traceback.print_exc(file=sys.stdout))
                    raise
    
    def CalculateBuildRequestStatus(self, buildrequests, revision=None):
        """ Accepts buildrequests and calculates their results, calls OrangeFactorHandling
            to ensure completeness of results, makes sure that COMPLETION_THRESHOLD is met
            before declaring a build finished (this is for delays in test triggerings)
            
            If a revision is passed in, the revision will be checked for timeout in revisionTimedOut
            and factored into the is_complete value
        
        returns a tuple of:
            status (dict)
            is_complete (boolean)
        """
        is_complete = False
        status = {
            'total_builds': 0,
            'pending': 0,
            'running': 0,
            'complete': 0,
            'cancelled': 0,
            'interrupted': 0,
            'misc': 0,
            'status_string': "",
        }
        for key,value in buildrequests.items():
            status['total_builds'] +=1
            br = value.to_dict()
            if br['status_str'].lower() in status.keys():
                status[br['status_str'].lower()] += 1

        total_complete = status['misc'] + status['interrupted'] + status['cancelled'] + status['complete']
        if status['total_builds'] == total_complete:
            is_complete = True
            timeout_complete = []
            for key,value in buildrequests.items():
                br = value.to_dict()
                if br['finish_time']:
                    timeout_complete.append(time() - br['finish_time'] > COMPLETION_THRESHOLD)
                for passed_timeout in timeout_complete:
                    if not passed_timeout:
                        is_complete = False # we'll wait a bit and make sure no tests are coming
                        break
            if is_complete:
                # one more check before it's _really complete_ - any oranges to retry?
                if self.verbose:
                    log.debug("Check Orange Factor for rev: %s" % revision)
                is_complete, status['status_string'] =  self.OrangeFactorHandling(buildrequests)
        else:
            # check timeout, perhaps it's time to kick this out of the tracking queue
            if revision != None:
                if self.revisionTimedOut(revision):
                    status['status_string'] = 'timed out'

        return (status,is_complete)
    
    def GetRevisions(self, starttime=None, endtime=None):
        """ Gets the buildrequests between starttime & endtime, returns a dict keyed by revision
            with the buildrequests per revision
        """
        rev_dict = {}
        buildrequests = self.scheduler_db.GetBuildRequests(None, self.branch, starttime, endtime)
        for key, value in buildrequests.items():
            # group buildrequests by revision
            br = value.to_dict()
            revision = br['revision']
            if not rev_dict.has_key(revision):
                rev_dict[revision] = {}
        return rev_dict

    def ProcessCompletedRevision(self, revision, message, bug, status_str, type):
        """ Posts to bug and sends msg to autoland mq with completion status """

        bug_post = False
        dupe = False
        result = False
        action = type + '.push'

        if status_str == 'timed out':
            message += "\n Timed out after %s hours without completing." % strftime('%I', gmtime(TIMEOUT))
                    
        posted = self.bz.has_comment(message, bug)

        if posted:
            log.debug("NOT POSTING TO BUG %s, ALREADY POSTED" % bug)
            dupe = True
            self.RemoveCache(revision)
        else:
            if self.dry_run:
                log.debug("DRY_RUN: Would post to %s%s" % (self.bz_url, bug))
            else:
                if self.verbose:
                    log.debug("Type: %s Revision: %s - bug comment & message being sent" % (type, revision))
                result = self.bz.notify_bug(message, bug)
        if result:
            log.debug("BZ POST SUCCESS result: %s bug: %s%s" % (result, self.bz_url, bug))
            bug_post = True
            msg = { 'type'  : status_str,
                    'action': action,
                    'bug_id' : bug,
                    'revision': revision }
            self.mq.send_message(msg, self.config.get('mq', 'queue'),
                routing_keys=[self.config.get('mq', 'db_topic')])
            self.WriteToBuglist(revision, bug)
        elif not self.dry_run and not dupe:
            log.debug("BZ POST FAILED message: %s bug: %s, couldn't notify bug. Try again later." % (message, bug))

        return bug_post

    def PollByRevision(self, revision, bugs=None):
        """ Run a single revision through the polling process to determine if it is complete, 
            or not, returns information on the revision in a dict which includes the message
            that can be posted to a bug (if not in dryrun mode), whether the message was 
            successfully posted, and the current status of the builds
        """
        info = {
            'message': None,
            'posted_to_bug': False,
            'status': None,
            'is_complete': False,
            'discard': False,
        }
        buildrequests = self.scheduler_db.GetBuildRequests(revision, self.branch)
        type = self.ProcessPushType(revision, buildrequests)
        # if no bugs passed in, check comments for --post-to-bugzilla bug XXXXXX
        if bugs == None:
            bugs = self.GetBugNumbers(buildrequests)
        info['status'], info['is_complete'] = self.CalculateBuildRequestStatus(buildrequests, revision)
        if self.verbose:
            log.debug("POLL_BY_REVISION: RESULTS: %s BUGS: %s TYPE: %s IS_COMPLETE: %s" % (info['status'], bugs, type, info['is_complete']))
        if info['is_complete'] and len(bugs) > 0:
            results = self.CalculateResults(buildrequests)
            info['message'] = self.GenerateResultReportMessage(revision, results, self.GetSingleAuthor(buildrequests))
            if self.verbose:
                log.debug("POLL_BY_REVISION: MESSAGE: %s" % info['message'])
            for bug in bugs:
                if info['message'] != None and self.dry_run == False:
                    info['posted_to_bug'] = self.ProcessCompletedRevision(revision=revision, 
                                                    message=info['message'], bug=bug, 
                                                    status_str=info['status']['status_string'], 
                                                    type=type)
                elif self.dry_run:
                    log.debug("DRY RUN: Would have posted %s to %s" % (info['message'], bug))
        # No bug number(s) or no try syntax, but complete gets flagged for discard
        elif info['is_complete']:
            log.debug("Nothing to do here for %s" % revision)
            info['discard'] = True
        else:
            if bugs != None and not self.dry_run:
                # Cache it
                log.debug("Writing %s to cache" % revision)
                incomplete = {}
                incomplete[revision] = info['status']
                self.WriteToCache(incomplete)
            else:
                info['discard'] = True
            
        return info
    
    def PollByTimeRange(self, starttime, endtime):
        # Get all the unique revisions in the specified timeframe range
        rev_report = self.GetRevisions(starttime,endtime)
        # Check the cache for any additional revisions to pull reports for
        revisions, completed_revisions = self.LoadCache()
        rev_report.update(revisions)
        # Clear out complete revisions from the rev_report keys
        for rev in completed_revisions:
            if rev_report.has_key(rev):
                log.debug("Removing %s from the revisions to poll, it's been done." % rev)
                del rev_report[rev]
    
        # Check each revision's buildrequests to determine: completeness, type
        for revision in rev_report.keys():
            buildrequests = self.scheduler_db.GetBuildRequests(revision, self.branch)
            rev_report[revision]['bugs'] = self.GetBugNumbers(buildrequests)
            rev_report[revision]['push_type'] = self.ProcessPushType(revision, buildrequests)
            (rev_report[revision]['status'], rev_report[revision]['is_complete']) = self.CalculateBuildRequestStatus(buildrequests, revision)
    
            # For completed runs, generate a bug comment message if there are bugs
            if rev_report[revision]['is_complete'] and len(rev_report[revision]['bugs']) > 0:
                rev_report[revision]['results'] = self.CalculateResults(buildrequests)
                rev_report[revision]['message'] = self.GenerateResultReportMessage(revision, rev_report[revision]['results'], self.GetSingleAuthor(buildrequests))
            else:
                rev_report[revision]['message'] = None
    
        # Process the completed rev_report for this run, gather incomplete revisions and writing to cache
        incomplete = {}
        for revision,info in rev_report.items():
            # Incomplete builds that have bugs get added to dict for re-checking later
            if not info['is_complete']:
                if len(info['bugs']) == 1:
                    incomplete[revision] = {'status': info['status'],
                                            'bugs': info['bugs'],
                                            }

            # Try syntax has --post-to-bugzilla so we want to post to bug
            if info['is_complete'] and info['push_type'] != None and len(info['bugs']) == 1:
                bug = info['bugs'][0]
                if not self.ProcessCompletedRevision(revision, 
                                      rev_report[revision]['message'], 
                                      bug, 
                                      rev_report[revision]['status']['status_string'], 
                                      info['push_type']):
                    # If bug post didn't happen put it back (once per revision) into cache to try again later
                    if not incomplete.has_key(revision):
                        incomplete[revision] = {'status': info['status'],
                                                'bugs': info['bugs'],
                                                }
            # Complete but to be discarded
            elif info['is_complete']:
                if self.verbose:
                    log.debug("Nothing to do for push_type:%s revision:%s - no one cares about it" % (info['push_type'], revision))
                self.RemoveCache(revision)

        # Store the incompletes for the next run if there's a bug
        self.WriteToCache(incomplete)

        return incomplete

if __name__ == '__main__':
    """
        Poll the schedulerdb for all the buildrequests of a certain timerange or a single
        revision. Determine the results of that revision/timerange's buildsets and then posts to 
        the bug with results for any that are complete (if it's a try-syntax push, then checks for
        --post-to-bugzilla flag). Any revision(s) builds that are not complete are written to a 
        cache file named by revision for checking again later.
    """

    log.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(LOGFILE, maxBytes=50000, backupCount=5)
    log.addHandler(handler)

    parser = ArgumentParser()
    parser.add_argument("-b", "--branch", 
                        dest="branch", 
                        help="the branch revision to poll", 
                        required=True)
    parser.add_argument("-c", "--config-file", 
                        dest="config",
                        help="config file to use for accessing db", 
                        required=True)
    parser.add_argument("-u", "--user", 
                        dest="user", 
                        help="username for buildapi ldap posting", 
                        required=True)
    parser.add_argument("-p", "--password", 
                        dest="password", 
                        help="password for buildapi ldap posting", 
                        required=True)
    parser.add_argument("-r", "--revision", 
                        dest="revision", 
                        help="a specific revision to poll")
    parser.add_argument("-s", "--start-time", 
                        dest="starttime", 
                        help="unix timestamp to start polling from")
    parser.add_argument("-e", "--end-time", 
                        dest="endtime", 
                        help="unix timestamp to poll until")
    parser.add_argument("-n", "--dry-run", 
                        dest="dry_run", 
                        help="flag for turning off actually posting to bugzilla", 
                        action='store_true')
    parser.add_argument("-v", "--verbose", 
                        dest="verbose", 
                        help="turn on verbose output", 
                        action='store_true')
    parser.add_argument("--cache-dir", 
                        dest="cache_dir", 
                        help="working dir for tracking incomplete revisions")

    parser.set_defaults(
        branch="try",
        cache_dir="cache",
        revision=None,
        starttime = time() - POLLING_INTERVAL,
        endtime = time(),
        dry_run = False,
    )

    options, args = parser.parse_known_args()

    if not os.path.exists(options.config):
        log.debug("Config file does not exist or is not valid.")
        sys.exit(1)

    if options.revision:
        poller = SchedulerDBPoller(branch=options.branch, cache_dir=options.cache_dir, config=options.config, 
                                    user=options.user, password=options.password, dry_run=options.dry_run, 
                                    verbose=options.verbose)
        result, posted_to_bug = poller.PollByRevision(options.revision)
        if options.verbose:
            log.debug("Single revision run complete: RESULTS: %s POSTED_TO_BUG: %s" % (result, posted_to_bug))
    else:
        if options.starttime > time():
            log.debug("Starttime %s must be earlier than the current time %s" % (options.starttime, time.localtime()))
            sys.exit(1)
        elif options.endtime < options.starttime:
            log.debug("Endtime %s must be later than the starttime %s" % (options.endtime, options.starttime))
            sys.exit(1)
        elif options.endtime - options.starttime > MAX_POLLING_INTERVAL:
            log.debug("Too large of a time interval between start and end times, please try a smaller polling interval")
            sys.exit(1)
        else:
            poller = SchedulerDBPoller(branch=options.branch, cache_dir=options.cache_dir, config=options.config, 
                                    user=options.user, password=options.password, dry_run=options.dry_run, 
                                    verbose=options.verbose)
            incomplete = poller.PollByTimeRange(options.starttime, options.endtime)
            if options.verbose:
                log.debug("Time range run complete: INCOMPLETE %s" % incomplete)

    sys.exit(0)
