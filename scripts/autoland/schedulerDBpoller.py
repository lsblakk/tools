import sys, os, traceback, urllib2, urllib, re
try:
    import json
except ImportError:
    import simplejson as json
from argparse import ArgumentParser
import ConfigParser
import utils.bz_utils as bz_utils
import utils.mq_utils as mq_utils
from utils.db_handler import DBHandler
from time import time, strftime, localtime

import logging, logging.handlers

FORMAT="%(asctime)s - %(module)s - %(funcName)s - %(message)s"
LOGFILE='schedulerDBpoller.log'
POSTED_BUGS='postedbugs.log'
POLLING_INTERVAL=14400 # 4 hours
MAX_POLLING_INTERVAL=172800 # 48 hours
COMPLETION_THRESHOLD=600 # 10 minutes
MAX_ORANGE = 2

# console logging, formatted
logging.basicConfig(format=FORMAT)
# sets up a rotating logfile that's written to the working dir
log = logging.getLogger(LOGFILE)
log.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(LOGFILE, maxBytes=50000, backupCount=5)
log.addHandler(handler)

class SchedulerDBPoller():

    def __init__(self, branch, cache_dir, config, flagcheck=True,
                user=None, password=None, dry_run=False, verbose=False):

        self.config = ConfigParser.ConfigParser()
        self.config.read(config)

        # Set up the message queue
        self.mq = mq_utils.mq_util()
        self.mq.set_host(self.config.get('mq', 'host'))
        self.mq.set_exchange(self.config.get('mq', 'exchange'))
        
        # Set up bz
        self.bz = bz_utils.bz_util(self.config.get('bz', 'url'), None,
        self.config.get('bz', 'username'), self.config.get('bz', 'password'))

        self.self_serve_api_url = self.config.get('self_serve', 'url')
        self.branch = branch
        self.cache_dir = cache_dir
        self.flagcheck = flagcheck
        self.dry_run = dry_run
        self.verbose = verbose
        self.user = user
        self.password = password

        self.scheduler_db = DBHandler(self.config.get('databases', 'scheduler_db_url'))
        self.autoland_db = DBHandler(self.config.get('databases', 'autoland_db_url'))

    def OrangeFactorHandling(self, buildrequests):
        """ Checks buildrequests results if all success except # warnings is <= MAX_ORANGE
    
            * Check if the buildername with warning result is duplicated in requests
            * If not, triggers a rebuild using self-serve API of that buildernames's buildid
            * If yes, check the results of the pair and report back success/fail based on:
            ** orange:green == Success, intermittent orange
            ** orange:orange == Failed on retry
        returns is_complete and final_status (success, failure, None) based on retries
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
                    # Unique buildername with warnings, trigger a rebuild
                    else:
                        for result, branch, bid in info:
                            if result == 'warnings':
                                if self.verbose:
                                    log.debug("Attempting to retry branch: %s bid: %s" % (branch, bid))
                                post = self.SelfServeRetry(bid)
                                if post != {}:
                                    is_complete = False
                                    final_status = "retrying"
                                else:
                                    is_complete = True
                                    final_status = "failure"
                                    if self.verbose:
                                        log.debug("Unsuccessful attempt to rebuild branch: %s bid: %s" % (branch, bid))
                # Passed on Retry
                if retry_count != 0 and retry_pass == retry_count:
                    is_complete = True
                    final_status = "success"
                # Failed on Retry
                elif retry_count != 0:
                    is_complete = True
                    final_status = "failure"
        else:
            # There are too many warnings there's nothing to be done
            if self.verbose:
                log.debug("Too many warnings! Final = failure")
            is_complete = True
            final_status = "failure"

        return is_complete, final_status
    
    def SelfServeRetry(self, buildid):
        """ Uses self-serve API to retrigger the buildid/branch sent in with a POST request"""
        try:
            password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None,
                                      uri=self.self_serve_api_url,
                                      # works with autolanduser@mozilla.com
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
            req = urllib2.Request(url, data)
            req.method = "POST"
            result = json.loads(opener.open(req).read())
        except Exception, e:
            log.debug("Exception on attempted rebuild for %s:%s -- %s" % (self.branch, buildid, e))
            result = {}
        return result
    
    def GetSingleAuthor(self, buildrequests):
        """Look through a list of buildrequests and return only one author from the changes if one exists"""
        author = None
        for key, value in buildrequests.items():
          br = value.to_dict()
          if author == None:
              author = br['authors']
        if len(author) == 1:
            return ''.join(author)
    
    def GetBugNumbers(self, buildrequests):
        """Look through a list of buildrequests and return bug number(s) from the change comments"""
        bugs = []
        for key,value in buildrequests.items():
            br = value.to_dict()
            for comment in br['comments']:
                if bugs == []:
                    bugs = self.bz.bugs_from_comments(comment)
        return bugs
    
    def ProcessPushType(self, revision, buildrequests):
        """ Search buildrequest comments for try syntax and query autoland_db about a revision returns type as "try", "auto", or None
    
        try: if "try: --post-to-bugzilla" is present in the comments of a buildrequest
        auto: if a check against AutolandDB returns True
        None: if it's not "try" and AutolandDB isn't tracking it """
    
        type = None
        for key,value in buildrequests.items():
            br = value.to_dict()
            for comments in br['comments']:
                if self.flagcheck and type == None:
                    if 'try: ' in comments and '--post-to-bugzilla' in comments:
                        type = "try"
                else:
                    if 'try: ' in comments:
                        type = "try"
        if self.autoland_db.AutolandQuery(revision):
            type = "auto"
        return type
    
    def CalculateResults(self, buildrequests):
        """ Returns dictionary of the results for the buildrequests passed in"""
    
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
    http://tbpl.allizom.org/?tree=%s&usebuildbot=1&rev=%s
Results (out of %d total builds):\n""" % (revision, self.branch.title(), revision, report['total_builds'])
        for key, value in report.items():
            if value > 0 and key != 'total_builds':
                message += "    %s: %d\n" % (key, value)
        if author != None:
            message += "Builds (or logs if builds failed) available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/%(author)s-%(revision)s" % locals()
        return message
    
    def CheckBugCommentTimeout(self, revision, filename=POSTED_BUGS):
        """ Checks that at least 4 hours have elapsed since the last post to a bug for a rev in the buglist"""
        post = False
        has_revision = False
        if os.path.isfile(filename):
            if self.verbose:
                log.debug("Reading postedbug list, comparing to contents...")
            f = open(filename, 'r')
            for line in f.readlines():
                (bug, rev, timestamp, human_time) = line.split("|")
                if revision == rev:
                    has_revision = True
                    # checking elapsed time is greater than the polling interval so as not to spam bugs
                    post = time() - POLLING_INTERVAL > timestamp
            f.close()
        if self.verbose:
            log.debug("REV %s ON FILE, POSTING: %s" % (has_revision, post))
        return (has_revision, post)
    
    def WriteToBuglist(self, revision, bug, filename=POSTED_BUGS):
        """ Writes a bug number and timestamp of complete build info to the BUGLIST."""
        if self.dry_run:
            log.debug("DRY_RUN: WRITING TO %s: %s" % (filename, revision))
        else:
            try:
                f = open(filename, 'a')
                f.write("%s|%s|%d|%s\n" % (bug, revision, time(), strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())))
                f.close()
                if self.verbose:
                    log.debug("WROTE TO %s: %s" % (filename, revision))

                # clear out the cache file so we're not tracking it anymore
                cache_file = os.path.join(self.cache_dir, revision)
                if os.path.exists(cache_file):
                    os.remove(cache_file)
                    if self.verbose:
                        log.debug("REMOVING %s CACHE FILE" % cache_file)
            except:
                traceback.print_exc(file=sys.stdout)
        
    
    def LoadCache(self):
        """Search for existing cache dir, return dict of revisions (filenames) in the dir"""
        revisions = {}
        if self.verbose:
            log.debug("Checking for existing cache file...")
            
        if os.path.isdir(self.cache_dir):
            cache_revs = os.listdir(self.cache_dir)
            print cache_revs
            for revision in cache_revs:
                revisions[revision] = {}
            if self.verbose:
                log.debug("REVISIONS IN CACHE %s" % (revisions))
        return revisions
    
    def WriteToCache(self, incomplete):
        """ Writes a results of incomplete build results to file, named by revision"""
        if not os.path.isdir(self.cache_dir):
            os.mkdir(self.cache_dir)
            if self.verbose:
                log.debug("CREATED DIR: %s" % self.cache_dir)
        try:
            for revision, results in incomplete.items():
                filename = os.path.join(self.cache_dir, revision)
                if self.dry_run:
                    log.debug("DRY_RUN: WRITING TO %s: %s" % (filename, results))
                else:
                    f = open(filename, 'a')
                    f.write("%s|%s\n" % (strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                    if self.verbose:
                        log.debug("WROTE TO %s: %s" % (filename, results))
                    f.close()
        except:
            traceback.print_exc(file=sys.stdout)
    
    def CalculateBuildRequestStatus(self, buildrequests):
        """ Accepts buildrequests and calculates their results
        
        returns a tuple of:
            status (dict)
            is_complete (boolean)
        """
    
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
            # get the status for each buildrequest item and build the rev_revision['log']for the revision
            status['total_builds'] +=1
            br = value.to_dict()
            # Do the tallying of statuses
            if br['status_str'].lower() in status.keys():
                status[br['status_str'].lower()] += 1
    
        # Calculate completeness and check against timeout threshold to account for delay in test sendchanges
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
                        is_complete = False # let's wait longer to make sure it's really done
            if is_complete:
                # one more check before it's really complete - any oranges to retry?
                is_complete, status['status_string'] =  self.OrangeFactorHandling(buildrequests)
        else:
            is_complete = False
        return (status,is_complete)
    
    def GetRevisions(self, starttime=None, endtime=None):
        """ Gets the buildrequests between starttime & endtime, returns a dict keyed by revision
        with the buildrequests per revision"""
    
        rev_dict = {}
        buildrequests = self.scheduler_db.GetBuildRequests(None, self.branch, starttime, endtime)
        for key, value in buildrequests.items():
            # group buildrequests by revision
            br = value.to_dict()
            revision = br['revision']
            if not rev_dict.has_key(revision):
                rev_dict[revision] = {}
        return rev_dict
    
    def PollByRevision(self, revision):
        message = None
        posted_to_bug = False
        buildrequests = self.scheduler_db.GetBuildRequests(revision, self.branch)
        type = self.ProcessPushType(revision, buildrequests)
        bugs = self.GetBugNumbers(buildrequests)
        status, is_complete = self.CalculateBuildRequestStatus(buildrequests)
        if self.verbose:
            log.debug("POLL_BY_REVISION: RESULTS: %s BUGS: %s TYPE: %s IS_COMPLETE: %s" % (status, bugs, type, is_complete))
        if is_complete and type == "try" and len(bugs) > 0:
            results = self.CalculateResults(buildrequests)
            message = self.GenerateResultReportMessage(revision, results, self.GetSingleAuthor(buildrequests))
            if self.verbose:
                log.debug("POLL_BY_REVISION: MESSAGE: %s" % message)
            for bug in bugs:
                has_revision, post = self.CheckBugCommentTimeout(revision)
                if has_revision and not post:
                    log.debug("NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                else:
                    if message != None and self.dry_run == False:
                        # Put comment in the bug
                        if self.dry_run:
                            log.debug("DRY_RUN: Posting to https://bugzilla.mozilla.org/show_bug.cgi?id=%s " % bug)
                        else:
                            r = self.bz.notify_bug(message, bug)
                            if r and not has_revision:
                                self.WriteToBuglist(revision, bug)
                                log.debug("BZ POST SUCCESS r: %s bug: https://bugzilla.mozilla.org/show_bug.cgi?id=%s" % (r, bug))
                                posted_to_bug = True
                            else:
                                log.debug("BZ POST FAILED message: %s bug: %s, couldn't notify bug. Try again later." % (message, bug))
        # It's a try run but no bug number(s) gets discarded with log note for debugging
        elif is_complete and type == "try" and len(bugs) == 0 and self.verbose:
            log.debug("Try run for %s but no bug number(s) - nothing to do here" % revision)
        elif is_complete and type == None and self.verbose:
            log.debug("Nothing to do for %s - no one cares about it" % revision)
        elif not is_complete:
            # Cache it
            incomplete = {}
            incomplete[revision] = status
            self.WriteToCache(incomplete)
            
        return (message, posted_to_bug)
    
    def PollByTimeRange(self, starttime, endtime):
        # Get all the unique revisions in the specified timeframe range
        rev_report = self.GetRevisions(starttime,endtime)
        # Add in any revisions currently in cache for a complete list to poll schedulerdb about
        rev_report.update(self.LoadCache())
    
        # Check each revision's buildrequests to determine: completeness, type
        for revision in rev_report.keys():
            buildrequests = self.scheduler_db.GetBuildRequests(revision, self.branch)
            rev_report[revision]['bugs'] = self.GetBugNumbers(buildrequests)
            rev_report[revision]['push_type'] = self.ProcessPushType(revision, buildrequests)
            (rev_report[revision]['status'], rev_report[revision]['is_complete']) = self.CalculateBuildRequestStatus(buildrequests)
    
            # For completed runs, generate a bug comment message if there are bugs
            if rev_report[revision]['is_complete'] and len(rev_report[revision]['bugs']) > 0:
                rev_report[revision]['results'] = self.CalculateResults(buildrequests)
                rev_report[revision]['message'] = self.GenerateResultReportMessage(revision, rev_report[revision]['results'], self.GetSingleAuthor(buildrequests))
            else:
                rev_report[revision]['message'] = None
    
        # Process the completed rev_report for this run, gather incomplete revisions and writing to cache
        incomplete = {}
        for revision,info in rev_report.items():
            if self.verbose:
                log.debug("PROCESSING --- REV: %s: INFO: %s" % (revision, info))
            # Incomplete gets added to dict for later processing
            if not info['is_complete']:
                incomplete[revision] = {'status': info['status'],
                                        'bugs': info['bugs'],
                                        }
            # For completed buildruns determine handling for the completed revision
            if info['is_complete'] and info['push_type'] == "try" and len(info['bugs']) > 0:
                for bug in info['bugs']:
                    posted = self.bz.has_recent_comment(revision, bug)
                    if posted:
                        if self.verbose:
                            log.debug("NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                        if self.dry_run:
                            log.debug("DRY-RUN: NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                    else:
                        if self.dry_run:
                            log.debug("DRY-RUN: POSTING TO BUG %s" % bug)
                            r = False
                        else:
                            # Comment in the bug
                            r = self.bz.notify_bug(rev_report[revision]['message'], bug)
                        if r:
                            self.WriteToBuglist(revision, bug)
                            log.debug("BZ POST SUCCESS bugs:%s" % info['bugs'])
                        elif not r:
                            if self.dry_run:
                                log.debug("DRY-RUN: NO BUG POST RESULTS")
                            else:
                                log.debug("BZ POST FAIL bugs:%s, writing to cache for retrying later" % info['bugs'])
                                # put it back (only once per revision) into the cache file to try again later
                                if not incomplete.has_key(revision):
                                    incomplete[revision] = {'status': info['status'],
                                                            'bugs': info['bugs'],
                                                            }
            # It's a try run but no bug number(s) gets discarded with log note for debugging
            elif info['is_complete'] and info['push_type'] == "try" and len(info['bugs']) == 0 and self.verbose:
                log.debug("Try run for %s but no bug number(s) - nothing to do here" % revision)
            # Autoland revision is complete, send message to the autoland_queue
            elif info['is_complete'] and info['push_type'] == "auto":
                if self.verbose:
                    log.debug("Autoland wants to know about %s - bug comment & message being sent" % revision)
                # Comment in the bug
                r = self.bz.notify_bug(rev_report[revision]['message'], info['bugs'][0])
                if r:
                    self.WriteToBuglist(revision, info['bugs'][0])
                if len(info['bugs']) == 1:
                    msg = { 'type'  : rev_report[revision]['status']['status_str'],
                            'action': 'try.push',
                            'bugid' : info['bugs'][0],
                            'revision': revision }
                    self.mq.send_message(msg, config.get('mq', 'queue'),
                        routing_keys=[config.get('mq', 'autoland_db')])
                else:
                    log.debug("Don't know what to do with %d bugs. Autoland works with only one bug right now." % len(info['bugs']))
            # Complete but neither PushToTry nor Autoland, throw it away
            elif info['is_complete'] and info['push_type'] == None and self.verbose:
                log.debug("Nothing to do for %s - no one cares about it" % revision)

        self.WriteToCache(incomplete)
        return incomplete


if __name__ == '__main__':
    """
        Accepts a revision/branch and polls the schedulerdb for all the buildrequests of that revision
        Determines the results of that revision/branch buildset and then posts to the bug with results
        when that is determined to be complete. If not complete, the revision/branch and bugID are held
        in an incomplete cache file to be checked again at regular intervals.
    """
    parser = ArgumentParser()
    parser.add_argument("-b", "--branch", dest="branch", help="the branch revision to poll", required=True)
    parser.add_argument("-c", "--config-file", dest="config", help="config file to use for accessing db", required=True)
    parser.add_argument("-u", "--user", dest="user", help="username for buildapi ldap posting", required=True)
    parser.add_argument("-p", "--password", dest="password", help="password for buildapi ldap posting", required=True)
    parser.add_argument("-r", "--revision", dest="revision", help="a specific revision to poll")
    parser.add_argument("-s", "--start-time", dest="starttime", help="unix timestamp to start polling from")
    parser.add_argument("-e", "--end-time", dest="endtime", help="unix timestamp to poll until")
    parser.add_argument("-f", "--flagcheck", dest="flagcheck", help="check for the --post-to-bugzilla flag in comments", action='store_true')
    parser.add_argument("-n", "--dry-run", dest="dry_run", help="flag for turning off actually posting to bugzilla", action='store_true')
    parser.add_argument("-v", "--verbose", dest="verbose", help="turn on verbose output", action='store_true')
    parser.add_argument("--cache-dir", dest="cache_dir", help="working dir for tracking incomplete revisions")

    parser.set_defaults(
        branch="try",
        cache_dir="cache",
        revision=None,
        starttime = time() - POLLING_INTERVAL,
        endtime = time(),
    )

    options, args = parser.parse_known_args()

    if not os.path.exists(options.config):
        log.debug("Config file does not exist or is not valid.")
        sys.exit(1)

    if options.revision:
        poller = SchedulerDBPoller(options.branch, options.cache_dir, options.config, options.flagcheck, options.dry_run, options.verbose)
        result, posted_to_bug = poller.PollByRevision(options.revision)
        if options.verbose:
            log.debug("Single revision run complete: RESULTS: %s POSTED_TO_BUG: %s" % (result, posted_to_bug))
    else:
        # Validation on the timestamps provided
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
            poller = SchedulerDBPoller(options.branch, options.cache_dir, options.config, options.flagcheck, options.dry_run, options.verbose)
            incomplete = poller.PollByTimeRange(options.starttime, options.endtime)
            if options.verbose:
                log.debug("Time range run complete: INCOMPLETE %s" % incomplete)

    sys.exit(0)
