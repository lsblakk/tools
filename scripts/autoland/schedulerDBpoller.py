import sys
import os
import traceback
import urllib2
import urllib
import re
import json
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
        
        # Set up bugzilla api connection
        self.bz_url = self.config.get('bz', 'url')
        self.bz = bz_utils.bz_util(self.config.get('bz', 'api_url'), self.config.get('bz', 'url'),
        None, self.config.get('bz', 'username'), self.config.get('bz', 'password'))

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
                                    log.error("FAIL: Unsuccessful attempt to rebuild branch: %s bid: %s" % (branch, bid))
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
        if self.autoland_db.AutolandQuery(revision):
            type = "auto"
        else:
            for key,value in buildrequests.items():
                br = value.to_dict()
                for comments in br['comments']:
                    if self.flagcheck and type == None:
                        if 'try: ' in comments and '--post-to-bugzilla' in comments:
                            type = "try"
                    else:
                        if 'try: ' in comments:
                            type = "try"
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
    https://tbpl.mozilla.org/?tree=%s&rev=%s
Results (out of %d total builds):\n""" % (revision, self.branch.title(), revision, report['total_builds'])
        for key, value in report.items():
            if value > 0 and key != 'total_builds':
                message += "    %s: %d\n" % (key, value)
        if author != None:
            message += "Builds (or logs if builds failed) available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/%(author)s-%(revision)s" % locals()
        return message
    
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
            assert isinstance(incomplete, dict)
        except AssertionError, e:
            log.error("Incomplete should be type:dict")
            raise
        try:
            for revision, results in incomplete.items():
                filename = os.path.join(self.cache_dir, revision)
                if self.dry_run:
                    log.debug("DRY RUN: WOULD WRITE TO %s: %s|%s\n" % (filename, strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                else:
                    f = open(filename, 'a')
                    f.write("%s|%s\n" % (strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                    if self.verbose:
                        log.debug("WROTE TO %s: %s|%s\n" % (filename, strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), results))
                    f.close()
        except:
            log.error(traceback.print_exc(file=sys.stdout))
            raise
    
    def CalculateBuildRequestStatus(self, buildrequests):
        """ Accepts buildrequests and calculates their results, calls OrangeFactorHandling
            to ensure completeness of results, makes sure that COMPLETION_THRESHOLD is met
            before declaring a build finished (this is for delays in test triggerings)
        
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
                is_complete, status['status_string'] =  self.OrangeFactorHandling(buildrequests)
        else:
            # TODO - this is where to kick things out that have bugs which can't be posted to
            # or if something's been in the retry queue for N amount of time
            # check how long since builds started
            is_complete = False
            log.debug("Need to kick out things that don't meet the usual complete check here")

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
    
    def PollByRevision(self, revision, hours=4, bugs=None):
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
        if bugs == None:
            bugs = self.GetBugNumbers(buildrequests)
        info['status'], info['is_complete'] = self.CalculateBuildRequestStatus(buildrequests)
        if self.verbose:
            log.debug("POLL_BY_REVISION: RESULTS: %s BUGS: %s TYPE: %s IS_COMPLETE: %s" % (info['status'], bugs, type, info['is_complete']))
        if info['is_complete'] and type == "try" and len(bugs) > 0:
            results = self.CalculateResults(buildrequests)
            info['message'] = self.GenerateResultReportMessage(revision, results, self.GetSingleAuthor(buildrequests))
            if self.verbose:
                log.debug("POLL_BY_REVISION: MESSAGE: %s" % info['message'])
            for bug in bugs:
                # if we have posted to the bug for this revision, but the timeout has passed
                # we could post again
                posted = self.bz.has_recent_comment(revision, bug, hours)
                if posted:
                    log.debug("NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                else:
                    if info['message'] != None and self.dry_run == False:
                        # Comment in the bug
                        r = self.bz.notify_bug(info['message'], bug)
                        if r == 1:
                            self.WriteToBuglist(revision, bug)
                            log.debug("BZ POST SUCCESS r: %s bug: %s%s" % (r, self.bz_url, bug))
                            info['posted_to_bug'] = True
                        else:
                            log.debug("BZ POST FAILED message: %s bug: %s, couldn't notify bug. Try again later." % (info['message'], bug))
                            info['posted_to_bug'] = False
                            # TODO - write to the cache file how many tries (set a limit for this?)
        # No bug number(s) or no try syntax, but complete gets flagged for discard
        elif info['is_complete']:
            log.debug("Nothing to do here" % revision)
            info['discard'] = True
        else:
            # Cache it
            log.debug("Writing %s to cache" % revision)
            incomplete = {}
            incomplete[revision] = info['status']
            self.WriteToCache(incomplete)
            
        return info
    
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
                            log.debug("DRY_RUN: Would post to %s%s " % (self.bz_url, bug))
                            r = False
                        else:
                            # Comment in the bug
                            r = self.bz.notify_bug(rev_report[revision]['message'], bug)
                        if r:
                            self.WriteToBuglist(revision, bug)
                            log.debug("BZ POST SUCCESS: %s%s " % (self.bz_url, info['bugs']))
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
            # Autoland revision is complete, send message to the autoland_queue and post to bug
            elif info['is_complete'] and info['push_type'] == "auto":
                if self.verbose:
                    log.debug("Autoland wants to know about %s - bug comment & message being sent" % revision)
                # Comment in the bug and send message to autoland queue
                if len(info['bugs']) == 1:
                    r = self.bz.notify_bug(rev_report[revision]['message'], info['bugs'][0])
                    if r:
                        self.WriteToBuglist(revision, info['bugs'][0])
                    msg = { 'type'  : rev_report[revision]['status']['status_string'],
                            'action': 'try.push',
                            'bugid' : info['bugs'][0],
                            'revision': revision }
                    self.mq.send_message(msg, self.config.get('mq', 'queue'),
                        routing_keys=[self.config.get('mq', 'db_topic')])
                else:
                    log.debug("Don't know what to do with %d bug numbers. Autoland works with only one bug right now." % len(info['bugs']))
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
        # TODO Validation on the timestamps provided
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
