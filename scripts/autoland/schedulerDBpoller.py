import sys, os, traceback, urllib2, urllib, json
from argparse import ArgumentParser
import ConfigParser
import utils.bz_utils as bz_utils
import utils.mq_utils as mq_utils
from utils.db_handler import DBHandler
from time import time, strftime, localtime

import logging, logging.handlers

FORMAT="%(asctime)s - %(module)s - %(funcName)s - %(message)s"
LOGFILE='schedulerDBpoller.log'
BUGLIST='postedbugs.log'
# console logging, formatted
logging.basicConfig(format=FORMAT)
# sets up a rotating logfile that's written to the working dir
log = logging.getLogger(LOGFILE)
log.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(LOGFILE, maxBytes=50000, backupCount=5)
log.addHandler(handler)

POLLING_INTERVAL=14400 # 4 hours
MAX_POLLING_INTERVAL=172800 # 48 hours
COMPLETION_THRESHOLD=600 # 10 minutes
MAX_ORANGE = 2
BUILDAPI_URL = "https://build.mozilla.org/buildapi/self-serve"

def OrangeFactorHandling(buildrequests, user=None, password=None):
    """ Checks buildrequests for results and looks for all success but for (up to) MAX_ORANGE warnings
    
    If any warnings are present (no other non-success results):
        * Check if the buildername with warning result is duplicated in requests
        * If no, then trigger a rebuild of that builder's buildid
        * If yes, check the timestamp/result of the matched pair and report back accordingly:
            ** [orange-factor] but pass if O:G
            ** [fail] if O:O
    returns is_complete and final_status (success, failure, None) based on retried oranges
    """
    is_complete = None
    final_status = None
    results = CalculateResults(buildrequests)
    # If only warnings and nothing else, we checkto see if a retry is possible
    if results['total_builds'] != results['success']:
        if results['total_builds'] - results['warnings'] == results['success'] and results['warnings'] <= MAX_ORANGE:
            print "We have a case for orange factor"
            # get buildernames of the ones with warnings
            # for the buildrequests each one has the buildername and the status_str so I need to find
            # if there is a dupe of buildername ie: len(all_buildrequests_buildernames) > 1
            # then if yes, compare the status of those 2 or more buildernames
            # otherwise trigger a rebuild of that buildername's buildid (bid) to branch and return incomplete
            buildernames = []
            for key, value in buildrequests.items():
                br = value.to_dict()
                buildernames.append((br['buildername'], br['status'], br['bid']))
            print buildernames
            seen = set()
            for name, status, bid in buildernames:
                if name in seen:
                    print "we have a duplicate buildername %s - compare the statuses" % n
                    # collect the two or more out of buildrequests....
                else:
                    print "unique buildername"
                    seen.add(name)
            # TODO - get the bid here instead of this hardcoded junk
            post = SelfServeRetry("try", 4801896, user, password)
            is_complete = False
        else:
            print "This isn't an orange factor results set %s" % results
            is_complete = True
            final_status = "failure"
    else:
        is_complete = True
        final_status = "success"
    return is_complete, final_status

def SelfServeRetry(branch, buildid, user, password):
    """ Takes a buildid and sends a POST request to self-serve api to retrigger that buildid"""
    # POST	/self-serve/{branch}/build	Rebuild `build_id`, which must be passed in as a POST parameter.
    try:
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None,
                                  uri='https://build.mozilla.org/buildapi/self-serve',
                                  # works with autolanduser@mozilla.com
                                  user=user,
                                  passwd=password)
        auth_handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        opener = urllib2.build_opener(auth_handler, urllib2.HTTPSHandler())
        
        opener.addheaders = [
         ('Content-Type', 'application/json'),
         ('Accept', 'application/json'),
         ]
        urllib2.install_opener(opener)
        
        data = urllib.urlencode({"build_id": 4801896})
        req = urllib2.Request("https://build.mozilla.org/buildapi/self-serve/try/build", data)
        req.method = "POST"
        
        result = json.loads(opener.open(req).read())
        # check that result['status'] == 'OK' {u'status': u'OK', u'request_id': 19354}
        
    except Exception, e:
        print "couldn't rebuild %s on %s: %s" % (branch, buildid, e)
        return {}

def GetSingleAuthor(buildrequests):
    """Look through a list of buildrequests and return only one author from the changes if one exists"""
    author = None
    for key, value in buildrequests.items():
      br = value.to_dict()
      if author == None:
          author = br['authors']
    if len(author) == 1:
        return ''.join(author)

def GetBugNumbers(buildrequests):
    """Look through a list of buildrequests and return bug number(s) from the change comments"""

    bugs = []
    #log.debug("BUILDREQUESTS: %s" % buildrequests)
    for key,value in buildrequests.items():
        br = value.to_dict()
        # If we've gotten a bug number we can stop
        if bugs == []:
            for comment in br['comments']:
                if bugs == []:
                    bugs = bz_utils.bugs_from_comments(comment)
        else:
            log.debug("Got bug(s) already BUG: %s" % bugs)
            break
    return bugs

def ProcessPushType(revision, buildrequests, autoland_db, flagcheck):
    """ Checks buildrequests for a revision and returns type as "try", "auto", or None

    try: if "try: --post-to-bugzilla" is present in the comments of a buildrequest
    auto: if "try: " is NOT present, and if a check against AutolandDB returns True
    None: if it's not "try" and AutolandDB isn't tracking it """

    type = None
    for key,value in buildrequests.items():
        br = value.to_dict()
        # TODO: More robust checking here?
        for comments in br['comments']:
            if flagcheck and type == None:
                if 'try: ' in comments and '--post-to-bugzilla' in comments:
                    type = "try"
            else:
                if 'try: ' in comments:
                    type = "try"
    if type == None and autoland_db.AutolandQuery(revision):
        log.debug("ProcessPushType:CheckAutoalndDN - True")
        type = "auto"
    log.debug("ProcessPushType:CheckAutoalndDN - False")
    return type

def CalculateResults(buildrequests):
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

def GenerateResultReportMessage(revision, report, author=None):
    """ Returns formatted message of revision report"""

    log.debug("REPORT: %s" % report)
    message = """Try run for %s is complete.
Detailed breakdown of the results available here:
    http://tbpl.mozilla.org/?tree=Try&rev=%s
Results (out of %d total builds):\n""" % (revision, revision, report['total_builds'])
    for key, value in report.items():
        if value > 0 and key != 'total_builds':
            message += "    %s: %d\n" % (key, value)
    if author != None:
        message += "Builds available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/%(author)s-%(revision)s" % locals()
    return message

def CheckBugCommentTimeout(revision, filename=BUGLIST):
    """ Checks that at least 4 hours have elapsed since the last post to a bug for a rev in the buglist"""

    post = False
    has_revision = False
    if os.path.isfile(filename):
        log.debug("Located postedbug list, checking contents...")
        f = open(filename, 'r')
        for line in f.readlines():
            (bug, rev,timestamp, human_time) = line.split("|")
            if revision == rev:
                has_revision = True
                # checking elapsed time is greater than the polling interval so as not to spam bugs
                post = time() - POLLING_INTERVAL > timestamp
        f.close()
    log.debug("has_revision: %s post: %s" % (has_revision, post))
    return (has_revision, post)

def WriteToBuglist(revision, bug, filename=BUGLIST):
    """ Writes a bug number and timestamp of complete build info to the BUGLIST."""

    try:
        f = open(filename, 'a')
        f.write("%s|%s|%d|%s\n" % (bug, revision, time(), strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())))
        f.close()
    except:
        traceback.print_exc(file=sys.stdout)
    log.debug("WRITTEN TO %s: %s" % (filename, revision))

def LoadCache(filename):
    """Search for existing cache file for revision, return dict of revisions in the file"""
    revisions = {}
    log.debug("Checking for existing cache file...")
    if os.path.isfile(filename):
        log.debug("Located existing cache file, checking contents...")
        f = open(filename, 'r')
        for line in f.readlines():
            (time,revision,status) = line.split("|")
            revisions[revision] = {}
        f.close()
    else:
        log.debug("No cache file present")
    log.debug("READ FROM %s: %s" % (filename, revisions))
    return revisions

def WriteToCache(filename, incomplete):
    """ Writes a dictionary of incomplete builds' info to the specified filename."""
    try:
        f = open(filename, 'w')
        for revision, results in incomplete.items():
            f.write("%s|%s|%s\n" % (strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()), revision, results))
        f.close()
    except:
        traceback.print_exc(file=sys.stdout)
    log.debug("WRITTEN TO %s: %s" % (filename,incomplete))

def CalculateBuildRequestStatus(buildrequests):
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
    }
    is_complete = False
    for key,value in buildrequests.items():
        # get the status for each buildrequest item and build the rev_revision['log']for the revision
        status['total_builds'] +=1
        br = value.to_dict()
        # Do the tallying of statuses
        if br['status_str'].lower() in status.keys():
            status[br['status_str'].lower()] += 1

    # Calculate completeness -- check against the timeout threshold
    total_complete = status['misc'] + status['interrupted'] + status['cancelled'] + status['complete']
    if status['total_builds'] == total_complete:
        timeout_complete = []
        for key,value in buildrequests.items():
            br = value.to_dict()
            if br['finish_time']:
                timeout_complete.append(time() - br['finish_time'] > COMPLETION_THRESHOLD)
            for c in timeout_complete:
                if not c:
                    is_complete = False
        # TODO: If is_complete = True do a check for Orange here to get if is_complete is REALLY true or not
        is_complete = True
        log.debug("REV %s COMPLETED -- CALCULATIONS: %s: %s" % (br['revision'],status,is_complete))
    return (status,is_complete)

def GetRevisions(db, branch, starttime=None, endtime=None):
    """ Gets the buildrequests between starttime & endtime, returns a dict keyed by revision
    with the buildrequests per revision"""

    rev_dict = {}
    buildrequests = db.GetBuildRequests(None, branch, starttime, endtime)
    for key, value in buildrequests.items():
        # group buildrequests by revision
        br = value.to_dict()
        revision = br['revision']
        if not rev_dict.has_key(revision):
            rev_dict[revision] = {}
    return rev_dict

def SchedulerDBPollerByRevision(revision, branch, scheduler_db, autoland_db, flagcheck, config, dry_run=False):
    message = None
    posted_to_bug = False
    buildrequests = scheduler_db.GetBuildRequests(revision, branch)
    type = ProcessPushType(revision, buildrequests, autoland_db, flagcheck)
    bugs = GetBugNumbers(buildrequests)
    status, is_complete = CalculateBuildRequestStatus(buildrequests)
    log.debug("RESULTS: %s BUGS: %s TYPE: %s IS_COMPLETE: %s" % (status, bugs, type, is_complete))
    if is_complete and type == "try" and len(bugs) > 0:
        results = CalculateResults(buildrequests)
        # Now check report for oranges to be retried
        message = GenerateResultReportMessage(revision, results, GetSingleAuthor(buildrequests))
        log.debug("MESSAGE: %s" % message)
        for bug in bugs:
            api = config.get('bz_api', 'url')
            username = config.get('bz_api', 'username')
            password = config.get('bz_api', 'password')
            has_revision, post = CheckBugCommentTimeout(revision)
            if has_revision and not post:
                log.debug("NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
            else:
                if message != None:
                    # Comment in the bug
                    r = bz_utils.bz_notify_bug(api, bug, message, username, password)
                    if r and not has_revision:
                        WriteToBuglist(revision, bug)
                        log.debug("BZ POST SUCCESS bug:%s" % bug)
                        posted_to_bug = True
                else:
                    log.debug("BZ POST FAILED message: %s bug: %s, couldn't notify bug. Try again later." % (message, bug))
    else:
        log.debug("Something is not matching up:\nis_complete: %s\ntype: %s\nbugs: %s" %
                    (is_complete, type, bugs))
    return (message, posted_to_bug)

def SchedulerDBPollerByTimeRange(scheduler_db, branch, starttime, endtime, autoland_db, flagcheck, config, dry_run=False, cache_filename=None):
    cache_filename = branch + "_cache"
    # Make a message queue instance
    mq = mq_utils.mq_util()

    # Get all the unique revisions in the specified timeframe range
    rev_report = GetRevisions(scheduler_db, branch, starttime, endtime)
    # Add in any revisions currently in cache for a complete list to poll schedulerdb about
    if os.path.exists(cache_filename):
        rev_report.update(LoadCache(cache_filename))

    # Check each revision's buildrequests to determine: completeness, type
    for revision in rev_report.keys():
        buildrequests = scheduler_db.GetBuildRequests(revision, branch)
        rev_report[revision]['bugs'] = GetBugNumbers(buildrequests)
        rev_report[revision]['push_type'] = ProcessPushType(revision, buildrequests, autoland_db, flagcheck)
        (rev_report[revision]['status'], rev_report[revision]['is_complete']) = CalculateBuildRequestStatus(buildrequests)

        # For completed runs, generate a bug comment message if there are bugs
        if rev_report[revision]['is_complete'] and len(rev_report[revision]['bugs']) > 0:
            rev_report[revision]['results'] = CalculateResults(buildrequests)
            rev_report[revision]['message'] = GenerateResultReportMessage(revision, rev_report[revision]['results'], GetSingleAuthor(buildrequests))
        else:
            rev_report[revision]['message'] = None

    # Process the completed rev_report for this run, gather incomplete revisions and writing to cache
    incomplete = {}
    for revision,info in rev_report.items():
        log.debug("PROCESSING --- REV: %s: INFO: %s" % (revision, info))
        # Incomplete gets added to dict for later processing
        if not info['is_complete']:
            incomplete[revision] = {'status': info['status'],
                                    'bugs': info['bugs'],
                                    }
        # For completed buildruns determine handling for the completed revision:
        # PushToTry with bug(s) gets a bug post or log print depending on --dry-run
        if info['is_complete'] and info['push_type'] == "try" and len(info['bugs']) > 0:
            for bug in info['bugs']:
                api = config.get('bz_api', 'url')
                username = config.get('bz_api', 'username')
                password = config.get('bz_api', 'password')
                has_revision, post = CheckBugCommentTimeout(revision)
                if dry_run:
                    if has_revision and not post:
                        log.debug("DRY-RUN: NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                    else:
                        log.debug("DRY-RUN: POST TO BUG: %s\n%s" % (bug, info['message']))
                        if not has_revision:
                            WriteToBuglist(revision, bug)
                else:
                    if has_revision and not post:
                        log.debug("NOT POSTING TO BUG %s, ALREADY POSTED RECENTLY" % bug)
                    else:
                        # Comment in the bug
                        r = bz_utils.bz_notify_bug(api, bug, info['message'], username, password)
                        if r and not has_revision:
                            WriteToBuglist(revision, bug)
                            log.debug("BZ POST SUCCESS bugs:%s" % info['bugs'])
                        elif not r:
                            log.debug("BZ POST FAIL bugs:%s, putting into cache and will retry later" % info['bugs'])
                            # put it back (only once per revision) into the cache file to try again later
                            if not incomplete.has_key(revision):
                                incomplete[revision] = {'status': info['status'],
                                                        'bugs': info['bugs'],
                                                        }
        # PushToTry but no bug number(s) gets discarded with log note for debugging
        elif info['is_complete'] and info['push_type'] == "try" and not len(info['bugs']) > 0:
            log.debug("Push to try for %s is not requesting bug post - moving along..." % revision)
        # Autoland revision is complete, send message to the BugCommenter queue
        elif info['is_complete'] and info['push_type'] == "auto":
            log.debug("Autoland wants to know about %s - bug commenter message sent" % revision)
            # TODO - get the run's status to fit into one of success/failure
            if len(info['bugs']) == 1:
                msg = { 'type'  : status,
                        'action': 'try.push',
                        'bugid' : info['bugs'][0],
                        'revision': revision }
                mq.send_message(msg, config.get('mq', 'queue'),
                    routing_keys=[config.get('mq', 'db_queue')])
            else:
                log.debug("Don't know what to do with %d bugs. Autoland tracks one bug right now." % len(info['bugs']))
        # Complete but neither PushToTry nor Autoland, throw it away
        elif info['is_complete'] and info['push_type'] == None:
            log.debug("Nothing to do for %s - no one cares about it" % revision)

    WriteToCache(cache_filename, incomplete)

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
    parser.add_argument("-r", "--revision", dest="revision", help="a specific revision to poll")
    parser.add_argument("-s", "--start-time", dest="starttime", help="unix timestamp to start polling from")
    parser.add_argument("-e", "--end-time", dest="endtime", help="unix timestamp to poll until")
    parser.add_argument("-f", "--flagcheck", dest="flagcheck", help="check for the --post-to-bugzilla flag in comments", action='store_true')
    parser.add_argument("-n", "--dry-run", dest="dry_run", help="flag for turning off actually posting to bugzilla", action='store_true')
    parser.add_argument("-c", "--config-file", dest="config", help="config file to use for accessing db", required=True)
    parser.add_argument("-u", "--user", dest="user", help="username for buildapi ldap posting", required=True)
    parser.add_argument("-p", "--password", dest="password", help="password for buildapi ldap posting", required=True)
    parser.set_defaults(
        branch="try",
        revision=None,
        starttime = time() - POLLING_INTERVAL,
        endtime = time(),
    )

    options, args = parser.parse_known_args()

    # Validation on the timestamps provided
    if options.starttime > time():
        log.debug("Starttime %s must be earlier than the current time %s" % (options.starttime, time.localtime()))
        sys.exit(1)
    if options.endtime < options.starttime:
        log.debug("Endtime %s must be later than the starttime %s" % (options.endtime, options.starttime))
        sys.exit(1)
    if options.endtime - options.starttime > MAX_POLLING_INTERVAL:
        log.debug("Too large of a time interval between start and end times, please try a smaller polling interval")
        sys.exit(1)

    # Check for and load the config file
    if not os.path.exists(options.config):
        log.debug("Config file does not exist or is not valid.")
        sys.exit(1)
    else:
        config = ConfigParser.ConfigParser()
        config.read(options.config)

    # Grab the db handlers
    scheduler_db = DBHandler(config.get('databases', 'scheduler_db_url'))
    autoland_db = DBHandler(config.get('databases', 'autoland_db_url'))

    if options.revision:
        result, posted_to_bug = SchedulerDBPollerByRevision(options.revision, options.branch, scheduler_db, autoland_db, options.flagcheck, config, options.dry_run)
        log.debug("Single revision run complete: RESULTS: %s POSTED_TO_BUG: %s" % (result, posted_to_bug))
    else:
        incomplete = SchedulerDBPollerByTimeRange(scheduler_db, options.branch, options.starttime, options.endtime, autoland_db, options.flagcheck, config, options.dry_run)
        log.debug("Time range run complete: INCOMPLETE %s" % incomplete)

    sys.exit(0)
