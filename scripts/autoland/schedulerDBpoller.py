try:
    import simplejson as json
except ImportError:
    import json
import sys, os, traceback, urllib2, urllib
from time import time, strftime, strptime, localtime, mktime, gmtime
from argparse import ArgumentParser
from utils.db_handler import DBHandler
import ConfigParser
import utils.bz_utils as bz_utils
import utils.mq_utils as mq_utils
import logging, logging.handlers
from mercurial import lock, error

FORMAT = '%(asctime)s - %(module)s - %(funcName)s - %(message)s'
LOGFILE = 'schedulerDBpoller.log'
POSTED_BUGS = 'postedbugs.log'
POLLING_INTERVAL = 14400 # 4 hours
TIMEOUT = 43200 # 12 hours
MAX_POLLING_INTERVAL = 172800 # 48 hours
COMPLETION_THRESHOLD = 600 # 10 minutes
MAX_ORANGE = 2

# console logging, formatted
logging.basicConfig(format=FORMAT)
# sets up a rotating logfile that's written to the working dir
log = logging.getLogger(LOGFILE)

class SchedulerDBPoller():
    def __init__(self, branch, cache_dir, config,
                user=None, password=None, dry_run=False,
                verbose=False, messages=True):

        self.config = ConfigParser.ConfigParser()
        self.config.read(config)
        self.branch = branch
        self.cache_dir = cache_dir
        self.dry_run = dry_run
        self.verbose = verbose
        self.messages = messages

        # Set up the message queue
        if self.messages:
            self.mq = mq_utils.mq_util()
            self.mq.set_host(self.config.get('mq', 'host'))
            self.mq.set_exchange(self.config.get('mq', 'exchange'))
            self.mq.connect()

        # Set up bugzilla api connection
        self.bz_url = self.config.get('bz', 'url')
        self.bz = bz_utils.bz_util(self.config.get('bz', 'api_url'),
                        self.config.get('bz', 'url'),
                        None, self.config.get('bz', 'username'),
                        self.config.get('bz', 'password'))

        # Set up Self-Serve API
        self.self_serve_api_url = self.config.get('self_serve', 'url')
        if user:
            self.user = user
        else:
            self.user = self.config.get('self_serve', 'user')

        if password:
            self.password = password
        else:
            self.password = self.config.get('self_serve', 'password')

        # Set up database handler
        self.scheduler_db = DBHandler(self.config.get('databases',
                                'scheduler_db_url'))

    def revision_timed_out(self, revision, timeout=TIMEOUT):
        """
        Read the cache file for revision and return if the build has timed out
        """
        timed_out = False
        now = time()
        if self.verbose:
            log.debug("Checking for timed out revision: %s" % revision)
        filename = os.path.join(self.cache_dir, revision)
        print "Opening file: %s" % (filename)
        try:
            with open(filename, 'r') as f_in:
                entries = f_in.readlines()
        except IOError:
            log.error("Couldn't open cache file for rev: %s" % revision)
            return False

        try:
            first_entry = mktime(strptime(entries[0].split('|')[0],
                            "%a, %d %b %Y %H:%M:%S %Z"))
        except (OverflowError, ValueError), err:
            log.error("Couldn't format time for entry: %s" % err)
            raise

        diff = now - first_entry
        if diff > timeout:
            log.debug("Timeout on rev: %s " % revision)
            timed_out = True
        return timed_out

    def orange_factor_handling(self, buildrequests):
        """
        Checks buildrequests results.
        If all success except # warnings is <= MAX_ORANGE
            * Check if the buildername with warning result is
              duplicated in requests
            * If not, triggers a rebuild using self-serve API of that
              buildernames's buildid
            * If yes, check the results of the pair and report back
              success/fail based on:
                  orange:green == Success, intermittent orange
                  orange:orange == Failed on retry
        returns:
            is_complete {True,False}
            final_status {'success', 'failure', None}
        """
        is_complete = None
        final_status = None
        results = self.calculate_results(buildrequests)
        log.debug("RESULTS (orange_factor_handling): %s" % results)
        if results['total_builds'] == results['success'] + \
                results['failure'] + results['other'] + \
                results['skipped'] + results['exception']:
            # It's really complete, now check for success
            is_complete = True
            if results['total_builds'] == results['success']:
                final_status = "SUCCESS"
                log.debug("Complete and a success")
            else:
                final_status = "FAILURE"
                log.debug("Complete and a failure")
        elif results['total_builds'] - results['warnings'] == \
                results['success'] and results['warnings'] <= (MAX_ORANGE * 2):
            # MAX_ORANGE * 2 since on retries, original warnings still counted.
            # The list of oranges it to be compared to previous

            # Get buildernames where result was warnings
            buildernames = {}
            for value in buildrequests.values():
                br = value.to_dict()
                # Collect duplicate buildernames
                if not br['buildername'] in buildernames:
                    buildernames[br['buildername']] = [(br['results_str'],
                        br['branch'], br['bid'])]
                else:
                    buildernames[br['buildername']].append(
                            (br['results_str'], br['branch'], br['bid']))
            retry_count = 0
            retry_pass = 0
            for name, info in buildernames.items():
                # If we have more than one result for a builder name,
                # compare the results
                if len(info) > 1:
                    log.debug("WE HAVE A DUPE: %s" % name)
                    retry_count += 1
                    c =  zip(info[0], info[1])
                    if len(set(c[0])) > 1:
                        log.debug("We have a mismatch in %s"
                                % set(c[0]))
                        # We have a mismatch of results - is one a success?
                        if 'success' in c[0]:
                            log.debug("There's a success, "
                                      "incrementing retry_pass")
                            retry_pass += 1
                # Unique buildername with warnings, attempt a rebuild
                else:
                    for result, branch, bid in info:
                        if result == 'warnings':
                            log.debug("Attempting to retry branch: "
                                      "%s bid: %s" % (branch, bid))
                            try:
                                post = self.self_serve_rebuild(bid)
                                is_complete = False
                                final_status = "retrying"
                            except:
                                is_complete = True
                                final_status = "FAILURE"
            # Passed on Retry
            if retry_count != 0 and retry_pass == retry_count:
                is_complete = True
                final_status = "SUCCESS"
            # Failed on Retry
            elif retry_count != 0:
                is_complete = True
                final_status = "FAILURE"
        else:
            # too many warnings, no point retrying builds
            log.debug("Too many warnings! Final = failure")
            is_complete = True
            final_status = "FAILURE"

        return is_complete, final_status

    def self_serve_rebuild(self, buildid):
        """
        Uses self-serve API to retrigger the buildid/branch
        sent in with a POST request
        """
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
        except urllib2.HTTPError, err:
            log.debug("FAIL attempted rebuild for %s:%s -- %s"
                    % (self.branch, buildid, err))
            raise
        except ValueError, err:
            log.debug("FAILED to load json result for %s:%s -- %s"
                    % (self.branch, buildid, err))

    def get_single_author(self, buildrequests):
        """
        Look through a list of buildrequests and return only one author
        from the changes if one exists
        """
        author = None
        for value in buildrequests.values():
            br = value.to_dict()
            if author == None:
                author = br['authors']
        # if there's one author return it
        if len(author) == 1:
            return author[0]
        elif author:
            log.error("More than one author for: %s" % br)

    def get_bug_numbers(self, buildrequests):
        """
        Look through a list of buildrequests and return bug number
        from push comments.
        """
        bugs = []
        for value in buildrequests.values():
            br = value.to_dict()
            for comment in br['comments']:
                # we only want the bug specified in try syntax
                if 'try: ' in comment:
                    comment = comment.split('try: ')[1]
                    bugs = self.bz.bugs_from_comments(comment)
        return bugs

    def process_push_type(self, revision, buildrequests, flag_check=True):
        """
        Search buildrequest comments for try syntax and query autoland_db

        returns type as "try", "auto", or None
            try: if "try: --post-to-bugzilla" is present in the comments
                 of a buildrequest
            auto: if a check for 'autoland-' in the comments returns True
                  (for future branch landings)
            None: if not try request and Autoland system isn't tracking it
        """
        push_type = None
        for value in buildrequests.values():
            br = value.to_dict()
            for comments in br['comments']:
                if 'try: ' in comments:
                    if flag_check:
                        if '--post-to-bugzilla' in comments:
                            push_type = "TRY"
                    else:
                        push_type = "TRY"
                if 'autoland-' in comments:
                    push_type = "AUTO"
        return push_type

    def calculate_results(self, buildrequests):
        """
        Returns dictionary of the results for the buildrequests passed in.
        """

        results = {
            'success': 0,
            'warnings': 0,
            'failure': 0,
            'skipped': 0,
            'exception': 0,
            'other': 0,
            'total_builds': 0
        }
        for value in buildrequests.values():
            br = value.to_dict()
            # Do the tallying of statuses
            if br['results_str'].lower() in results.keys():
                results[br['results_str'].lower()] += 1
            else:
                results['other'] += 1
        results['total_builds'] = sum(results.values())
        return results

    def generate_result_report_message(self, revision, report, author=None):
        """
        Returns formatted message of revision report.
        """
        log.debug("REPORT: %s" % report)

        message = "Try run for %s is complete.\n" \
                  "Detailed breakdown of the results available here:\n" \
                  "\thttps://tbpl.mozilla.org/?tree=%s&rev=%s\n" \
                  "Results (out of %d total builds):\n" \
                  % (revision, self.branch.title(),
                     revision, report['total_builds'])
        for key, value in report.items():
            if value > 0 and key != 'total_builds':
                message += "    %s: %d\n" % (key, value)
        if author:
            message += "Builds (or logs if builds failed) available at:\n" \
                       "http://ftp.mozilla.org/pub/mozilla.org/firefox/" \
                       "try-builds/%s-%s" % (author, revision)
        return message

    def write_to_buglist(self, revision, bug, filename=POSTED_BUGS):
        """
        Writes a bug #, timestamp, and build's info to the BUGLIST to
        track what has been posted.
        Also calls remove_cache on the revision once it's been posted.
        """
        if self.dry_run:
            log.debug("DRY_RUN: WRITING TO %s: %s" % (filename, revision))
        else:
            try:
                with open(filename, 'a') as f_out:
                    f_out.write("%s|%s|%d|%s\n" % (bug, revision, time(),
                        strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())))
                log.debug("WROTE TO %s: %s" % (filename, revision))
                self.remove_cache(revision)
            except IOError, err:
                log.error("Encountered error while writing bug list: %s" % err)
                traceback.print_exc(file=sys.stdout)

    def remove_cache(self, revision):
        # attach '.done' to the cache file so we're not tracking it anymore
        # delete original cache file
        cache_file = os.path.join(self.cache_dir, revision)
        log.debug("MOVING %s CACHE FILE to %s"
                % (cache_file, cache_file + '.done'))
        try:
            os.rename(cache_file, cache_file + '.done')
            os.remove(cache_file)
        except OSError, err:
            log.error("Error while removing cache revision %s:%s -- %s"
                        % (revision, cache_file, err))

    def load_cache(self):
        """
        Search for cache dir, return dict of all filenames (revisions) in the
        dir and a list of completed revisions to knock out of poll run
        """
        revisions = {}
        completed_revisions = []
        log.debug("Scanning cache files...")

        if os.path.isdir(self.cache_dir):
            cache_revs = os.listdir(self.cache_dir)
            for revision in cache_revs:
                if '.done' in revision:
                    completed_revisions.append(revision.split('.')[0])
                else:
                    revisions[revision] = {}

        return revisions, completed_revisions

    def write_to_cache(self, incomplete):
        """
        Writes results of incomplete build to cache dir in a file that is
        named with the revision
        """
        try:
            assert isinstance(incomplete, dict)
        except AssertionError:
            log.error("Incomplete should be type:dict")
            raise

        if not os.path.isdir(self.cache_dir):
            if not self.dry_run:
                try:
                    os.mkdir(self.cache_dir)
                    log.debug("CREATED DIR: %s" % self.cache_dir)
                except OSError, err:
                    log.error("Could not create cache dir %s -- %s"
                                % (self.cache_dir, err))
                    raise
            else:
                log.debug("DRY RUN: WOULD CREATE DIR: %s" % self.cache_dir)

        for revision, results in incomplete.items():
            filename = os.path.join(self.cache_dir, revision)
            if self.dry_run:
                log.debug("DRY RUN: WOULD WRITE TO %s: %s|%s\n" % (filename,
                    strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()),
                    results))
            else:
                try:
                    with open(filename, 'a') as f_out:
                        f_out.write("%s|%s\n"
                                % (strftime("%a, %d %b %Y %H:%M:%S %Z",
                                   localtime()), results))
                    log.debug("WROTE TO %s: %s|%s\n" % (filename,
                        strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()),
                        results))
                except IOError:
                    log.error(traceback.print_exc(file=sys.stdout))
                    raise

    def calculate_build_request_status(self, buildrequests, revision=None):
        """
        Accepts buildrequests and calculates their results, calls
        orange_factor_handling to ensure completeness of results, makes sure
        that COMPLETION_THRESHOLD is met before declaring a build finished
        (this is for delays in test triggerings)

        If a revision is passed in, the revision will be checked for timeout in
        revision_timed_out and factored into the is_complete value

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
        for value in buildrequests.values():
            status['total_builds'] += 1
            br = value.to_dict()
            if br['status_str'].lower() in status.keys():
                status[br['status_str'].lower()] += 1

        total_complete = status['misc'] + status['interrupted'] + \
                status['cancelled'] + status['complete']
        if status['total_builds'] == total_complete:
            is_complete = True
            timeout_complete = []
            for value in buildrequests.values():
                br = value.to_dict()
                if br['finish_time']:
                    timeout_complete.append(
                        (time() - br['finish_time']) > COMPLETION_THRESHOLD)
                for passed_timeout in timeout_complete:
                    if not passed_timeout:
                        # we'll wait a bit and make sure no tests are coming
                        is_complete = False
                        break
            if is_complete:
                # one more check before it's _really complete_
                # any oranges to retry?
                log.debug("Check Orange Factor for rev: %s" % revision)
                is_complete, status['status_string'] = \
                        self.orange_factor_handling(buildrequests)
        # check timeout, maybe it's time to kick this out of the tracking queue
        if revision != None:
            if self.revision_timed_out(revision):
                status['status_string'] = 'TIMED_OUT'
                is_complete = True

        return (status, is_complete)

    def get_revisions(self, starttime=None, endtime=None):
        """
        Gets the buildrequests between starttime & endtime
        returns a dict keyed by revision with the buildrequests per revision
        """
        rev_dict = {}
        buildrequests = self.scheduler_db.GetBuildRequests(None, self.branch,
                starttime, endtime)
        for value in buildrequests.values():
            # group buildrequests by revision
            br = value.to_dict()
            revision = br['revision']
            if not revision in rev_dict:
                rev_dict[revision] = {}
        return rev_dict

    def process_completed_revision(self, revision, message,
            bug, status_str, push_type):
        """
        Posts to bug and sends msg to autoland mq with completion status
        """

        bug_post = False
        posted = False
        result = False
        action = push_type + '.RUN'

        if status_str == 'TIMED_OUT':
            message += "\n Timed out after %s hours without completing." \
                            % strftime('%I', gmtime(TIMEOUT))
        posted = self.bz.has_comment(message, bug)

        if posted:
            log.debug("NOT POSTING TO BUG %s, ALREADY POSTED" % bug)
            posted = True
            self.remove_cache(revision)
        else:
            if self.dry_run:
                log.debug("DRY_RUN: Would post to %s%s" % (self.bz_url, bug))
            else:
                log.debug("Type: %s Revision: %s - "
                        "bug comment & message being sent"
                        % (push_type, revision))
                result = self.bz.notify_bug(message, bug)
        if result:
            self.write_to_buglist(revision, bug)
            log.debug("BZ POST SUCCESS result: %s bug: %s%s"
                    % (result, self.bz_url, bug))
            bug_post = True
            if self.messages:
                msg = { 'type'  : status_str,
                        'action': action,
                        'bug_id' : bug,
                        'revision': revision }
                self.mq.send_message(msg, routing_key='db')

        elif not self.dry_run and not posted:
            # Still can't post to the bug even on time out?
            # Throw it away for now (maybe later we'll email)
            if status_str == 'TIMED_OUT' and not result:
                self.remove_cache(revision)
            else:
                log.debug("BZ POST FAILED message: %s bug: %s, "
                        "couldn't notify bug. Try again later."
                        % (message, bug))
        return bug_post

    def poll_by_revision(self, revision, flag_check=False):
        """
        Run a single revision through the polling process to determine if it is
        complete, or not.
        returns information on the revision in a dict which includes the
        message that can be posted to a bug, whether the message was
        successfully posted, and the current status of the builds
        """
        info = {
            'message': None,
            'posted_to_bug': False,
            'status': None,
            'is_complete': False,
            'discard': False,
        }
        buildrequests = self.scheduler_db.GetBuildRequests(
                revision, self.branch)
        push_type = self.process_push_type(revision, buildrequests, flag_check)
        bugs = self.get_bug_numbers(buildrequests)
        info['status'], info['is_complete'] = \
                self.calculate_build_request_status(buildrequests, revision)
        log.debug("POLL_BY_REVISION: RESULTS: %s BUGS: %s "
                "TYPE: %s IS_COMPLETE: %s"
                % (info['status'], bugs, push_type, info['is_complete']))
        if info['is_complete'] and len(bugs) > 0:
            results = self.calculate_results(buildrequests)
            info['message'] = self.generate_result_report_message(revision,
                    results, self.get_single_author(buildrequests))
            log.debug("POLL_BY_REVISION: MESSAGE: %s" % info['message'])
            for bug in bugs:
                if info['message'] and not self.dry_run:
                    info['posted_to_bug'] = self.process_completed_revision(
                            revision=revision, message=info['message'],
                            bug=bug, push_type=push_type,
                            status_str=info['status']['status_string'])
                elif self.dry_run:
                    log.debug("DRY RUN: Would have posted %s to %s"
                            % (info['message'], bug))
        # No bug number(s) or no try syntax
        # complete still gets flagged for discard
        elif info['is_complete']:
            log.debug("Nothing to do here for %s" % revision)
            info['discard'] = True
        else:
            if bugs and not self.dry_run:
                # Cache it
                log.debug("Writing %s to cache" % revision)
                incomplete = {}
                incomplete[revision] = info['status']
                self.write_to_cache(incomplete)
            else:
                info['discard'] = True
        return info

    def poll_by_time_range(self, starttime, endtime):
        # Get all the unique revisions in the specified timeframe range
        rev_report = self.get_revisions(starttime, endtime)
        # Check the cache for any additional revisions to pull reports for
        revisions, completed_revisions = self.load_cache()
        log.debug("INCOMPLETE REVISIONS IN CACHE %s" % (revisions))
        rev_report.update(revisions)
        # Clear out complete revisions from the rev_report keys
        for rev in completed_revisions:
            if 'rev' in rev_report:
                log.debug("Removing %s from the revisions to poll, "
                          "it's been done." % rev)
                del rev_report[rev]

        # Check each revision's buildrequests to determine: completeness, type
        for revision in rev_report.keys():
            buildrequests = self.scheduler_db.GetBuildRequests(
                    revision, self.branch)
            rev_report[revision]['bugs'] = self.get_bug_numbers(buildrequests)
            rev_report[revision]['push_type'] = self.process_push_type(
                    revision, buildrequests)
            (rev_report[revision]['status'],
             rev_report[revision]['is_complete']) = \
                     self.calculate_build_request_status(buildrequests,
                                                         revision)

            # For completed runs, generate a bug comment message if necessary
            if rev_report[revision]['is_complete'] and \
                    len(rev_report[revision]['bugs']) > 0:
                rev_report[revision]['results'] = \
                        self.calculate_results(buildrequests)
                rev_report[revision]['message'] = \
                        self.generate_result_report_message(revision,
                                rev_report[revision]['results'],
                                self.get_single_author(buildrequests))
            else:
                rev_report[revision]['message'] = None

        # Process the completed rev_report for this run
        # gather incomplete revisions and writing to cache
        incomplete = {}
        for revision, info in rev_report.items():
            # Add incomplete builds with bugs to a dict for re-checking later
            if not info['is_complete']:
                if len(info['bugs']) == 1:
                    incomplete[revision] = {'status': info['status'],
                                            'bugs': info['bugs'],
                                            }

            # Try syntax has --post-to-bugzilla so we want to post to bug
            if info['is_complete'] and \
                    info['push_type'] != None and len(info['bugs']) == 1:
                bug = info['bugs'][0]
                if not self.process_completed_revision(revision,
                              rev_report[revision]['message'],
                              bug,
                              rev_report[revision]['status']['status_string'],
                              info['push_type']):
                    # If bug post didn't happen put it back
                    # (once per revision) into cache to try again later
                    if not revision in incomplete:
                        incomplete[revision] = {'status': info['status'],
                                                'bugs': info['bugs'],
                                                }
            # Complete but to be discarded
            elif info['is_complete']:
                log.debug("Nothing to do for push_type:%s revision:%s - "
                          "no one cares about it"
                              % (info['push_type'], revision))
                self.remove_cache(revision)
        # Clean incomplete list of timed out build runs
        for rev in incomplete.keys():
            if incomplete[rev]['status']['status_string'] == 'TIMED_OUT':
                del incomplete[rev]

        # Store the incomplete revisions for the next run if there's a bug
        self.write_to_cache(incomplete)

        return incomplete

if __name__ == '__main__':
    """
    Poll the schedulerdb for all the buildrequests of a certain timerange or a
    single revision. Determine the results of that revision/timerange's
    buildsets and then posts to the bug with results for any that are complete
    (if it's a try-syntax push, then checks for --post-to-bugzilla flag).
    Any revision(s) builds that are not complete are written to a cache file
    named by revision for checking again later.
    """

    # XXX: This should be set to logging.DEBUG if verbose flag passed
    log.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(LOGFILE,
            maxBytes=50000, backupCount=5)
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
                        help="flag for turning off posting to bugzilla",
                        action='store_true')
    parser.add_argument("-v", "--verbose",
                        dest="verbose",
                        help="turn on verbose output",
                        action='store_true')
    parser.add_argument("--cache-dir",
                        dest="cache_dir",
                        help="working dir for tracking incomplete revisions")
    parser.add_argument("--no-messages",
                        dest="messages",
                        help="toggle for sending messages to queue",
                        action='store_false')
    parser.add_argument("--flag-check",
                        dest="flag_check",
                        help="toggle for checking if --post-to-bugzilla "
                             "is in the build's comments",
                        action='store_true')
    parser.set_defaults(
        branch="try",
        cache_dir="cache",
        revision=None,
        starttime = time() - POLLING_INTERVAL,
        endtime = time(),
        dry_run = False,
        messages = True,
        flag_check = False,
    )

    options, args = parser.parse_known_args()

    if not os.path.exists(options.config):
        log.debug("Config file does not exist or is not valid.")
        sys.exit(1)

    lock_file = None
    try:
        lock_file = lock.lock(os.path.join(os.getcwd(),
                    '.schedulerDbPoller.lock'), timeout=1)

        if options.revision:
            poller = SchedulerDBPoller(branch=options.branch,
                    cache_dir=options.cache_dir, config=options.config,
                    user=options.user, password=options.password,
                    dry_run=options.dry_run, verbose=options.verbose)
            result = poller.poll_by_revision(
                    options.revision, options.flag_check)
            if options.verbose:
                log.setLevel(logging.DEBUG)
                log.debug("Single revision run complete: "
                        "RESULTS: %s POSTED_TO_BUG: %s"
                        % (result, result['posted_to_bug']))
        else:
            if options.starttime > time():
                log.debug("Starttime %s must be earlier than the "
                        "current time %s" % (options.starttime, localtime()))
                sys.exit(1)
            elif options.endtime < options.starttime:
                log.debug("Endtime %s must be later than the starttime %s"
                        % (options.endtime, options.starttime))
                sys.exit(1)
            elif options.endtime - options.starttime > MAX_POLLING_INTERVAL:
                log.debug("Too large of a time interval between start and "
                        "end times, please try a smaller polling interval")
                sys.exit(1)
            else:
                poller = SchedulerDBPoller(branch=options.branch,
                                cache_dir=options.cache_dir,
                                config=options.config,
                                user=options.user, password=options.password,
                                dry_run=options.dry_run,
                                verbose=options.verbose,
                                messages=options.messages)
                incomplete = poller.poll_by_time_range(
                                options.starttime, options.endtime)
                if options.verbose:
                    log.debug("Time range run complete: INCOMPLETE %s"
                                % incomplete)
    except error.LockHeld:
        print "There is an instance of SchedulerDbPoller running already."
        print "If you're sure that it' not running, delete %s and try again." \
                % (os.path.join(os.getcwd(), '.schedulerDbPoller.lock'))
        sys.exit(1)
    finally:
        if lock_file:
            lock_file.release()

    sys.exit(0)

