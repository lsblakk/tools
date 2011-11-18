import unittest, os, sys, shutil, mock, urllib2
from time import time
import ConfigParser
sys.path.append('..')
import utils.bz_utils as bz_utils
from autoland_queue import PatchSet
from schedulerDBpoller import SchedulerDBPoller
from utils.db_handler import DBHandler

CONFIG_FILE = 'test/test_config.ini'
BUGLIST="postedbugs.log"
CACHE_DIR="test_cache"
# These are all the revisions in the scheduler.sqlite that has been generated for this
# test suite.  Some of them have had their content altered from the real schedulerdb
# to provide alternate test data.
REVISIONS = ['9465683dcfe5', '83c09dc13bb8', 'b8e5f09eead1', '6f8727aab415', 'e53d9b5ad8f8',
             '7acd48c25b5c', '157ac288e589', 'eb85e9fe0be7', '77d3c3cd755d', '020f7584545b',
             'b60a0c153400', '08b6a1ab405b', '365c4b2067f3', '32d9b56c5ea6', '965f9271f2cf',
             '7fb7e88a1739', '6242c0b1ef60', '87e7b2736018', 'c815c02a8bbc', 'cc750feffa41',
             'd1653821d023', '5fe5c08a5737', '34a6c1275fd0', '8da8f0209359', 'e743e3347c09',
             '867c3741e16d', 'e6ae55cd2f5d', '924976bc4bf9', '127c2f71d6b0']

class SchedulerDBPollerTests(unittest.TestCase):

    def setUp(self):
        # Clean up from previous runs
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
            
        self.poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        self.poller.verbose = True
        self.poller.bz.notify_bug = mock.Mock(return_value=1)
        self.poller.SelfServeRebuild = mock.Mock(return_value={u'status': u'OK', u'request_id': 19354})
        self.maxDiff = None

    def testGetBugNumbers(self):
        bugs = {}
        for revision in REVISIONS:
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
            bugs[revision] = self.poller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, {'9465683dcfe5': [9949], '83c09dc13bb8': [609845], 'b8e5f09eead1': [], '6f8727aab415': [95846], 'e53d9b5ad8f8': [], 'e6ae55cd2f5d': [], '32d9b56c5ea6': [], '157ac288e589': [9949], 'eb85e9fe0be7': [], '77d3c3cd755d': [], '020f7584545b': [], 'b60a0c153400': [], '08b6a1ab405b': [], '365c4b2067f3': [], '7acd48c25b5c': [12345, 234456, 244677], '965f9271f2cf': [], '7fb7e88a1739': [], '87e7b2736018': [], 'c815c02a8bbc': [], 'cc750feffa41': [], 'd1653821d023': [], '5fe5c08a5737': [], '34a6c1275fd0': [], '8da8f0209359': [], 'e743e3347c09': [], '867c3741e16d': [], '6242c0b1ef60': [], '924976bc4bf9': [], '127c2f71d6b0': []})

    def testGetSingleAuthor(self):
        authors = {}
        for revision in REVISIONS:
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
            authors[revision] = self.poller.GetSingleAuthor(buildrequests)
        self.assertEquals(authors, {'9465683dcfe5': u'bherland@mozilla.com', '83c09dc13bb8': u'eakhgari@mozilla.com', 'b8e5f09eead1': u'eakhgari@mozilla.com', '6f8727aab415': u'jdaggett@mozilla.com', 'e53d9b5ad8f8': u'mstange@themasta.com', 'e6ae55cd2f5d': u'dougt@mozilla.com', '32d9b56c5ea6': u'neil@mozilla.com', '157ac288e589': u'mstange@themasta.com', 'eb85e9fe0be7': u'jdrew@mozilla.com', '77d3c3cd755d': u'me@kylehuey.com', '020f7584545b': u'me@kylehuey.com', 'b60a0c153400': u'mmulani@mozilla.com', '08b6a1ab405b': u'jruderman@mozilla.com', '365c4b2067f3': u'masayuki@d-toybox.com', '7acd48c25b5c': u'jorendorff@mozilla.com', '965f9271f2cf': u'mkristoffersen@mozilla.com', '7fb7e88a1739': u'jmaher@mozilla.com', '87e7b2736018': u'tglek@mozilla.com', 'c815c02a8bbc': u'surkov.alexander@gmail.com', 'cc750feffa41': u'mlamouri@mozilla.com', 'd1653821d023': u'eakhgari@mozilla.com', '5fe5c08a5737': u'vladimir@mozilla.com', '34a6c1275fd0': u'cpearce@mozilla.com', '8da8f0209359': u'eakhgari@mozilla.com', 'e743e3347c09': u'mlamouri@mozilla.com', '867c3741e16d': None, '6242c0b1ef60': u'jorendorff@mozilla.com', '924976bc4bf9': u'opettay@mozilla.com', '127c2f71d6b0': u'jmaher@mozilla.com'})

    def testGetBugNumbersForSingleRevisionWithTwoComments(self):
        revision = '9465683dcfe5'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
        bugs = self.poller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, [9949])

    def testGetBugFromComments(self):
        message = "try: -b do -p linux,linuxqt,linux64,macosx64,win32,macosx -u reftest,crashtest,mochitests -t none --post-to-bugzilla b664095"
        bugs = self.poller.bz.bugs_from_comments(message)
        self.assertEquals(bugs, [664095])

    def testPushTypeTry(self):
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "try")

    def testPushTypeTryNoFlagcheck(self):
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        self.poller.flagcheck = False
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "try")

    # Push type should be None since there is incorrect try syntax in this commit message
    def testPushTypeNone(self):
        revision = '08b6a1ab405b'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, None)

    # Push type should be Auto since the revision is being tracked in AutolandDB
    def testPushTypeAutoland(self):
        revision='b8e5f09eead1'
        ps1 = PatchSet(revision=revision)
        ps1.id = self.poller.autoland_db.PatchSetInsert(ps1)
        ps_query = self.poller.autoland_db.PatchSetQuery(PatchSet(id=ps1.id))[0]
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "auto")

    def testProcessPushTypeFlagcheckWithFlag(self):
        revision = '6f8727aab415'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "try")

    def testProcessPushTypeFlagcheckNoFlag(self):
        revision = '157ac288e589'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, None)

    def testGenerateResultReport(self):
        revision = '157ac288e589'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        report = self.poller.CalculateResults(buildrequests)
        message = self.poller.GenerateResultReportMessage(revision, report)
        self.assertEquals(message,'Try run for 157ac288e589 is complete.\nDetailed breakdown of the results available here:\n    https://tbpl.mozilla.org/?tree=Try&rev=157ac288e589\nResults (out of 11 total builds):\n    success: 10\n    warnings: 1\n')

    def testCreateCacheDir(self):
        if os.path.isdir(CACHE_DIR):
            revisions = os.listdir(CACHE_DIR)
            for rev in revisions:
                os.remove(os.path.join(CACHE_DIR,rev))
        os.rmdir(CACHE_DIR)
        self.assertRaises(AssertionError, self.poller.WriteToCache, None)
                    
    def testWriteAndLoadCache(self):
        ## remove test_cache dir here, but it needs to be emptied first
        if os.path.isdir(CACHE_DIR):
            revisions = os.listdir(CACHE_DIR)
            for rev in revisions:
                if rev != '6f8727aab415':
                    os.remove(os.path.join(CACHE_DIR,rev))
        incomplete = {}
        incomplete['6f8727aab415'] = self.poller.PollByRevision('6f8727aab415')
        self.poller.WriteToCache(incomplete)
        revisions = self.poller.LoadCache()
        self.assertEquals(revisions, {'6f8727aab415': {}})

    def testCheckBugCommentTimeout(self):
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        (has_revision, post) = self.poller.CheckBugCommentTimeout('1234', BUGLIST)
        self.assertEquals(has_revision, False)

    def testWriteToBuglist(self):
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        # create a couple of cache file to test that writing to buglist removes the cache file
        # only for the one that is written to buglist
        incomplete = {}
        incomplete['1234'] = {}
        incomplete['2345'] = {}
        self.poller.WriteToCache(incomplete)
        self.poller.WriteToBuglist('1234', '9949', BUGLIST)
        (has_revision, post) = self.poller.CheckBugCommentTimeout('1234', BUGLIST)
        revisions = self.poller.LoadCache()
        self.assertEquals(revisions, {'2345': {}, '6f8727aab415': {}})
        self.assertTrue(has_revision)
    
    def testWriteToBuglistDryRun(self):
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        self.poller.dry_run = True
        # make sure that a dry-run does not write to buglist\
        # TODO - this doesn't seem to do what I think it does
        self.poller.WriteToBuglist('1234', '9949', BUGLIST)
        (has_revision, post) = self.poller.CheckBugCommentTimeout('1234', BUGLIST)
        self.assertFalse(has_revision)

    def testCalculateBuildRequestStatusComplete(self):
        revision = 'e6ae55cd2f5d'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = self.poller.CalculateBuildRequestStatus(buildrequests)
        self.assertEquals(is_complete, True)

    def testCalculateBuildRequestStatusIncomplete(self):
        revision = '6f8727aab415'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = self.poller.CalculateBuildRequestStatus(buildrequests)
        self.assertFalse(is_complete)

    def testPostToBug(self):
        revision = '157ac288e589'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        bugs = self.poller.GetBugNumbers(buildrequests)
        report = self.poller.CalculateResults(buildrequests)
        message = self.poller.GenerateResultReportMessage(revision, report)
        if len(bugs) > 0:
            for bug in bugs:
                # UNCOMMENT to check sandbox bugzilla posting, commented out to avoid spamming the bug
                #r = bz_utils.bz_notify_bug(self.config.get('bz_api', 'url'), self.config.get('bz_api', 'sandbox_bug'), message, self.config.get('bz_api', 'username'), self.config.get('bz_api', 'password'))
                r = True
        self.assertTrue(r)

    def testDBGetBuildRequests(self):
        buildrequests = self.poller.scheduler_db.GetBuildRequests()
        self.assertNotEquals(buildrequests,{})

    def testGetRevisions(self):
        revisions = self.poller.GetRevisions()
        self.assertEquals(revisions.keys()[:5],[u'9465683dcfe5', u'163e8764498e', u'72e79e2d4c48', u'aa4cedbd66ab', u'82f950327fa8'])

    def testPollByRevisionComplete(self):
        # First time should return True as there is not a postedbugs.log
        output = self.poller.PollByRevision('83c09dc13bb8')
        self.assertEqual((u'Try run for 83c09dc13bb8 is complete.\nDetailed breakdown of the results available here:\n    https://tbpl.mozilla.org/?tree=Try&rev=83c09dc13bb8\nResults (out of 10 total builds):\n    success: 9\n    failure: 1\nBuilds (or logs if builds failed) available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/eakhgari@mozilla.com-83c09dc13bb8', True), (output['message'], output['posted_to_bug']))
        # Run CheckBugCommentTimeout again now and there should be a False on posting for this
        # revision, as we have now posted to the bug
        has_revision,post = self.poller.CheckBugCommentTimeout('83c09dc13bb8', filename=BUGLIST)
        self.assertFalse(post)
        # Run the PollByRevision again to test 'it was already written there recently'
        output = self.poller.PollByRevision('83c09dc13bb8')
        self.assertFalse(output['posted_to_bug'])
        self.assertTrue(output['is_complete'])

    def testPollByRevisionIncomplete(self):
        output = self.poller.PollByRevision('6f8727aab415')
        self.assertEqual((None, False), (output['message'], output['posted_to_bug']))

    #### what am I really testing here for dry-run?
    ## test that nothing gets written to postedbugs.log
    ## test that no bug comments get sent?
    def testDryRunPollByRevisionComplete(self):
        self.poller.dry_run = True
        output = self.poller.PollByRevision('83c09dc13bb8')
        # TODO replace this with something to make sure there are no new entries to the test_cache when you run this
        # TODO make sure nothing goes to the bug
        self.assertEqual((u'Try run for 83c09dc13bb8 is complete.\nDetailed breakdown of the results available here:\n    https://tbpl.mozilla.org/?tree=Try&rev=83c09dc13bb8\nResults (out of 10 total builds):\n    success: 9\n    failure: 1\nBuilds (or logs if builds failed) available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/eakhgari@mozilla.com-83c09dc13bb8', False), (output['message'], output['posted_to_bug']))

    def testDryRunPollByRevisionIncomplete(self):
        self.poller.dry_run = True
        output = self.poller.PollByRevision('6f8727aab415')
        self.assertEqual((None, False), (output['message'], output['posted_to_bug']))
    
    def testPollByTimeRange(self):
        incomplete = self.poller.PollByTimeRange(None, None)
        self.assertEquals(incomplete['6f8727aab415']['status']['status_string'], '')
        self.assertEquals(incomplete['abbc6df9a187']['status']['status_string'], 'retrying')
        

    def testPollByTimeRangeDryRun(self):
        self.poller.dry_run = True
        incomplete = self.poller.PollByTimeRange(None, None)
        self.assertEquals(incomplete['6f8727aab415']['status']['status_string'], '')
        self.assertEquals(incomplete['abbc6df9a187']['status']['status_string'], 'retrying')

    def testOrangeFactorRetriesWithoutDupes(self):
        # SAMPLE DATA without having duplicate buildernames - test retrying
        # 9465683dcfe5 {'success': 9, 'warnings': 1, 'failure': 0, 'other': 0}
        # 83c09dc13bb8 {'success': 9, 'warnings': 0, 'failure': 1, 'other': 0}
        # 6f8727aab415 {'success': 0, 'warnings': 9, 'failure': 0, 'other': 1}
        # e6ae55cd2f5d {'success': 10, 'warnings': 0, 'failure': 0, 'other': 0}
        
        revision='e6ae55cd2f5d'
        ps1 = PatchSet(revision=revision)
        ps1.id = self.poller.autoland_db.PatchSetInsert(ps1)

        revisions = {'83c09dc13bb8': (True, 'failure'), '9465683dcfe5': (False, 'retrying'), 'e6ae55cd2f5d': (True, 'success'), '6f8727aab415': (True, 'failure')}
        orange_revs = {}
        for revision in revisions.keys():
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
            orange_revs[revision] = self.poller.OrangeFactorHandling(buildrequests)
        self.assertEqual(orange_revs, revisions)

    def testOrangeFactorRetriesWithSelfServeFail(self):
        # SAMPLE DATA without having duplicate buildernames - test retrying failure
        # 9465683dcfe5 {'success': 9, 'warnings': 1, 'failure': 0, 'other': 0}
        # 83c09dc13bb8 {'success': 9, 'warnings': 0, 'failure': 1, 'other': 0}
        # 6f8727aab415 {'success': 0, 'warnings': 9, 'failure': 0, 'other': 1}
        # e6ae55cd2f5d {'success': 10, 'warnings': 0, 'failure': 0, 'other': 0}
        
        clean_poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        revision='e6ae55cd2f5d'
        ps1 = PatchSet(revision=revision)
        ps1.id = clean_poller.autoland_db.PatchSetInsert(ps1)

        revisions = {'83c09dc13bb8': (True, 'failure'), '9465683dcfe5': (True, 'failure'), 'e6ae55cd2f5d': (True, 'success'), '6f8727aab415': (True, 'failure')}
        orange_revs = {}
        for revision in revisions.keys():
            buildrequests = clean_poller.scheduler_db.GetBuildRequests(revision)
            orange_revs[revision] = clean_poller.OrangeFactorHandling(buildrequests)
        self.assertEqual(orange_revs, revisions)

    def testOrangeFactorRetriesWithDupes(self):
        # SAMPLE DATA with duplicate buildernames (already retried, now what is the result?)
        # One warn, one pass on one dupe buildername- should return (True, 'success')
        # 157ac288e589 {'success': 10, 'warnings': 1, 'total_builds': 11}
        # Three warn, one pass on two dupe buildernames - should return (True, 'failure')
        # 7acd48c25b5c {'success': 9, 'warnings': 3, 'total_builds': 12}
        revisions = {'7acd48c25b5c': (True, 'failure'), '157ac288e589': (True, 'success')}
        orange_revs = {}
        for revision in revisions.keys():
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
            for key, value in buildrequests.items():
                br = value.to_dict()
                print (br['results_str'], br['branch'], br['bid'], br['buildername'], br['brid'])
            orange_revs[revision] = self.poller.OrangeFactorHandling(buildrequests)
        self.assertEqual(orange_revs, revisions)

    def testSelfServeRebuildPass(self):
        results = self.poller.SelfServeRebuild(4801896)
        # Using the Mock return value
        self.assertEquals(results, {u'status': u'OK', u'request_id': 19354})

    def testSelfServeRebuildFail(self):
        clean_poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        # Assert that an HTTPError returns when using the real self-serve
        self.assertRaises(urllib2.HTTPError, clean_poller.SelfServeRebuild, 4801896)

    def testOrangeFactorHandling(self):
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        self.assertEquals(self.poller.OrangeFactorHandling(buildrequests), (True, 'failure'))

if __name__ == '__main__':
    unittest.main(verbosity=2)

"""
TODO Before landing:
* bugzilla posting tests, no double posts!
** This also means including handling for security bugs and for 400 errors (bad bug typing)

* Set a timer on how long we wait/retry to consider complete (not just completed builds, but > N hours)
* Tests/Validation for the argparser of schedulerdbpoller
* Clean up cache files for revisions that are no longer tracked, right now only writing to buglist takes out the file once it's complete
* Better handling for which bug to post to (add a flag?) see: http://hg.mozilla.org/try/rev/d45763120aad where it thought to post to 700835 and not 699134
* only write to file for things that are try or autoland - no need to keep the ones with no bugs in them
* if self-serve retry fails - test that the build comes back as complete


TODO - AUTOLAND enhancements
** bug 695076 is getting hit a lot - need to kick things out of the queue
* can't post to secure bugs - so is there a way to do this? otherwise, need to kick it out of the retry loop
* ability to check what's hidden on tbpl - can we add a schedulerdb table for hidden and have only one place that tbpl and tools like this check?
* Why does every second whiteboard tag not trigger builds?
* More handling around the bug posting in the if type = "auto" section - also tests for this part
* There's a 10 minute gap between schedulerdbpoller runs so you could have an autoland push start & stop in that time with no report back
** HgPusher could send a message to schedulerdbpoller to create the empty cache file so that it's tracked from push time
* Makefile & setup script for test environment
* Set up an archiving script for postedbug.log on cruncher - so we have history of usage
* Make a note in the bug comment message when builds were cancelled via self-serve
* Nagios check top entry in cache files and warn about possibly hung builds
* Make it impossible to override the cache files on cruncher with one in the repo -- don't check in any cache files!!!
"""