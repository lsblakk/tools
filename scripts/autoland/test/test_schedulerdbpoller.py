import unittest, os, sys
sys.path.append('..')
import schedulerDBpoller
from utils.db_handler import DBHandler
import utils.bz_utils as bz_utils
from time import time
import ConfigParser

CONFIG_FILE = 'test/test_config.ini'
FILENAME = "test_cache"
BUGLIST="test_buglist"
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
        if os.path.exists(FILENAME):
            os.remove(FILENAME)
        # get config
        self.config = ConfigParser.ConfigParser()
        self.config.read(CONFIG_FILE)
        # Create DB handlers
        self.scheduler_db = DBHandler(self.config.get('databases', 'scheduler_db_url'))
        self.autoland_db = DBHandler(self.config.get('databases', 'autoland_db_url'))

    # Buildrequests that have a number
    def testGetBugNumbers(self):
        bugs = {}
        for revision in REVISIONS:
            buildrequests = self.scheduler_db.GetBuildRequests(revision, "try")
            bugs[revision] = schedulerDBpoller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, {'9465683dcfe5': [9949], '83c09dc13bb8': [609845], 'b8e5f09eead1': [], '6f8727aab415': [95846], 'e53d9b5ad8f8': [], 'e6ae55cd2f5d': [], '32d9b56c5ea6': [], '157ac288e589': [9949], 'eb85e9fe0be7': [], '77d3c3cd755d': [], '020f7584545b': [], 'b60a0c153400': [], '08b6a1ab405b': [], '365c4b2067f3': [], '7acd48c25b5c': [12345, 234456, 244677], '965f9271f2cf': [], '7fb7e88a1739': [], '87e7b2736018': [], 'c815c02a8bbc': [], 'cc750feffa41': [], 'd1653821d023': [], '5fe5c08a5737': [], '34a6c1275fd0': [], '8da8f0209359': [], 'e743e3347c09': [], '867c3741e16d': [], '6242c0b1ef60': [], '924976bc4bf9': [], '127c2f71d6b0': []})

    def testGetSingleAuthor(self):
        authors = {}
        for revision in REVISIONS:
            buildrequests = self.scheduler_db.GetBuildRequests(revision, "try")
            authors[revision] = schedulerDBpoller.GetSingleAuthor(buildrequests)
        self.assertEquals(authors, {'9465683dcfe5': u'bherland@mozilla.com', '83c09dc13bb8': u'eakhgari@mozilla.com', 'b8e5f09eead1': u'eakhgari@mozilla.com', '6f8727aab415': u'jdaggett@mozilla.com', 'e53d9b5ad8f8': u'mstange@themasta.com', 'e6ae55cd2f5d': u'dougt@mozilla.com', '32d9b56c5ea6': u'neil@mozilla.com', '157ac288e589': u'mstange@themasta.com', 'eb85e9fe0be7': u'jdrew@mozilla.com', '77d3c3cd755d': u'me@kylehuey.com', '020f7584545b': u'me@kylehuey.com', 'b60a0c153400': u'mmulani@mozilla.com', '08b6a1ab405b': u'jruderman@mozilla.com', '365c4b2067f3': u'masayuki@d-toybox.com', '7acd48c25b5c': u'jorendorff@mozilla.com', '965f9271f2cf': u'mkristoffersen@mozilla.com', '7fb7e88a1739': u'jmaher@mozilla.com', '87e7b2736018': u'tglek@mozilla.com', 'c815c02a8bbc': u'surkov.alexander@gmail.com', 'cc750feffa41': u'mlamouri@mozilla.com', 'd1653821d023': u'eakhgari@mozilla.com', '5fe5c08a5737': u'vladimir@mozilla.com', '34a6c1275fd0': u'cpearce@mozilla.com', '8da8f0209359': u'eakhgari@mozilla.com', 'e743e3347c09': u'mlamouri@mozilla.com', '867c3741e16d': None, '6242c0b1ef60': u'jorendorff@mozilla.com', '924976bc4bf9': u'opettay@mozilla.com', '127c2f71d6b0': u'jmaher@mozilla.com'})

    def testGetBugNumbersForSingleRevisionWithTwoComments(self):
        revision = '9465683dcfe5'
        buildrequests = self.scheduler_db.GetBuildRequests(revision, "try")
        bugs = schedulerDBpoller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, [9949])

    # Test bz_utils
    def testGetBugFromComments(self):
        message = "try: -b do -p linux,linuxqt,linux64,macosx64,win32,macosx -u reftest,crashtest,mochitests -t none --post-to-bugzilla b664095"
        bugs = bz_utils.bugs_from_comments(message)
        self.assertEquals(bugs, [664095])

    # Push type should be try because commit message has 'try: ' 
    # TODO check for '--post-to-bugzilla' once that is enabled
    def testPushTypeTry(self):
        revision = '83c09dc13bb8'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        type = schedulerDBpoller.ProcessPushType(revision, buildrequests, self.autoland_db, False)
        self.assertEquals(type, "try")
 
    # Push type should be None since there is incorrect try syntax in this commit message
    def testPushTypeNone(self):
        revision = '08b6a1ab405b'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        type = schedulerDBpoller.ProcessPushType(revision, buildrequests, self.autoland_db, False)
        self.assertEquals(type, None)

    # Push type should be Auto since the revision is being tracked in AutolandDB
    def testPushTypeAutoland(self):
        revision = 'b8e5f09eead1'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        type = schedulerDBpoller.ProcessPushType(revision, buildrequests, self.autoland_db, False)
        self.assertEquals(type, "auto")

    def testProcessPushTypeFlagcheckWithFlag(self):
        revision = '6f8727aab415'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        type = schedulerDBpoller.ProcessPushType(revision, buildrequests, self.autoland_db, True)
        self.assertEquals(type, "try")

    def testProcessPushTypeFlagcheckNoFlag(self):
        revision = '157ac288e589'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        type = schedulerDBpoller.ProcessPushType(revision, buildrequests, self.autoland_db, True)
        self.assertEquals(type, None)

    def testGenerateResultReport(self):
        revision = '157ac288e589'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        report = schedulerDBpoller.CalculateResults(buildrequests)
        message = schedulerDBpoller.GenerateResultReportMessage(revision, report)
        self.assertEquals(message,'Try run for 157ac288e589 is complete.\nDetailed breakdown of the results available here:\n    http://tbpl.mozilla.org/?tree=Try&rev=157ac288e589\nResults (out of 11 total builds):\n    success: 10\n    warnings: 1\n')

    def testLoadCacheNoFile(self):
        revisions = schedulerDBpoller.LoadCache(FILENAME)
        self.assertEquals(revisions, {})

    def testWriteAndLoadCache(self):
        schedulerDBpoller.WriteToCache(FILENAME, {'1234': {}, '2345': {}, '3456': {}})
        revisions = schedulerDBpoller.LoadCache(FILENAME)
        self.assertEquals(revisions, {'1234': {}, '2345': {}, '3456': {}})

    def testCheckBugCommentTimeout(self):
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        (has_revision, post) = schedulerDBpoller.CheckBugCommentTimeout('1234', BUGLIST)
        self.assertEquals(has_revision, False)

    def testWriteToBuglist(self):
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        schedulerDBpoller.WriteToBuglist('1234', '9949', BUGLIST)
        (has_revision, post) = schedulerDBpoller.CheckBugCommentTimeout('1234', BUGLIST)
        self.assertTrue(has_revision)

    def testCalculateBuildRequestStatusComplete(self):
        revision = '157ac288e589'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = schedulerDBpoller.CalculateBuildRequestStatus(buildrequests)
        self.assertTrue(is_complete)

    def testCalculateBuildRequestStatusIncomplete(self):
        revision = '6f8727aab415'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = schedulerDBpoller.CalculateBuildRequestStatus(buildrequests)
        self.assertFalse(is_complete)

    def testPostToBug(self):
        revision = '157ac288e589'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        bugs = schedulerDBpoller.GetBugNumbers(buildrequests)
        report = schedulerDBpoller.CalculateResults(buildrequests)
        message = schedulerDBpoller.GenerateResultReportMessage(revision, report)
        if len(bugs) > 0:
            for bug in bugs:
                # UNCOMMENT to check sandbox bugzilla posting, commented out to avoid spamming the bug
                #r = bz_utils.bz_notify_bug(self.config.get('bz_api', 'url'), self.config.get('bz_api', 'sandbox_bug'), message, self.config.get('bz_api', 'username'), self.config.get('bz_api', 'password'))
                r = True
        self.assertTrue(r)

    def testDBGetBuildRequests(self):
        buildrequests = self.scheduler_db.GetBuildRequests()
        self.assertNotEquals(buildrequests,{})

    def testGetRevisions(self):
        revisions = schedulerDBpoller.GetRevisions(self.scheduler_db, "try")
        self.assertEquals(revisions.keys()[:5],[u'9465683dcfe5', u'163e8764498e', u'72e79e2d4c48', u'aa4cedbd66ab', u'82f950327fa8'])

    def testSchedulerDBByRevision(self):
        output = schedulerDBpoller.SchedulerDBPollerByRevision('83c09dc13bb8', "try", self.scheduler_db, self.autoland_db, True, self.config, True)
        self.assertEqual((u'Try run for 83c09dc13bb8 is complete.\nDetailed breakdown of the results available here:\n    http://tbpl.mozilla.org/?tree=Try&rev=83c09dc13bb8\nResults (out of 10 total builds):\n    success: 9\n    failure: 1\nBuilds available at http://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/eakhgari@mozilla.com-83c09dc13bb8', False), output)

    def testSchedulerDBByTimeRange(self):
        incomplete = schedulerDBpoller.SchedulerDBPollerByTimeRange(self.scheduler_db, "try", None, None, self.autoland_db, True, self.config, True)
        self.assertEquals({'6f8727aab415': {'status': {'complete': 8, 'misc': 0, 'interrupted': 1, 'running': 1, 'cancelled': 0, 'total_builds': 10, 'pending': 0}, 'bugs': [95846]}}, incomplete)

    def testOrangeFactorRetriesWithoutDupes(self):
        # SAMPLE DATA without having duplicate buildernames - test retrying
        # 9465683dcfe5 {'success': 9, 'warnings': 1, 'failure': 0, 'other': 0}
        # 83c09dc13bb8 {'success': 9, 'warnings': 0, 'failure': 1, 'other': 0}
        # 6f8727aab415 {'success': 0, 'warnings': 9, 'failure': 0, 'other': 1}
        # e6ae55cd2f5d {'success': 10, 'warnings': 0, 'failure': 0, 'other': 0}

        revisions = {'9465683dcfe5': (False, None), '83c09dc13bb8': (True, 'failure'), '6f8727aab415': (True, 'failure'), 'e6ae55cd2f5d': (True, 'success')}
        orange_revs = {}
        for revision in revisions.keys():
            buildrequests = self.scheduler_db.GetBuildRequests(revision)
            orange_revs[revision] = schedulerDBpoller.OrangeFactorHandling(buildrequests)
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
            buildrequests = self.scheduler_db.GetBuildRequests(revision)
            for key, value in buildrequests.items():
                br = value.to_dict()
                print (br['results_str'], br['branch'], br['bid'], br['buildername'], br['brid'])
            orange_revs[revision] = schedulerDBpoller.OrangeFactorHandling(buildrequests)
        self.assertEqual(orange_revs, revisions)

    def testPostRetryOrangeHandling(self):
        # Need to test a revision that has 2 oranges with the same builder name
        # or 1 orange & 1 green with same name - in first case pass, send is_complete
        # second case fail
        pass

    def testSelfServeRetry(self):
        results = schedulerDBpoller.SelfServeRetry("try", 4801896, None, None)
        print results
        self.assertTrue(results)

    def testOrangeFactorHandling(self):
        revision = '83c09dc13bb8'
        buildrequests = self.scheduler_db.GetBuildRequests(revision)
        self.assertEquals(schedulerDBpoller.OrangeFactorHandling(buildrequests), (True, 'failure'))

if __name__ == '__main__':
    unittest.main()

"""
TODO:
** Dry-run mode doesn't actually work: I want to see what would get posted - do not actually write to the bug, do not actually write to postedbugs.log
** Turn SchedulerDBPoller into a class so that self.username, self.password and self.config file can be accessed in all modules?
** Make a note in the bug comment message when builds were cancelled via self-serve
** Retry when there's only 1 or 2 warnings on tests - send again via self-serve and mark incomplete so as to wait for results
** when writing incomplete to the file, keep the oldest timestamp for that revisions?
    ie: don't just write to incomplete everytime with the same 10 min interval datetime
    for each line (loaded time setting in the rev_report?)
    *** Write a file for each revision and just append the status line so there's history,
        then delete the revision's file when it is complete
** make a verbose mode
** more tests - there must be stuff missing
** incorporate mq_util - send a message if autoland & complete
** Make it impossible to override the cache file on cruncher with one in the repo -- don't check in any cache files!!!
"""