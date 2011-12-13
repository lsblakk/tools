import unittest, os, sys, shutil, mock, urllib2
import datetime
from time import time, strftime, strptime, localtime, sleep
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
# to provide test data.
REVISIONS = ['9465683dcfe5', '83c09dc13bb8', 'b8e5f09eead1', '6f8727aab415', 'e53d9b5ad8f8',
             '7acd48c25b5c', '157ac288e589', 'eb85e9fe0be7', '77d3c3cd755d', '020f7584545b',
             'b60a0c153400', '08b6a1ab405b', '365c4b2067f3', '32d9b56c5ea6', '965f9271f2cf',
             '7fb7e88a1739', '6242c0b1ef60', '87e7b2736018', 'c815c02a8bbc', 'cc750feffa41',
             'd1653821d023', '5fe5c08a5737', '34a6c1275fd0', '8da8f0209359', 'e743e3347c09',
             '867c3741e16d', 'e6ae55cd2f5d', '924976bc4bf9', '127c2f71d6b0']

class SchedulerDBPollerTests(unittest.TestCase):

    def setUp(self):
        print 'setUp()'
        # Clean up the postedbugs.log from previous runs
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
            
        self.poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        self.poller.verbose = True
        self.poller.SelfServeRebuild = mock.Mock(return_value={u'status': u'OK', u'request_id': 19354})
        self.maxDiff = None

    def testGetBugNumbers(self):
        print 'testGetBugNumbers()'
        bugs = {}
        for revision in REVISIONS:
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
            bugs[revision] = self.poller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, {'9465683dcfe5': [9949], '83c09dc13bb8': [9949], 'b8e5f09eead1': [9949], '6f8727aab415': [95846], 'e53d9b5ad8f8': [], 'e6ae55cd2f5d': [], '32d9b56c5ea6': [], '157ac288e589': [9949], 'eb85e9fe0be7': [], '77d3c3cd755d': [], '020f7584545b': [], 'b60a0c153400': [], '08b6a1ab405b': [], '365c4b2067f3': [], '7acd48c25b5c': [12345, 234456, 244677], '965f9271f2cf': [], '7fb7e88a1739': [], '87e7b2736018': [], 'c815c02a8bbc': [], 'cc750feffa41': [], 'd1653821d023': [], '5fe5c08a5737': [], '34a6c1275fd0': [], '8da8f0209359': [], 'e743e3347c09': [], '867c3741e16d': [], '6242c0b1ef60': [], '924976bc4bf9': [], '127c2f71d6b0': []})

    def testGetSingleAuthor(self):
        print 'testGetSingleAuthor()'
        authors = {}
        for revision in REVISIONS:
            buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
            authors[revision] = self.poller.GetSingleAuthor(buildrequests)
        self.assertEquals(authors, {'9465683dcfe5': u'bherland@mozilla.com', '83c09dc13bb8': u'eakhgari@mozilla.com', 'b8e5f09eead1': u'eakhgari@mozilla.com', '6f8727aab415': u'jdaggett@mozilla.com', 'e53d9b5ad8f8': u'mstange@themasta.com', 'e6ae55cd2f5d': u'dougt@mozilla.com', '32d9b56c5ea6': u'neil@mozilla.com', '157ac288e589': u'mstange@themasta.com', 'eb85e9fe0be7': u'jdrew@mozilla.com', '77d3c3cd755d': u'me@kylehuey.com', '020f7584545b': u'me@kylehuey.com', 'b60a0c153400': u'mmulani@mozilla.com', '08b6a1ab405b': u'jruderman@mozilla.com', '365c4b2067f3': u'masayuki@d-toybox.com', '7acd48c25b5c': u'jorendorff@mozilla.com', '965f9271f2cf': u'mkristoffersen@mozilla.com', '7fb7e88a1739': u'jmaher@mozilla.com', '87e7b2736018': u'tglek@mozilla.com', 'c815c02a8bbc': u'surkov.alexander@gmail.com', 'cc750feffa41': u'mlamouri@mozilla.com', 'd1653821d023': u'eakhgari@mozilla.com', '5fe5c08a5737': u'vladimir@mozilla.com', '34a6c1275fd0': u'cpearce@mozilla.com', '8da8f0209359': u'eakhgari@mozilla.com', 'e743e3347c09': u'mlamouri@mozilla.com', '867c3741e16d': None, '6242c0b1ef60': u'jorendorff@mozilla.com', '924976bc4bf9': u'opettay@mozilla.com', '127c2f71d6b0': u'jmaher@mozilla.com'})

    def testGetBugNumbersForSingleRevisionWithTwoComments(self):
        print 'testGetBugNumbersForSingleRevisionWithTwoComments()'
        revision = '9465683dcfe5'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision, "try")
        bugs = self.poller.GetBugNumbers(buildrequests)
        self.assertEquals(bugs, [9949])

    def testGetBugFromComments(self):
        print 'testGetBugFromComments()'
        message = "try: -b do -p linux,linuxqt,linux64,macosx64,win32,macosx -u reftest,crashtest,mochitests -t none --post-to-bugzilla b664095"
        bugs = self.poller.bz.bugs_from_comments(message)
        self.assertEquals(bugs, [664095])

    def testPushTypeTry(self):
        print 'testPushTypeTry()'
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "try")

    # Push type should be None since there is incorrect try syntax in this commit message
    def testPushTypeNone(self):
        print 'testPushTypeNone()'
        revision = '08b6a1ab405b'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, None)

    # Push type should be Auto since the revision is being tracked in AutolandDB
    def testPushTypeAutoland(self):
        print 'testPushTypeAutoland()'
        revision = 'b8e5f09eead1'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.ProcessPushType(revision, buildrequests)
        self.assertEquals(type, "auto")

    def testGenerateResultReport(self):
        print 'testGenerateResultReport()'
        revision = '157ac288e589'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        report = self.poller.CalculateResults(buildrequests)
        message = self.poller.GenerateResultReportMessage(revision, report)
        self.assertEquals(message,'Try run for 157ac288e589 is complete.\nDetailed breakdown of the results available here:\n    https://tbpl.mozilla.org/?tree=Try&rev=157ac288e589\nResults (out of 11 total builds):\n    success: 10\n    warnings: 1\n')

    def testCreateCacheDir(self):
        print 'testCreateCacheDir()'
        if os.path.isdir(CACHE_DIR):
            revisions = os.listdir(CACHE_DIR)
            for rev in revisions:
                os.remove(os.path.join(CACHE_DIR,rev))
            os.rmdir(CACHE_DIR)
        self.assertRaises(AssertionError, self.poller.WriteToCache, None)
                    
    def testWriteAndLoadCache(self):
        print 'testWriteAndLoadCache()'
        # remove test_cache dir here, but it needs to be emptied first
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

    def testWriteToBuglist(self):
        print 'testWriteToBuglist()'
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        # create a couple of cache file to test that writing to buglist removes the cache file
        # only for the one that gets written to buglist (ie: is complete)
        incomplete = {
            '1234': {},
            '2345': {},
            }
        self.poller.WriteToCache(incomplete)
        # before writing to buglist
        revisions = self.poller.LoadCache()
        self.assertEquals(revisions, {'1234': {}, '2345': {}, '6f8727aab415': {}})
        self.poller.WriteToBuglist('1234', '9949', BUGLIST)
        # after writing to buglist
        revisions = self.poller.LoadCache()
        self.assertEquals(revisions, {'2345': {}, '6f8727aab415': {}})
        # now make sure dry-run doesn't affect things
        # read the buglist for comparing after
        f = open(BUGLIST, 'r')
        before = f.readlines()
        f.close()
        self.poller.dry_run = True
        self.poller.WriteToBuglist('2345', '9949', BUGLIST)
        # cache should not change on a dry-run
        revisions = self.poller.LoadCache()
        self.assertEquals(revisions, {'2345': {}, '6f8727aab415': {}})
        # readlines from BUGLIST after and compare
        f = open(BUGLIST, 'r')
        after = f.readlines()
        f.close()
        self.assertEquals(before, after)

    def testCalculateBuildRequestStatusComplete(self):
        print 'testCalculateBuildRequestStatusComplete()'
        revision = 'e6ae55cd2f5d'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = self.poller.CalculateBuildRequestStatus(buildrequests)
        self.assertEquals(is_complete, True)

    def testCalculateBuildRequestStatusIncomplete(self):
        print 'testCalculateBuildRequestStatusIncomplete()'
        revision = '6f8727aab415'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = self.poller.CalculateBuildRequestStatus(buildrequests)
        self.assertFalse(is_complete)

    def testPostToBug(self):
        #ProcessCompletedRevision(self, revision, message, bug, status_str, type):
        dt = str(datetime.datetime.utcnow())
        comment = "Test-Passed " + dt
        # Test Passing
        print 'testPostToBug_passing()'
        output = self.poller.ProcessCompletedRevision(revision='157ac288e589', message=comment, bug=9949, status_str='', type='try')
        self.assertTrue(output)
        # Test Time Out
        print 'testPostToBug_timed_out()'
        output = self.poller.ProcessCompletedRevision(revision='157ac288e589', message=comment, bug=9949, status_str='timed out', type='try')
        self.assertTrue(output)
        # Test Failing due to incorrect bug number
        print 'testPostToBug_failing()'
        output = self.poller.PollByRevision('157ac288e589', [909090])
        print output
        self.assertFalse(output['posted_to_bug'])
        # Test No One Cares
        print 'testPostToBug_noOneCares()'
        output = self.poller.PollByRevision('cc750feffa41')
        self.assertTrue(output['discard'])
        
    def testDBGetBuildRequests(self):
        print 'testDBGetBuildRequests()'
        buildrequests = self.poller.scheduler_db.GetBuildRequests()
        self.assertNotEquals(buildrequests,{})

    def testGetRevisions(self):
        print 'testGetRevisions()'
        revisions = self.poller.GetRevisions()
        self.assertEquals(revisions.keys()[:5],[u'9465683dcfe5', u'163e8764498e', u'72e79e2d4c48', u'aa4cedbd66ab', u'82f950327fa8'])

    def testPollByRevisionComplete_Autoland(self):
        print 'testPollByRevisionComplete_Autoland()'
        posted = self.poller.bz.has_recent_comment('b8e5f09eead1', 9949)
        output = self.poller.PollByRevision('b8e5f09eead1')
        if posted:
            self.assertEquals(output, {'status': {'running': 0, 'complete': 10, 'cancelled': 0, 'total_builds': 10, 'status_string': 'success', 'misc': 0, 'interrupted': 0, 'pending': 0}, 'posted_to_bug': True, 'message': None, 'is_complete': True, 'discard': False})
        else:
            self.assertEquals(output, {'status': {'running': 0, 'complete': 10, 'cancelled': 0, 'total_builds': 10, 'status_string': 'success', 'misc': 0, 'interrupted': 0, 'pending': 0}, 'posted_to_bug': False, 'message': None, 'is_complete': True, 'discard': False})
        
    def testPollByRevisionComplete_TrySyntax(self):
        print 'testPollByRevisionComplete_TrySyntax()'
        message = u'Try run for 83c09dc13bb8 is complete.\nDetailed breakdown of the results available here:\n    https://tbpl.mozilla.org/?tree=Try&rev=83c09dc13bb8\nResults (out of 10 total builds):\n    success: 9\n    failure: 1\nBuilds (or logs if builds failed) available at:\nhttp://ftp.mozilla.org/pub/mozilla.org/firefox/try-builds/eakhgari@mozilla.com-83c09dc13bb8'
        posted = self.poller.bz.has_comment(message, 9949)
        if not posted:
            # if this test hasn't been run in 4 hours this should return True
            output = self.poller.PollByRevision('83c09dc13bb8')
            self.assertEqual((message, True), (output['message'], output['posted_to_bug']))
        # we have posted to the bug so this should be false
        output = self.poller.PollByRevision('83c09dc13bb8')
        self.assertEqual((message, False), (output['message'], output['posted_to_bug']))
        self.assertFalse(output['posted_to_bug'])
        self.assertTrue(output['is_complete'])

    def testPollByRevisionIncomplete_TrySyntax(self):
        print 'testPollByRevisionIncomplete_TrySyntax()'
        output = self.poller.PollByRevision('6f8727aab415')
        self.assertEqual((None, False), (output['message'], output['posted_to_bug']))

    def testDryRunPollByRevisionComplete_TrySyntax(self):
        print 'testDryRunPollByRevisionComplete_TrySyntax()'
        self.poller.dry_run = True
        output = self.poller.PollByRevision('83c09dc13bb8')
        # make sure nothing goes to the bug
        self.assertFalse(output['posted_to_bug'])
    
    def testPollByTimeRange(self):
        print 'testPollByTimeRange()'
        incomplete = self.poller.PollByTimeRange(None, None)
        self.assertEquals(incomplete['6f8727aab415']['status']['status_string'], '')
        self.assertEquals(incomplete['9465683dcfe5']['status']['status_string'], 'retrying')

    def testPollByTimeRangeDryRun(self):
        print 'testPollByTimeRangeDryRun()'
        self.poller.dry_run = True
        incomplete = self.poller.PollByTimeRange(None, None)
        self.assertEquals(incomplete['6f8727aab415']['status']['status_string'], '')
        self.assertEquals(incomplete['9465683dcfe5']['status']['status_string'], 'retrying')

    def testOrangeFactorRetriesWithoutDupes(self):
        print 'testOrangeFactorRetriesWithoutDupes()'
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
        print 'testOrangeFactorRetriesWithSelfServeFail()'
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
        print 'testOrangeFactorRetriesWithDupes()'
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
        print 'testSelfServeRebuildPass()'
        results = self.poller.SelfServeRebuild(4801896)
        # Using the Mock return value
        self.assertEquals(results, {u'status': u'OK', u'request_id': 19354})

    def testSelfServeRebuildFail(self):
        print 'testSelfServeRebuildFail()'
        clean_poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        # Assert that an HTTPError returns when using the real self-serve
        self.assertRaises(urllib2.HTTPError, clean_poller.SelfServeRebuild, 4801896)

    def testOrangeFactorHandling(self):
        print 'testOrangeFactorHandling()'
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        self.assertEquals(self.poller.OrangeFactorHandling(buildrequests), (True, 'failure'))
    
    def testRevisionTimedOut(self):
        print 'testRevisionTimedOut()'
        incomplete = {
            '6f8727aab415': {},
            }
        now = strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())
        self.poller.WriteToCache(incomplete)
        sleep(5)
        self.poller.WriteToCache(incomplete)
        sleep(5)
        self.poller.WriteToCache(incomplete)
        cache_file = os.path.join(CACHE_DIR, '6f8727aab415')
        f = open(cache_file, 'r')
        entries = f.readlines()
        first_entry = entries[0].split('|')[0]
        # pass in 10 seconds as timeout to be sure we get a timeout
        timed_out = self.poller.revisionTimedOut('6f8727aab415', 10)
        self.assertTrue(timed_out)

if __name__ == '__main__':
    unittest.main(verbosity=2)
