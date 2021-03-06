import site
site.addsitedir('vendor')
site.addsitedir('vendor/lib/python')

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
BUGLIST = "postedbugs.log"
CACHE_DIR = "test_cache"
# These are all the revisions in the scheduler.sqlite that has been generated
# for this test suite.  Some of them have had their content altered from the
# real schedulerdb to provide test data.
REVISIONS = ['9465683dcfe5', '83c09dc13bb8', 'b8e5f09eead1', '6f8727aab415',
             'e53d9b5ad8f8', '7acd48c25b5c', '157ac288e589', 'eb85e9fe0be7',
             '77d3c3cd755d', '020f7584545b', 'b60a0c153400', '08b6a1ab405b',
             '365c4b2067f3', '32d9b56c5ea6', '965f9271f2cf', '7fb7e88a1739',
             '6242c0b1ef60', '87e7b2736018', 'c815c02a8bbc', 'cc750feffa41',
             'd1653821d023', '5fe5c08a5737', '34a6c1275fd0', '8da8f0209359',
             'e743e3347c09', '867c3741e16d', 'e6ae55cd2f5d', '924976bc4bf9',
             '127c2f71d6b0']

class SchedulerDBPollerTests(unittest.TestCase):

    def setUp(self):
        print 'setUp()'
        # Clean up the postedbugs.log from previous runs
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)

        self.poller = SchedulerDBPoller(branch="try", cache_dir=CACHE_DIR,
                            config=CONFIG_FILE, messages=False)
        self.poller.verbose = True
        self.poller.self_serve_rebuild = mock.Mock(
                return_value={u'status': u'OK', u'request_id': 19354})
        self.maxDiff = None

    def testGetBugNumbers(self):
        print 'testGetBugNumbers()'
        bugs = {}
        for revision in REVISIONS:
            buildrequests = \
                self.poller.scheduler_db.GetBuildRequests(revision, "try")
            bugs[revision] = self.poller.get_bug_numbers(buildrequests)
        self.assertEquals(sorted(bugs), sorted({
            '9465683dcfe5': [9952], '83c09dc13bb8': [9952],
            'b8e5f09eead1': [9952], '6f8727aab415': [95846],
            'e53d9b5ad8f8': [], 'e6ae55cd2f5d': [],
            '32d9b56c5ea6': [], '157ac288e589': [9952],
            'eb85e9fe0be7': [], '77d3c3cd755d': [],
            '020f7584545b': [], 'b60a0c153400': [],
            '08b6a1ab405b': [], '365c4b2067f3': [],
            '7acd48c25b5c': [12345, 234456, 244677],
            '965f9271f2cf': [], '7fb7e88a1739': [],
            '87e7b2736018': [], 'c815c02a8bbc': [],
            'cc750feffa41': [], 'd1653821d023': [],
            '5fe5c08a5737': [], '34a6c1275fd0': [],
            '8da8f0209359': [], 'e743e3347c09': [],
            '867c3741e16d': [], '6242c0b1ef60': [],
            '924976bc4bf9': [], '127c2f71d6b0': []
        }))

    def testGetSingleAuthor(self):
        print 'testGetSingleAuthor()'
        authors = {}
        for revision in REVISIONS:
            buildrequests = \
                self.poller.scheduler_db.GetBuildRequests(revision, "try")
            authors[revision] = self.poller.get_single_author(buildrequests)
        self.assertEquals(authors, {
            '9465683dcfe5': u'bherland@mozilla.com',
            '83c09dc13bb8': u'eakhgari@mozilla.com',
            'b8e5f09eead1': u'eakhgari@mozilla.com',
            '6f8727aab415': u'jdaggett@mozilla.com',
            'e53d9b5ad8f8': u'mstange@themasta.com',
            'e6ae55cd2f5d': u'dougt@mozilla.com',
            '32d9b56c5ea6': u'neil@mozilla.com',
            '157ac288e589': u'mstange@themasta.com',
            'eb85e9fe0be7': u'jdrew@mozilla.com',
            '77d3c3cd755d': u'me@kylehuey.com',
            '020f7584545b': u'me@kylehuey.com',
            'b60a0c153400': u'mmulani@mozilla.com',
            '08b6a1ab405b': u'jruderman@mozilla.com',
            '365c4b2067f3': u'masayuki@d-toybox.com',
            '7acd48c25b5c': u'jorendorff@mozilla.com',
            '965f9271f2cf': u'mkristoffersen@mozilla.com',
            '7fb7e88a1739': u'jmaher@mozilla.com',
            '87e7b2736018': u'tglek@mozilla.com',
            'c815c02a8bbc': u'surkov.alexander@gmail.com',
            'cc750feffa41': u'mlamouri@mozilla.com',
            'd1653821d023': u'eakhgari@mozilla.com',
            '5fe5c08a5737': u'vladimir@mozilla.com',
            '34a6c1275fd0': u'cpearce@mozilla.com',
            '8da8f0209359': u'eakhgari@mozilla.com',
            'e743e3347c09': u'mlamouri@mozilla.com',
            '867c3741e16d': None,
            '6242c0b1ef60': u'jorendorff@mozilla.com',
            '924976bc4bf9': u'opettay@mozilla.com',
            '127c2f71d6b0': u'jmaher@mozilla.com'
        })

    def testGetBugNumbersForSingleRevisionWithTwoComments(self):
        print 'testGetBugNumbersForSingleRevisionWithTwoComments()'
        revision = '9465683dcfe5'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision,
                                                                    "try")
        bugs = self.poller.get_bug_numbers(buildrequests)
        self.assertEquals(bugs, [9952])

    def testGetBugFromComments(self):
        print 'testGetBugFromComments()'
        message = "try: -b do -p linux,linuxqt,linux64,macosx64,win32," \
                  "macosx -u reftest,crashtest,mochitests " \
                  "-t none --post-to-bugzilla b664095"
        bugs = self.poller.bz.bugs_from_comments(message)
        self.assertEquals(bugs, [664095])

    def testPushTypeTry(self):
        print 'testPushTypeTry()'
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.process_push_type(revision, buildrequests)
        self.assertEquals(type, "TRY")

    # Push type should be None since there is
    # incorrect try syntax in this commit message
    def testPushTypeNone(self):
        print 'testPushTypeNone()'
        revision = '08b6a1ab405b'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        type = self.poller.process_push_type(revision, buildrequests)
        self.assertEquals(type, None)

    def testGenerateResultReport(self):
        print 'testGenerateResultReport()'
        revision = '157ac288e589'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        report = self.poller.calculate_results(buildrequests)
        message = self.poller.generate_result_report_message(revision, report)
        self.assertEquals(message,'Try run for 157ac288e589 is complete.\n'
                'Detailed breakdown of the results available here:\n'
                '\thttps://tbpl.mozilla.org/?tree=Try&rev=157ac288e589\n'
                'Results (out of 11 total builds):\n'
                '    success: 10\n    warnings: 1\n')

    def testCreateCacheDir(self):
        print 'testCreateCacheDir()'
        if os.path.isdir(CACHE_DIR):
            revisions = os.listdir(CACHE_DIR)
            for rev in revisions:
                os.remove(os.path.join(CACHE_DIR, rev))
            os.rmdir(CACHE_DIR)
        self.assertRaises(AssertionError, self.poller.write_to_cache, None)

    def testWriteAndload_cache(self):
        print 'testWriteAndload_cache()'
        # remove test_cache dir here, but it needs to be emptied first
        if os.path.isdir(CACHE_DIR):
            revisions = os.listdir(CACHE_DIR)
            for rev in revisions:
                if rev != '6f8727aab415':
                    os.remove(os.path.join(CACHE_DIR, rev))
        incomplete = {}
        incomplete['6f8727aab415'] = \
                self.poller.poll_by_revision('6f8727aab415')
        incomplete['aa4cedbd66ab.done'] = {}
        self.poller.write_to_cache(incomplete)
        revisions, complete = self.poller.load_cache()
        self.assertEquals(revisions, {'6f8727aab415': {}})
        self.assertEquals(complete, ['aa4cedbd66ab'])

    def testWriteToBugList(self):
        print 'testWriteToBugList()'
        if os.path.exists(BUGLIST):
            os.remove(BUGLIST)
        # create a couple of cache file to test that
        # writing to buglist removes the cache file only for
        # the one that gets written to buglist (ie: is complete)
        incomplete = {
            '1234': {},
            '2345': {},
            '3456.done': {},
            }
        self.poller.write_to_cache(incomplete)
        # before writing to buglist
        revisions, complete = self.poller.load_cache()
        self.assertEquals(revisions, {'1234': {}, '2345': {},
                                      '6f8727aab415': {}})
        self.assertEquals(sorted(complete), sorted(['3456', 'aa4cedbd66ab']))
        self.poller.write_to_buglist('1234', '9952', BUGLIST)
        # after writing to buglist
        revisions, complete = self.poller.load_cache()
        self.assertEquals(revisions, {'2345': {}, '6f8727aab415': {}})
        self.assertEquals(sorted(complete), sorted(['3456', '1234',
                                                    'aa4cedbd66ab']))
        # now make sure dry-run doesn't affect things
        # read the buglist for comparing after
        f = open(BUGLIST, 'r')
        before = f.readlines()
        f.close()
        self.poller.dry_run = True
        self.poller.write_to_buglist('2345', '9952', BUGLIST)
        # cache should not change on a dry-run
        revisions, complete = self.poller.load_cache()
        self.assertEquals(revisions, {'2345': {}, '6f8727aab415': {}})
        self.assertEquals(sorted(complete), sorted(['3456', '1234',
                                                    'aa4cedbd66ab']))
        # readlines from BUGLIST after and compare
        f = open(BUGLIST, 'r')
        after = f.readlines()
        f.close()
        self.assertEquals(before, after)

    def testCalculateBuildRequestStatusComplete(self):
        print 'testCalculateBuildRequestStatusComplete()'
        revision = 'e6ae55cd2f5d'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = \
                self.poller.calculate_build_request_status(buildrequests)
        self.assertEquals(is_complete, True)

    def testCalculateBuildRequestStatusIncomplete(self):
        print 'testCalculateBuildRequestStatusIncomplete()'
        revision = '6f8727aab415'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        (results, is_complete) = \
                self.poller.calculate_build_request_status(buildrequests)
        self.assertFalse(is_complete)

    def testPostToBug(self):
        #process_completed_revision(self, revision, message,
        #                           bug, status_str, type):
        dt = str(datetime.datetime.utcnow())
        comment = "Test-Passed " + dt
        # Test Passing
        print 'testPostToBug_passing()'
        output = self.poller.process_completed_revision(
                revision='157ac288e589', message=comment,
                bug=9952, status_str='', push_type='try')
        self.assertTrue(output)
        # Test Time Out
        print 'testPostToBug_timed_out()'
        output = self.poller.process_completed_revision(
                revision='157ac288e589', message=comment, bug=9952,
                status_str='TIMED_OUT', push_type='try')
        self.assertTrue(output)
        # Test Failing due to incorrect bug number
        print 'testPostToBug_failing()'
        output = self.poller.poll_by_revision('157ac288e589', [909090])
        print output
        self.assertFalse(output['posted_to_bug'])
        # Test No One Cares
        print 'testPostToBug_noOneCares()'
        output = self.poller.poll_by_revision('cc750feffa41')
        self.assertTrue(output['discard'])

    def testDBGetBuildRequests(self):
        print 'testDBGetBuildRequests()'
        buildrequests = self.poller.scheduler_db.GetBuildRequests()
        self.assertNotEquals(buildrequests, {})

    def testGetRevisions(self):
        print 'testGetRevisions()'
        revisions = self.poller.get_revisions()
        self.assertEquals(revisions.keys()[:5], [u'9465683dcfe5',
            u'163e8764498e', u'72e79e2d4c48',
            u'aa4cedbd66ab', u'82f950327fa8'])

    def testPollByRevisionComplete_TrySyntax(self):
        print 'testPollByRevisionComplete_TrySyntax()'
        message = u'Try run for 83c09dc13bb8 is complete.\n' \
                  u'Detailed breakdown of the results available here:\n' \
                  u'\thttps://tbpl.mozilla.org/?tree=Try&rev=83c09dc13bb8\n' \
                  u'Results (out of 10 total builds):\n    ' \
                  u'success: 9\n    failure: 1\n' \
                  u'Builds (or logs if builds failed) ' \
                  u'available at:\nhttp://ftp.mozilla.org/pub/mozilla.org' \
                  u'/firefox/try-builds/eakhgari@mozilla.com-83c09dc13bb8'
        posted = self.poller.bz.has_comment(message, 9952)
        if not posted:
            output = self.poller.poll_by_revision('83c09dc13bb8')
            self.assertEqual((message, True), (output['message'],
                output['posted_to_bug']))
        output = self.poller.poll_by_revision('83c09dc13bb8')
        self.assertEqual((message, False), (output['message'],
            output['posted_to_bug']))
        self.assertFalse(output['posted_to_bug'])
        self.assertTrue(output['is_complete'])

    def testPollByRevisionIncomplete_TrySyntax(self):
        print 'testPollByRevisionIncomplete_TrySyntax()'
        output = self.poller.poll_by_revision('6f8727aab415')
        self.assertEqual((None, False), (output['message'],
                output['posted_to_bug']))

    def testDryRunPollByRevisionComplete_TrySyntax(self):
        print 'testDryRunPollByRevisionComplete_TrySyntax()'
        self.poller.dry_run = True
        output = self.poller.poll_by_revision('83c09dc13bb8')
        # make sure nothing goes to the bug
        self.assertFalse(output['posted_to_bug'])

    def testPollByTimeRange(self):
        print 'add a rev to cache dir'
        incomplete = {}
        incomplete['aa4cedbd66ab.done'] = {}
        self.poller.write_to_cache(incomplete)

        print 'TestPollByTimeRange()'
        incomplete = self.poller.poll_by_time_range(None, None)
        self.assertEquals(
                incomplete['6f8727aab415']['status']['status_string'],
                '')
        self.assertEquals(
                incomplete['9465683dcfe5']['status']['status_string'],
                'retrying')

    def testPollByTimeRangeDryRun(self):
        print 'testPollByTimeRangeDryRun'
        self.poller.dry_run = True
        incomplete = self.poller.poll_by_time_range(None, None)
        self.assertEquals(
                incomplete['6f8727aab415']['status']['status_string'],
                '')
        self.assertEquals(
                incomplete['9465683dcfe5']['status']['status_string'],
                'retrying')

    def testself_serve_rebuildPass(self):
        print 'testself_serve_rebuildPass()'
        results = self.poller.self_serve_rebuild(4801896)
        # Using the Mock return value
        self.assertEquals(results, {u'status': u'OK', u'request_id': 19354})

    def testself_serve_rebuildFail(self):
        print 'testself_serve_rebuildFail()'
        clean_poller = SchedulerDBPoller("try", CACHE_DIR, CONFIG_FILE)
        # Assert that an HTTPError returns when using the real self-serve
        self.assertRaises(urllib2.HTTPError,
                clean_poller.self_serve_rebuild, 4801896)

    def testOrangeFactorHandling(self):
        print 'testOrangeFactorHandling()'
        revision = '83c09dc13bb8'
        buildrequests = self.poller.scheduler_db.GetBuildRequests(revision)
        self.assertEquals(self.poller.orange_factor_handling(buildrequests),
                (True, 'FAILURE'))

    def testRevisionTimedOut(self):
        print 'testRevisionTimedOut()'
        incomplete = {
            '6f8727aab415': {},
            }
        now = strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())
        self.poller.write_to_cache(incomplete)
        sleep(5)
        self.poller.write_to_cache(incomplete)
        sleep(5)
        self.poller.write_to_cache(incomplete)
        cache_file = os.path.join(CACHE_DIR, '6f8727aab415')
        f = open(cache_file, 'r')
        entries = f.readlines()
        first_entry = entries[0].split('|')[0]
        # pass in 10 seconds as timeout to be sure we get a timeout
        timed_out = self.poller.revision_timed_out('6f8727aab415', 10)
        self.assertTrue(timed_out)

if __name__ == '__main__':
    unittest.main(verbosity=2)
