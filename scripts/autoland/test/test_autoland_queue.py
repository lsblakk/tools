import unittest
import sys
import json
import mock
sys.path.append('..')
from autoland_queue import get_first_autoland_tag, valid_autoland_tag,\
        get_branch_from_tag, get_reviews, get_patchset, bz_search_handler,\
        message_handler, DBHandler, PatchSet, bz_utils
from utils.db_handler import PatchSet

class TestAutolandQueue(unittest.TestCase):
    def setUp(self):
        pass

    def testGetFirstAutolandTag(self):
        tag = get_first_autoland_tag('[Autoland-try]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Autoland-try][Another Tag]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Another Tag][Autoland-try:12345,23456]')
        self.assertEqual(tag, '[autoland-try:12345,23456]')
        tag = get_first_autoland_tag('[Another Tag]')
        self.assertEqual(tag, None)
        tag = get_first_autoland_tag('[Autoland-try][Autoland-moz-central]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Autoland]')
        self.assertEqual(tag, '[autoland]')

    def testValidAutolandTag(self):
        self.assertFalse(valid_autoland_tag('autoland-try'))
        self.assertFalse(valid_autoland_tag('[not-autoland-try]'))
        self.assertFalse(valid_autoland_tag('[autoland-nogood'))

        self.assertTrue(valid_autoland_tag('[autoland-try]'))
        self.assertTrue(valid_autoland_tag('[autoland-try:12345]'))
        self.assertTrue(valid_autoland_tag('[autoland-try:123,456,678]'))
        self.assertTrue(valid_autoland_tag('[autoland]'))
        self.assertTrue(valid_autoland_tag('[autoland:123,456,789]'))

    def testGetBranchFromTag(self):
        self.assertEqual('try', get_branch_from_tag('[autoland]'))
        self.assertEqual('try', get_branch_from_tag('[autoland-try]'))
        self.assertEqual('try', get_branch_from_tag('[autoland:12345]'))
        self.assertEqual('try', get_branch_from_tag('[autoland-try:1,2,3]'))
        self.assertEqual('moz-cen', get_branch_from_tag('[autoland-moz-cen]'))

    def testGetReviews(self):
        bug = open('test/bug1.json', 'r').read()
        bug = json.loads(bug)
        expected = []
        expected.append([])
        expected.append([{'type':'review',
                      'reviewer':u'mjessome',
                      'result':u'+'},
                     {'type':'review',
                      'reviewer':u'mjessome',
                      'result':u'-'}])
        results = []
        for i in range(2):
            results.append(get_reviews(bug['attachments'][i]))
            self.assertEqual(results[i], expected[i])

    def testGetPatchSet(self):
        with mock.patch('utils.bz_utils.bz_util.request') as bz_rq:
            with mock.patch('utils.bz_utils.bz_util.notify_bug') as bz_pc:
                def notify_bug(comment, bugid):
                    print comment, bugid
                    return False
                def sf(path):
                    return json.loads(open(return_values.pop(), 'r').read())
                bz_pc.side_effect = notify_bug
                bz_rq.side_effect = sf
                return_values = []

                # Full patch set
                # Try run = True
                for i in range(6):
                    return_values.append('test/mjessome.json')
                    return_values.append('test/lsblakk.json')
                return_values.append('test/bug2.json')
                patchset = get_patchset('bug1', try_run=True)
                self.assertEquals(len(patchset), 6)
                patches = [531180, 531181, 532000,
                           534041, 534042, 534107]
                self.assertTrue(len(patches) == len(patchset))
                for p in patchset:
                    self.assertTrue(p['id'] in patches)
                    patches.remove(p['id'])
                self.assertTrue(len(patches) == 0)

                # 3 patches of 6
                # Try run = True
                for i in range(3):
                    return_values.append('test/mjessome.json')
                    return_values.append('test/lsblakk.json')
                return_values.append('test/bug2.json')
                patches = [531180, 531181, 534107]
                patchset = get_patchset('bug2', try_run=True, patches=patches)
                self.assertEqual(len(patchset), len(patches))
                for p in patchset:
                    self.assertTrue(p['id'] in patches)
                    patches.remove(p['id'])
                self.assertTrue(len(patches) == 0)

                # 3 patches that aren't real
                # Try run = True
                return_values = []
                return_values.append('test/bug2.json')
                patchset = get_patchset('bug3', try_run=True, patches=[1,2,3])
                self.assertEqual(patchset, None)

                # 2 real patches, 2 fake patch ids
                # Try run = True
                return_values = []
                for i in range(2):
                    return_values.append('test/mjessome.json')
                    return_values.append('test/lsblakk.json')
                return_values.append('test/bug2.json')
                patches = [531180, 4, 534042, 9]
                patchset = get_patchset('bug4', try_run=True, patches=patches)
                self.assertEqual(patchset, None)

                # Full patch set
                # Try run = False
                # One patch has no review, another has both + and -
                return_values = []
                return_values.append('test/mjessome.json')
                return_values.append('test/mjessome.json')
                return_values.append('test/bug1.json')
                patchset = get_patchset('bug5', try_run=False)
                self.assertEqual(patchset, None)

                # Full patch set
                # Try run = False
                # All non-obsolete patches have review
                return_values = []
                for i in range(6):
                    return_values.append('test/mjessome.json')
                    return_values.append('test/lsblakk.json')
                return_values.append('test/bug2.json')
                patchset = get_patchset('bug6', try_run=False)
                patches = [531180, 531181, 532000,
                           534041, 534042, 534107]
                self.assertTrue(len(patches) == len(patchset))
                for p in patchset:
                    self.assertTrue(p['id'] in patches)
                    patches.remove(p['id'])
                self.assertTrue(len(patches) == 0)

    def testBzSearchHandler(self):
        bugs = []
        db = []
        with mock.patch('utils.bz_utils.bz_util.get_matching_bugs') as bz_gmb:
            def gmb(tag, regex):
                print bugs
                return bugs
            bz_gmb.side_effect = gmb
            # populate some test cases
            for id in [10411]:
                for tag in ['[autoland]','[autoland-try]','[autoland-branch]',
                        '[autoland:2113,2114]','[autoland-try:2114]',
                        '[bad-autoland-tag]','[autoland\in:valid]']:
                    bugs.append((id, tag))
            with mock.patch('utils.bz_utils.bz_util.notify_bug') as bz_pc:
                def pc(comment, bug):
                    return True
                bz_pc.side_effect = pc
                with mock.patch('utils.bz_utils.bz_util.remove_whiteboard_tag') as bz_rwt:
                    def rwt(tag, bug):
                        return True
                    bz_rwt.side_effect = rwt
                    with mock.patch('utils.bz_utils.bz_util.replace_whiteboard_tag') as bz_repwt: 
                        def repwt(tag, rep, bug):
                            return True
                        bz_repwt.side_effect = repwt
                        with mock.patch('utils.db_handler.DBHandler.PatchSetInsert') as db_psi:
                            def psi(ps):
                                print "PATCH SET: %s" % ps
                                db.append(ps)
                            db_psi.side_effect = psi
                            old_bq = DBHandler.BranchQuery
                            DBHandler.BranchQuery = mock.Mock(return_value=True)
                            bz_search_handler()
                            DBHandler.BranchQuery = old_bq
        jobs = []
        jobs.append({'branch':'try', 'try_run':1, 'to_branch':0,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'to_branch':0,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'branch', 'try_run':1, 'to_branch':1,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'to_branch':0,
            'patches':'2113, 2114', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'to_branch':0,
            'patches':'2114', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        print jobs
        print db
        for job in db:
            jd = job.toDict()
            self.assertTrue(jd in jobs)
            jobs.remove(jd)
        self.assertEqual(jobs, [])

    def testMessageHandler(self):
        from message_gen import messages
        orig = []
        orig.append(DBHandler.PatchSetInsert)
        orig.append(DBHandler.PatchSetQuery)
        orig.append(DBHandler.PatchSetUpdate)
        orig.append(DBHandler.PatchSetDelete)
        DBHandler.PatchSetInsert = mock.Mock(return_value=True)
        DBHandler.PatchSetQuery = mock.Mock(return_value=[PatchSet(id=1),])
        DBHandler.PatchSetUpdate = mock.Mock(return_value=True)
        DBHandler.PatchSetDelete = mock.Mock(return_value=True)
        bz_utils.bz_util.remove_whiteboard_tag = mock.Mock(return_value=True)
        for msg_set in messages:
            for msg in msg_set:
                message_handler(msg)
        args = []
        args.extend(DBHandler.PatchSetInsert.call_args_list)
        args.extend(DBHandler.PatchSetQuery.call_args_list)
        args.extend(DBHandler.PatchSetDelete.call_args_list)
        args.extend(DBHandler.PatchSetUpdate.call_args_list)
        for arg in map(lambda x: x[0][0], args):
            self.assertEqual(type(arg), PatchSet)
        DBHandler.PatchSetInsert = orig[0]
        DBHandler.PatchSetQuery = orig[1]
        DBHandler.PatchSetUpdate = orig[2]
        DBHandler.PatchSetDelete = orig[3]

if __name__ == '__main__':
    unittest.main()
