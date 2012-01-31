import unittest
import sys
import json
import mock
from nose.tools import nottest
sys.path.append('..')
from autoland_queue import get_first_autoland_tag, get_patches_from_tag,\
        get_branch_from_tag, get_reviews, get_patchset, bz_search_handler,\
        message_handler, DBHandler, PatchSet, bz_utils, config,\
        handle_patchset, get_try_syntax_from_tag, main,\
        handle_comments, Comment
from utils.db_handler import PatchSet

TEST_DB = 'sqlite:///test/autoland.sqlite'

class TestAutolandQueue(unittest.TestCase):
    def setUp(self):
        config['staging'] = False

    def testGetFirstAutolandTag(self):
        tag = get_first_autoland_tag('[Autoland-try]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Autoland-try][Another Tag]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Another Tag][Autoland-try:12345,23456]')
        self.assertEqual(tag, '[autoland-try:12345,23456]')
        tag = get_first_autoland_tag('[Autoland-try][Autoland-moz-central]')
        self.assertEqual(tag, '[autoland-try]')
        tag = get_first_autoland_tag('[Autoland]')
        self.assertEqual(tag, '[autoland]')
        tag = get_first_autoland_tag('[autoland:-p linux -u none]')
        self.assertEqual(tag, '[autoland:-p linux -u none]')
        tag = get_first_autoland_tag('[autoland:35246:-p linux -u none]')
        self.assertEqual(tag, '[autoland:35246:-p linux -u none]')
        # failures
        tag = get_first_autoland_tag('[autoland:32456:12345:-p linux]')
        self.assertEqual(tag, None)
        tag = get_first_autoland_tag('[autoland-try:1:-p linux:2]')
        self.assertEqual(tag, None)
        tag = get_first_autoland_tag('[Another Tag]')
        self.assertEqual(tag, None)

    def testGetPatchesFromTag(self):
        self.assertEqual('', get_patches_from_tag('autoland-try'))
        self.assertEqual('',get_patches_from_tag ('[autoland-try]'))
        self.assertEqual('12345', get_patches_from_tag('[autoland-try:12345]'))
        self.assertEqual('123,456,678', get_patches_from_tag('[autoland-try:123,456,678]'))
        self.assertEqual('123,456,789', get_patches_from_tag('[autoland:123,456,789,]'))
        self.assertEqual('123,789', get_patches_from_tag('[autoland:123,456wesd,789:-p linux -u none]'))
        self.assertEqual('123789', get_patches_from_tag('[autoland: 123789:-p linux -u none]'))
        self.assertEqual('', get_patches_from_tag('[autoland:-t all]'))
        self.assertEqual('123', get_patches_from_tag('[autoland:-t all: 123]'))

    def testGetBranchFromTag(self):
        self.assertEqual(['try'], get_branch_from_tag('[autoland]'))
        self.assertEqual(['try'], get_branch_from_tag('[autoland-try]'))
        self.assertEqual(['try'], get_branch_from_tag('[autoland:12345]'))
        self.assertEqual(['try'], get_branch_from_tag('[autoland-try:1,2,3]'))
        self.assertEqual(['moz-cen'], get_branch_from_tag('[autoland-moz-cen]'))
        self.assertEqual(['try'], get_branch_from_tag('[autoland:1,2:-p linux -u none]'))
        self.assertEqual(['try'], get_branch_from_tag('[autoland:-p linux -u none]'))
        self.assertEqual(['m-c','m-i','try'], get_branch_from_tag('[autoland-m-c,m-i,try]'))

    def testGetTrySyntaxFromTag(self):
        self.assertEqual('-p linux -u none', get_try_syntax_from_tag('[autoland:-p linux -u none]'))
        self.assertEqual('-p all -t all', get_try_syntax_from_tag('[autoland-try:-p all -t all]'))
        self.assertEqual(None, get_try_syntax_from_tag('[autoland:12345]'))
        self.assertEqual('-p win32 -u mochitest-1,mochitest-2', get_try_syntax_from_tag('[autoland-try:1,2,3:-p win32 -u mochitest-1,mochitest-2]'))

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
                self.assertEqual(patchset, [])

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
        jobs.append({'branch':'try', 'try_run':1, 'try_syntax': None,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'try_syntax': None,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'branch', 'try_run':1, 'try_syntax': None,
            'patches':'', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'try_syntax': None,
            'patches':'2113,2114', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        jobs.append({'branch':'try', 'try_run':1, 'try_syntax': None,
            'patches':'2114', 'bug_id':10411, 'author': u'mjessome@mozilla.com'})
        print "jobs: %s" % (jobs)
        print "db: %s" % (db)
        for job in db:
            jd = job.toDict()
            print "job: %s" % (jd)
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
        orig.append(bz_utils.bz_util.notify_bug)
        bz_utils.bz_util.remove_whiteboard_tag = mock.Mock(return_value=True)
        def nbr(c, i):
            print >>sys.stderr, 'nbr called...'
            return 0
        bz_utils.bz_util.notify_bug = mock.Mock(side_effect=nbr)
        for msg_set in messages:
            for msg in msg_set:
                message_handler(msg)
        bz_utils.bz_util.notify_bug = mock.Mock(return_value=1)
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
        DBHandler.PatchSetDelete = orig.pop()
        DBHandler.PatchSetUpdate = orig.pop()
        DBHandler.PatchSetQuery = orig.pop()
        DBHandler.PatchSetInsert = orig.pop()
    @nottest
    def testLoop(self):
        import autoland_queue as aq

        orig = []
        orig.append(aq.mq_utils.mq_util.get_message)
        orig.append(aq.mq_utils.mq_util.connect)
        orig.append(aq.bz_search_handler)
        orig.append(aq.subprocess.Popen)
        orig.append(DBHandler.PatchSetGetNext)
        orig.append(aq.handle_patchset)
        orig.append(aq.time.sleep)
        orig.append(aq.handle_comments)

        done = Exception("Done")

        aq.time.sleep = mock.Mock(side_effect=done)
        aq.handle_patchset = mock.Mock(return_value=True)
        DBHandler.PatchSetGetNext = mock.Mock(return_value=True)
        aq.subprocess.Popen = mock.Mock(return_value=True)
        aq.bz_search_handler = mock.Mock(return_value=True)
        aq.mq_utils.mq_util.connect = mock.Mock(return_value=True)
        aq.mq_utils.mq_util.get_message = mock.Mock(return_value=True)
        aq.handle_comments = mock.Mock(return_value=True)

        self.assertRaises(Exception, aq.main)

        DBHandler.PatchSetGetNext.return_value = None
        self.assertRaises(Exception, aq.main)
        self.assertEquals(aq.handle_patchset.call_count, 1)

        aq.handle_comments = orig.pop()
        aq.time.sleep = orig.pop()
        aq.handle_patchset = orig.pop()
        DBHandler.PatchSetGetNext = orig.pop()
        aq.subprocess.Popen = orig.pop()
        aq.bz_search_handler = orig.pop()
        aq.mq_utils.mq_util.connect = orig.pop()
        aq.mq_utils.mq_util.get_message = orig.pop()

    def testHandleComments(self):
        nbr = [1, 0, 0]
        db = DBHandler(TEST_DB)
        r = db.scheduler_db_meta.tables['comments']
        q = "delete from comments;"
        connection = db.engine.connect()
        connection.execute(q)
        def nb_ret(c, id):
            n = nbr.pop()
            if n == 1:
                self.assertEquals(db.CommentGetNext()[0].attempts, 2)
            return n
        db.CommentInsert(Comment(comment='test1', bug=12345))
        with mock.patch('utils.bz_utils.bz_util.notify_bug') as nb:
            nb.side_effect = nb_ret
            handle_comments()

if __name__ == '__main__':
    unittest.main()

