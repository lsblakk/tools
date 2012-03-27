import site
site.addsitedir('vendor')
site.addsitedir('vendor/lib/python')

import unittest
import sys
import datetime
sys.path.append('..')
from utils.db_handler import Branch, PatchSet, Comment, DBHandler

TEST_DB = 'sqlite:///test/autoland.sqlite'

class TestAutolandDbHandler(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler(TEST_DB)
        # before every test, clear the tables
        qs = ['delete from patch_sets;', 'delete from comments;',
             'delete from branches']
        connection = self.db.engine.connect()
        for q in qs:
            connection.execute(q)

    def testBranch(self):
        b = Branch(name='mozilla-central', repo_url='https://hg.m.o/mozilla-central',
                threshold=50, status='enabled')
        self.db.BranchDelete(Branch(name='mozilla-central'))
        b.id = self.db.BranchInsert(b)  # Insert
        b_query = self.db.BranchQuery(Branch(id=b.id))  # Query
        print self.db.BranchQuery
        self.assertEqual(b.toDict(), b_query[0].toDict())
        self.db.BranchDelete(b) # Delete
        b_query = self.db.BranchQuery(Branch(id=b.id))
        self.assertEqual(b_query, None)
        b.id = self.db.BranchInsert(b)
        up = Branch(name='mozilla-central', status='disabled')
        self.db.BranchUpdate(up)
        b_query = self.db.BranchQuery(Branch(name='mozilla-central'))[0]
        b.status = 'disabled'
        self.assertEqual(b_query.toDict(), b.toDict())
        self.db.BranchDelete(b_query)
        b_query = self.db.BranchQuery(Branch(id=b_query.id))
        self.assertEqual(b_query, None)

    def testPatchSetInsertDelete(self):
        ps1 = PatchSet(bug_id=12577, patches='534442', branch='mozilla-central',
            try_run=1, author='lsblakk@mozilla.com')
        ps1.id = self.db.PatchSetInsert(ps1)
        ps_query = self.db.PatchSetQuery(ps1)
        if ps_query:
            ps_query = ps_query[0]
        self.assertNotEqual(ps_query.toDict(), None)
        self.db.PatchSetDelete(ps_query)

    def testPatchSetQuery(self):
        self.db.PatchSetDelete(PatchSet(branch=''))
        ps2 = PatchSet(bug_id=3, patches='543352,91223', branch='mozilla-central',
                try_run=0, try_syntax='-p linux -u none', author='lsblakk@mozilla.com')
        print "before psi %s" % (ps2.toDict())
        ps2.id = self.db.PatchSetInsert(ps2)
        print "before psq"
        ps2_query = self.db.PatchSetQuery(ps2)
        print "PS2_QUERY: %s" % ps2_query
        ps_query = self.db.PatchSetQuery(PatchSet(branch='abcdef'))
        self.assertEqual(ps_query, None)
        ps2_from_query = self.db.PatchSetQuery(ps2)[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps2_query_bugid = self.db.PatchSetQuery(PatchSet(branch='mozilla-central'))[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps2_query_bugid = self.db.PatchSetQuery(PatchSet(patches='543352,91223'))[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps2_query_bugid = self.db.PatchSetQuery(PatchSet(author='lsblakk@mozilla.com'))[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps2_query_bugid = self.db.PatchSetQuery(PatchSet(bug_id=3))[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps2_query_bugid = self.db.PatchSetQuery(PatchSet(try_syntax='-p linux -u none'))[0]
        self.assertEqual(ps2_from_query.toDict()['bug_id'], ps2.toDict()['bug_id'])
        self.assertEqual(ps2_from_query.toDict()['patches'], ps2.toDict()['patches'])
        self.assertEqual(ps2_from_query.toDict()['branch'], ps2.toDict()['branch'])
        self.assertEqual(ps2_from_query.toDict()['author'], ps2.toDict()['author'])
        self.assertEqual(ps2_from_query.toDict()['try_syntax'], ps2.toDict()['try_syntax'])
        ps3 = PatchSet(bug_id=4, patches='543352', branch='try',
                try_run=1, author='lsblakk@mozilla.com')
        ps3.id = self.db.PatchSetInsert(ps3)
        ps3_from_query = self.db.PatchSetQuery(ps3)[0]
        self.assertEqual(ps3_from_query.toDict()['bug_id'], ps3.toDict()['bug_id'])
        self.assertEqual(ps3_from_query.toDict()['patches'], ps3.toDict()['patches'])
        self.assertEqual(ps3_from_query.toDict()['branch'], ps3.toDict()['branch'])
        self.assertEqual(ps3_from_query.toDict()['author'], ps3.toDict()['author'])
        print ps3_from_query.toDict()['try_syntax']
        print ps3.toDict()['try_syntax']
        self.assertEqual(ps3_from_query.toDict()['try_syntax'], ps3.toDict()['try_syntax'])
        self.db.PatchSetDelete(ps2)
        self.db.PatchSetDelete(ps3)
        # Add tests for querying on other params than just branch
        
    def testPatchSetGetNext(self):
        ps1 = PatchSet(bug_id=12577, patches='534442', branch='try',
            try_run=1, author='lsblakk@mozilla.com', retries=None, try_syntax=None)
        ps2 = PatchSet(bug_id=4, patches='543352,91223', branch='mozilla-central',
                try_run=0, author='lsblakk@mozilla.com', retries=None, try_syntax=None)
        ps3 = PatchSet(bug_id=12577, patches='534442', branch='try',
            try_run=1, author='lsblakk@mozilla.com', retries=None, try_syntax=None)
        b1 = Branch(name='mozilla-central', repo_url='https://hg.m.o/mozilla-central',
                threshold=50, status='enabled')
        b2 = Branch(name='try', repo_url='https://hg.m.o/mozilla-central',
                threshold=50, status='enabled')
        # Insert ps1 then ps2. Ps2 should come out first since it is not a try
        # run, and it is to be pushed to branch.
        ps1.id = self.db.PatchSetInsert(ps1)
        ps2.id = self.db.PatchSetInsert(ps2)
        ps3.id = self.db.PatchSetInsert(ps3)
        self.db.BranchDelete(Branch(name='mozilla-central'))
        self.db.BranchDelete(Branch(name='try'))
        b1.id = self.db.BranchInsert(b1)
        b2.id = self.db.BranchInsert(b2)
        next = self.db.PatchSetGetNext()
        print "Pull the m-c patchset: %s" % next
        self.assertEqual(next.toDict(), ps2.toDict())
        self.db.BranchUpdate(Branch(name='mozilla-central', status='disabled'))
        next.push_time = datetime.datetime.utcnow()
        self.db.PatchSetUpdate(next)

        next = self.db.PatchSetGetNext()
        print "Pull the try patchset ps1: %s" % next
        self.assertEqual(next.toDict(), ps1.toDict())
        next.push_time = datetime.datetime.utcnow()
        self.db.PatchSetUpdate(next)
        self.db.BranchUpdate(Branch(name='try', status='disabled', threshold=0))

        next = self.db.PatchSetGetNext()
        print "Pull nothing, try is disabled: %s" % next
        self.assertEqual(next, None)
        self.db.BranchUpdate(Branch(name='try', status='enabled', threshold=0))
        next = self.db.PatchSetGetNext()
        print "Pull nothing, try threshold is full: %s" % next
        self.assertEqual(next, None)
        self.db.BranchUpdate(Branch(name='try', threshold=50))
        next = self.db.PatchSetGetNext()
        print "Pull next gets try ps3: %s" % next
        self.assertEqual(next.toDict(), ps3.toDict())
        # Clean up
        self.db.BranchDelete(Branch(name='mozilla-central'))
        self.db.BranchDelete(Branch(name='try'))
        self.db.PatchSetDelete(ps1)
        self.db.PatchSetDelete(ps2)
        self.db.PatchSetDelete(ps3)

    def testPatchSetGetRevs(self):
        ps1 = PatchSet(bug_id=12577, patches='534442', branch='try',
                revision='ps1',
            try_run=1, author='lsblakk@mozilla.com', retries=None, try_syntax=None)
        ps2 = PatchSet(bug_id=4, patches='543352,91223', branch='mozilla-central',
                revision='ps2',
                try_run=0, author='lsblakk@mozilla.com', retries=None, try_syntax=None)
        ps3 = PatchSet(bug_id=12577, patches='534442', branch='try',
                revision='ps3',
            try_run=1, author='lsblakk@mozilla.com', retries=None, try_syntax=None)

        ps1.id = self.db.PatchSetInsert(ps1)
        ps2.id = self.db.PatchSetInsert(ps2)
        ps3.id = self.db.PatchSetInsert(ps3)
        revs = self.db.PatchSetGetRevs()
        print revs
        for r in ('ps1', 'ps2', 'ps3'):
            self.assertTrue(r in revs)
        self.db.PatchSetDelete(ps1)
        self.db.PatchSetDelete(ps2)
        self.db.PatchSetDelete(ps3)
        revs = self.db.PatchSetGetRevs()
        self.assertEqual([], revs)

    def testBranchRunningJobsQuery(self):
        ps1 = PatchSet(bug_id=12577, patches='534442', branch='try',
            try_run=1, try_syntax=None, push_time=datetime.datetime.utcnow(), author='lsblakk@mozilla.com')
        ps2 = PatchSet(bug_id=4, patches='543352,91223', branch='try',
                try_run=0, author='lsblakk@mozilla.com')
        b = Branch(name='try', repo_url='https://hg.m.o/try',
                threshold=50, status='enabled')
        ps1.id = self.db.PatchSetInsert(ps1)
        ps2.id = self.db.PatchSetInsert(ps2)
        self.db.BranchDelete(Branch(name='try'))
        print "How many try runs are running? (answer 1)"
        b.id = self.db.BranchInsert(b)
        count = self.db.BranchRunningJobsQuery(branch=b)
        print "count: %d" % count
        self.assertEqual(count, 1)
        print "How many try runs are running? (answer 2)"
        ps3 = PatchSet(bug_id=12577, patches='534442', branch='try',
            try_run=1, push_time=datetime.datetime.utcnow(), author='lsblakk@mozilla.com')
        ps3.id = self.db.PatchSetInsert(ps3)
        count = self.db.BranchRunningJobsQuery(branch=b)
        print "count: %d" % count
        self.assertEqual(count, 2)
        # Clean up
        self.db.BranchDelete(Branch(name='mozilla-central'))
        self.db.BranchDelete(Branch(name='try'))
        self.db.PatchSetDelete(ps1)
        self.db.PatchSetDelete(ps2)
        self.db.PatchSetDelete(ps3)

    def testCommentInsert(self):
        c1 = Comment(comment='This is comment 1', bug=12345)
        c1.id = self.db.CommentInsert(c1)
        c1.attempts = 3
        self.db.CommentUpdate(c1)
        c_got = self.db.CommentGetNext()
        self.assertEquals(c_got[0].comment, 'This is comment 1')
        self.db.CommentDelete(c1)


if __name__ == '__main__':
    unittest.main()
