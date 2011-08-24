import unittest
import sys
import datetime
sys.path.append('..')
from utils.db_handler import Branch, PatchSet, DBHandler

TEST_DB = 'sqlite:///test/autoland.sqlite'

class TestAutolandDbHandler(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler(TEST_DB)

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
            try_run=1, to_branch=0)
        ps1.id = self.db.PatchSetInsert(ps1)
        ps_query = self.db.PatchSetQuery(PatchSet(id=ps1.id))
        if ps_query:
            ps_query = ps_query[0]
        self.assertNotEqual(ps_query.toDict(), None)
        self.db.PatchSetDelete(ps_query)

    def testPatchSetQuery(self):
        ps2 = PatchSet(bug_id=3, patches='543352,91223', branch='mozilla-central',
                try_run=0, to_branch=1)
        ps_query = self.db.PatchSetQuery(PatchSet(branch='abcdef'))
        self.assertEqual(ps_query, None)
        ps2.id = self.db.PatchSetInsert(ps2)
        ps_query = self.db.PatchSetQuery(ps2)[0]
        self.assertNotEqual(ps_query.toDict(), None)
        self.db.PatchSetDelete(ps2)

    def testPatchSetGetNext(self):
        ps1 = PatchSet(bug_id=12577, patches='534442', branch='mozilla-central',
            try_run=1, to_branch=0)
        ps2 = PatchSet(bug_id=4, patches='543352,91223', branch='mozilla-central',
                try_run=0, to_branch=1)
        b = Branch(name='mozilla-central', repo_url='https://hg.m.o/mozilla-central',
                threshold=50, status='enabled')
        # Insert ps1 then ps2. Ps2 should come out first since it is not a try
        # run, and it is to be pushed to branch.
        ps1.id = self.db.PatchSetInsert(ps1)
        ps2.id = self.db.PatchSetInsert(ps2)
        self.db.BranchDelete(Branch(name='mozilla-central'))
        b.id = self.db.BranchInsert(b)
        next = self.db.PatchSetGetNext()
        self.assertEqual(next.toDict(), ps2.toDict())
        self.db.BranchUpdate(Branch(name='mozilla-central', status='disabled'))
        next.push_time = datetime.datetime.utcnow()
        self.db.PatchSetUpdate(next)

        next = self.db.PatchSetGetNext()
        self.assertEqual(next, None)
        self.db.BranchUpdate(Branch(name='mozilla-central', status='enabled', threshold=0))

        next = self.db.PatchSetGetNext()
        self.assertEqual(next, None)
        self.db.BranchUpdate(Branch(name='mozilla-central', threshold=2))
        next = self.db.PatchSetGetNext()
        self.assertEqual(next.toDict(), ps1.toDict())
        # Clean up
        self.db.BranchDelete(Branch(name='mozilla-central'))
        self.db.PatchSetDelete(ps1)
        ps2.completion_time = datetime.datetime.utcnow()
        self.db.PatchSetUpdate(ps2)
        self.db.PatchSetDelete(ps2)

if __name__ == '__main__':
    unittest.main()
