import unittest
import os, shutil
import sys
import tempfile
import subprocess
import re
import string
from time import sleep
import mock
# Autoland imports
sys.path.append('..')
import hgpusher
from hgpusher import clone_branch, has_sufficient_permissions, \
        message_handler, clear_branch, import_patch, Patchset, Patch, \
        RepoCleanup, RetryException
from utils import mq_utils

top_dir = os.getcwd()
test_dir = os.path.join(top_dir, 'test_hgpusher/')
if os.access(test_dir, os.F_OK):
    shutil.rmtree(test_dir)

def gen_repos():
    proc = subprocess.Popen(['sh', '../test/gen_hgrepo.sh'])
    proc.wait()
    os.chdir('work_dir')

def gen_headers():
    proc = subprocess.Popen(['sh', '../test/gen_headers.sh'])
    proc.wait()

class TestHgPusher(unittest.TestCase):
    def setUp(self):
        if os.access(test_dir, os.F_OK):
            shutil.rmtree(test_dir)
        os.mkdir(test_dir)
        os.chdir(test_dir)
        os.mkdir('work_dir')
        hgpusher.config['hg_base_url'] = test_dir

        hgpusher.mq = mq_utils.mq_util()
        hgpusher.config['work_dir'] = os.path.join(test_dir, 'work_dir')

    def tearDown(self):
        os.chdir(top_dir)
        #shutil.rmtree(test_dir)

    def testValidDictionaryStructure(self):
        lower = {}
        upper = {}
        for c in string.ascii_lowercase:
            lower[c] = c
        for c in string.ascii_uppercase:
            upper[c] = c
        self.assertTrue(
                hgpusher.valid_dictionary_structure(lower, lower.keys()))
        self.assertFalse(
                hgpusher.valid_dictionary_structure(lower, upper.keys()))

    def hasSufficientPermissions(self):
        self.assertTrue(has_sufficient_permissions(
            [{'author':{'email': 'mjessome@mozilla.com'}}], 'try'))
        self.assertTrue(has_sufficient_permissions(
            [{'author':{'email': 'marc.jessome@gmail.com'}}], 'try'))

    def testValidJobMessage(self):
        msg = { 'bug_id' : '12345',
                'branch' : 'mozilla-central',
                'branch_url' : 'ssh://hg.mozilla.org/mozilla-central',
                'push_url' : 'ssh://hg.mozilla.org/try',
                'try_run' : 1,
                'patchsetid' : 5,
                'patches' : [
                    { 'id' : '12345',
                      'author' : { 'name' : 'name', 'email' : 'email' },
                      'reviews' : [ { 'reviewer' :
                                      { 'name' : 'name', 'email' : 'email' },
                                    'type' : 'review', 'result' : '+' } ]
                      }]
                    }
        self.assertTrue(hgpusher.valid_job_message(msg))
        del msg['try_run']
        self.assertFalse(hgpusher.valid_job_message(msg))

    def testCloneBranchWorks(self):
        # make sure that cloning works, and that the clean/active clones work
        gen_repos()
        rev = hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo'))
        self.assertTrue(os.access('active/repo', os.F_OK))
        self.assertNotEqual(rev, None)
        self.assertEqual(hgpusher.get_revision('active/repo'),
                         hgpusher.get_revision('clean/repo'))
    def testCloneBranchHgFail(self):
        # mercurial() fail when cloning clean
        with mock.patch('hgpusher.mercurial') as merc:
            merc.side_effect = subprocess.CalledProcessError(1, 'merc')
            self.assertRaises(RetryException, clone_branch, 'branch', 'remote')

            # is the retriable decorator working for us?
            self.assertEquals(merc.call_count, 3)
    def testCloneBranchFail(self):
        os.chdir('work_dir')
        self.assertRaises(RetryException,
                hgpusher.clone_branch, 'bad_repo',
                os.path.join(test_dir, 'bad_repo'))
        self.assertFalse(os.access('active/repo', os.F_OK))
        os.chdir(test_dir)

    def testRepoCleanup(self):
        rc = RepoCleanup('try', 'https://try')
        with mock.patch('hgpusher.update') as upd:
            upd.return_value = None
            rc()
            # soft_clean call
            upd.assert_called_once_with('active/try')

        with mock.patch('hgpusher.clear_branch') as clrb:
            clrb.return_value = None
            with mock.patch('hgpusher.clone_branch') as clnb:
                clnb.return_value = 'abcd123'
                rc()
                # hard_clean call
                clrb.assert_called_once_with('try')
                clnb.assert_called_once_with('try', 'https://try')

    def testPatch(self):
        """
        Test the Patch class.
        """
        p = Patch({'id':1,'author':{'name':'name', 'email':'email'}})
        with mock.patch('hgpusher.bz.get_patch') as gp:
            def gpf(num, dir, create_path=False):
                file = open('%s.patch' % (num), 'w')
                file.write('patch')
                file.close()
                if os.access('%s.patch' % (num), os.F_OK):
                    return '%s.patch' % (num)
                return None
            gp.side_effect = gpf
            self.assertEquals(p.get_file(), '1.patch')
            self.assertEquals(p.file, '1.patch')
            p.delete()
            self.assertFalse(os.access('1.patch', os.F_OK))
            self.assertEquals(p.file, None)
        p.fill_user()
        self.assertEquals(p.user, 'name <email>')

    def testPatchSetComment(self):
        ps = Patchset(1, 1, [], True, '', '', '', None)
        ps.setup_comment()
        comment = ['Autoland Patchset:\n\tPatches: %s\n\tBranch: %s%s'
                    % ('', '', ' => try')]
        self.assertEquals(ps.comment, comment)
        comment.append('Failed.')
        ps.add_comment('Failed.')
        self.assertEquals(ps.comment, comment)
        ps.setup_comment()
        self.assertEquals(ps.comment, [comment[0]])

    def testPatchSetVerify(self):
        self.assertRaises(RetryException,
            Patchset(1, 1, [], True, '', '', '', None).verify)
        with mock.patch('hgpusher.Patch.get_file') as pgf:
            pgf.return_value = None
            self.assertRaises(RetryException,
                Patchset(1, 1, [{'id':1, 'author':
                    {'name':'name', 'email':'email'}}],
                    True, '', '', '', None).verify)
            with mock.patch('hgpusher.has_valid_header') as hvh:
                pgf.return_value = True
                hvh.return_value = False
                # test invalid header on branch landing
                ps = Patchset(1,1, [{'id':1, 'author':
                        {'name':'name', 'email':'email'}}],
                        False, '', '', '', None)
                self.assertRaises(RetryException, ps.verify)
                self.assertTrue('Patch 1 doesn\'t have '
                        'a properly formatted header.' in ps.comment)
                hvh.assert_called_once_with(None)

                ps.setup_comment()
                with mock.patch('hgpusher.import_patch') as ip:
                    ip.return_value = (False, 'error msg')
                    # test invalid header on Try landing, failed patch
                    ps.try_run = True
                    self.assertRaises(RetryException, ps.verify)
                    ip.assert_called_once()
                    self.assertTrue('Patch 1 could not be applied to .\n'
                            'error msg' in ps.comment)

    def testPatchSetFullImport(self):
        ps = Patchset(1, 1, [{'id':1, 'author':
            {'name':'name', 'email':'email'}},
            {'id':2, 'author':
                {'name':'name', 'email':'email'}}],
            True, '', '', '', None)

        rc = [(True, None), (True, None)]
        def ipf(bd, pf, tr, no_commit=False, bug_id=None,
                user=None, try_syntax=None):
            return rc.pop()

        with mock.patch('hgpusher.import_patch') as ip:
            ip.side_effect = ipf
            ps.full_import('dir')
            self.assertTrue(len(ps.comment) == 1)
            ip.assert_called_once()

        rc = [(False, 'err'), (True, None)]
        ps.setup_comment()
        with mock.patch('hgpusher.import_patch') as ip:
            ip.side_effect = ipf
            self.assertRaises(RetryException, ps.full_import, 'dir')
            print ps.comment
            self.assertTrue(len(ps.comment) == 2)
            self.assertTrue('Patch 2 could not be applied to .\nerr'
                    in ps.comment)

    def testPatchSetProcess(self):
        ps = Patchset(1, 1, [{'id':1, 'author':
            {'name':'name', 'email':'email'}},
            {'id':2, 'author':
                {'name':'name', 'email':'email'}}],
            True, '', '', '', None)
        with mock.patch('hgpusher.has_sufficient_permissions') as hsp:
            hsp.return_value = False
            # insufficient permissions
            self.assertFalse(ps.process()[0])

            with mock.patch('hgpusher.clone_branch') as cb:
                with mock.patch('hgpusher.retry') as hgr:
                    hsp.return_value = True
                    cb.side_effect = RetryException
                    hgr.side_effect = RetryException
                    # failed apply_and_push
                    self.assertFalse(ps.process()[0])

                    with mock.patch('hgpusher.get_revision') as gr:
                        with mock.patch('shutil.rmtree') as rmt:
                            with mock.patch('hgpusher.Patch.delete') as pd:
                                hsp.return_value = True
                                cb.side_effect = None
                                cb.return_value = True
                                hgr.side_effect = None
                                hgr.return_value = True
                                gr.return_value = '12345'
                                rmt.return_value = True
                                pd.return_value = True
                                # successful try push
                                self.assertEquals(ps.process()[0], '12345')
                                gr.assert_called_once()
                                rmt.assert_called_once()
                                # successful branch push
                                ps.try_run = False
                                self.assertEquals(ps.process()[0], '12345')
                                self.assertEquals(gr.call_count, 2)
                                self.assertEquals(rmt.call_count, 2)

    def testHasSufficientPermissions(self):
        with mock.patch('hgpusher.ldap.get_member') as ld_gm:
            with mock.patch('hgpusher.ldap.get_branch_permissions') as ld_gbp:
                with mock.patch('hgpusher.ldap.is_member_of_group') as ld_imog:
                    ld_gbp.return_value = None
                    ret = has_sufficient_permissions(None, 'branch')
                    self.assertFalse(ret)

                    ld_gbp.return_value = 'scm_level_1'
                    ld_gm.return_value = [ [None, {'mail':['email_addr']} ] ]
                    ld_imog.return_value = True
                    ret = has_sufficient_permissions(
                            [Patch({'id':1,'author':
                                {'name':'name','email':'email_addr'}})],
                        'branch')
                    self.assertTrue(ret)

                    ld_imog.return_value = False
                    ret = has_sufficient_permissions(
                            [Patch({'id':2,'author':
                                {'email':'email_addr','name':'name'},
                              'reviews':[]})], 'branch')
                    self.assertFalse(ret)

                    ld_gm.return_value = []
                    ret = has_sufficient_permissions(
                            [Patch({'id':3,'author':
                                {'name':'name','email':'email_addr'},
                              'reviews':[]})], 'branch')
                    self.assertFalse(ret)

    def testRunHg(self):
        (out, err, rc) = hgpusher.run_hg(['help'])
        self.assertEquals(rc, 0)
        self.assertEquals(err, '')
        (out, err, rc) = hgpusher.run_hg(['bad_command'])
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(err, '')
        self.assertNotEqual(out, '')

    def testHasValidHeader(self):
        gen_headers()
        valid_patches = []
        bad_patches = []
        sleep(1)
        for rs,ds,fs in os.walk('.'):
            for f in fs:
                if re.match('valid.+\.patch$', f):
                    valid_patches.append(f)
                elif re.match('bad.+\.patch$', f):
                    bad_patches.append(f)
        for f in valid_patches:
            try:
                self.assertEquals(hgpusher.has_valid_header(f), True)
            except AssertionError:
                print 'Error with file: %s' % (f)
                raise
        for f in bad_patches:
            try:
                self.assertEquals(hgpusher.has_valid_header(f), False)
            except AssertionError:
                print 'Error with file: %s' % (f)
                raise

    def testCloneDuplicate(self):
        # Simply make sure that both checkouts have
        # the same revision number
        gen_repos()
        rev = []
        #sleep(5)
        for i in range(2):
            rev.append(hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo')))
            try:
                self.assertNotEqual(rev, None)
            except AssertionError:
                shutil.rmtree('active/repo')
                raise
            print "Got rev: %s" % (rev[i])
            sleep(2)
            if i == 0:
                shutil.rmtree('active/repo')
        print "rev0: %s" % (rev[0])
        print "rev1: %s" % (rev[1])
        self.assertTrue(rev[0] == rev[1])
        sleep(30)

    def testMessageHandler(self):
        msg = []
        msg.append({'payload' : {
            'job_type' : 'patchset',
            'branch' : 'try',
            'branch_url' : 'try_url',
            'patchsetid' : 1,
            'try_run' : 1,
            'bug_id' : 1,
            'patches' : [{ 'id' : 1, 'author':
                {'name':'name', 'email':'email'} }] } })
        with mock.patch('hgpusher.valid_job_message') as vjm:
            # test invalid job messages
            message_handler({'payload':{}})
            vjm.return_value = True
            #XXX:message_handler(msg[0])
            with mock.patch('hgpusher.Patchset.process') as pp:
                with mock.patch('hgpusher.mq.send_message') as sm:
                    #pp.return_value = (cb.return_value, 'This is a comment')
                    # XXX: Need to check that this case is covered.
                    pp.return_value = ('aaaaaa', 'comment')
                    sm.return_value = True
                    message_handler(msg[0])
                    sm.assert_called_once()

    def testClearBranch(self):
        gen_repos()
        clear_branch('repo')
        self.assertFalse(os.access(os.path.join('clean/', 'repo'), os.F_OK))
        self.assertFalse(os.access(os.path.join('active/', 'repo'), os.F_OK))

    def testImportPatch(self):
        with mock.patch('hgpusher.run_hg') as rhg:
            rhg.return_value = (None, None, 1)
            self.assertEquals(import_patch('repo', 'patch.file', 0), (False, None))
            rhg.return_value = (None, None, 0)
            self.assertEquals(import_patch('repo', 'patch.file', 1), (True, None))


if __name__ == "__main__":
    unittest.main()

