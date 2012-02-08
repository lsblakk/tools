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
        process_patchset, message_handler, clear_branch, import_patch
from utils import mq_utils

top_dir = os.getcwd()
test_dir = os.path.join(top_dir, 'test_hgpusher/')
if os.access(test_dir, os.F_OK):
    shutil.rmtree(test_dir)

def gen_repos():
    subprocess.Popen(['sh', '../test/gen_hgrepo.sh'])
    sleep(1)        # For some reason, need a pause here
    os.chdir('work_dir')

def gen_headers():
    subprocess.Popen(['sh', '../test/gen_headers.sh'])
    sleep(1)

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
        shutil.rmtree(test_dir)

    def testValidDictionaryStructure(self):
        lower = {}
        upper = {}
        for c in string.ascii_lowercase:
            lower[c] = c
        for c in string.ascii_uppercase:
            upper[c] = c
        self.assertTrue(hgpusher.valid_dictionary_structure(lower, lower.keys()))
        self.assertFalse(hgpusher.valid_dictionary_structure(lower, upper.keys()))

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
            ret = clone_branch('branch', 'remote')
            self.assertEquals(ret, None)
            merc.assert_called_once_with('remote', os.path.join('clean', 'branch'))
    def testCloneBranchFail(self):
        os.chdir('work_dir')
        rev = hgpusher.clone_branch('bad_repo', os.path.join(test_dir, 'bad_repo'))
        self.assertFalse(os.access('active/repo', os.F_OK))
        self.assertEquals(rev, None)
        os.chdir(test_dir)

    def testProcessPatchset_CleanupWrapper(self):
        gen_repos()
        branch_url = os.path.join(test_dir, 'repo/')
        push_url = os.path.join(test_dir, 'try/')

        should_pass = \
               [{ 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 1,  # Push to try, Author & review only have scm_level_1
                  'branch_url' : branch_url, 'push_url' : push_url,
                  'patchsetid' : 5,
                'patches' :
                [{ 'id' : 'hello_patch.patch',
                    'author' : { 'name' : 'Hg Pusher', 'email' : 'mjessome@mozilla.com' },
                    'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'mjessome@mozilla.com' } } ]
                    }]
               }]

    """
        with mock.patch('hgpusher.clear_branch') as cb:
            with mock.patch('hgpusher.update') as up:
                with mock.patch('hgpusher.clone_branch') as clone:
                    with mock.patch('hgpusher.has_sufficient_permissions') as hsp:
                        hsp.return_value = True
                        self.assertEquals(process_patchset(None), False)
                        for p in should_pass:
                            self.assertEquals(process_patchset(p) != False,
                                    True)
    def testProcessPatchset(self):
        #hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo'))
        #os.chdir(test_dir)
        branch_url = os.path.join(test_dir, 'repo/')
        push_url = os.path.join(test_dir, 'try/')
        should_pass = \
               [{ 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 1,  # Push to try, Author & review only have scm_level_1
                  'branch_url' : branch_url, 'push_url' : push_url,
                  'patchsetid' : 5,
                'patches' :
                [{ 'id' : 'hello_patch.patch',
                    'author' : { 'name' : 'Hg Pusher', 'email' : 'mjessome@mozilla.com' },
                    'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'mjessome@mozilla.com' } } ]
                    }]
               }]

        should_fail = \
               [{ 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 0,  # Push to branch, Author/Review have no access
                   'branch_url' : branch_url,
                  'patchsetid' : 5,
                'patches' :
                [{ 'id' : 'hello_patch.patch',
                    'author' : { 'name' : 'Hg Pusher', 'email' : 'hgp@mozilla.com' },
                    'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'hgpr@mozilla.com' } } ]
                    }]
               },
                { 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 1,
                  'branch_url' : branch_url,
                  'push_url' : push_url,
                  'patchsetid' : 5,
                  'patches' :
                  [{ 'id' : 'dne.patch',    # dne.patch doesn't exist
                     'author' : { 'name' : 'Hg Pusher', 'email' : 'hgp@none.com' },
                     'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'mjessome@mozilla.com' }} ]
                  }]
                },
                { 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 0,
                  'patchsetid' : 5,
                  'patches' :
                  [{ 'id' : 'hello_patch.diff', # invalid header
                     'author' : { 'name' : 'Hg Pusher', 'email' : 'mjessome@mozilla.com' },
                     'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'hgp@moz.com' }}]
                     }]
                },
                { 'branch' : 'repo', 'bug_id' : 10411, 'try_run' : 1,
                  'branch_url' : branch_url,
                  'patchsetid' : 5,
                  'patches' :
                  [{ 'id' : 'hello_patch.patch',
                     'author' : { 'name' : 'Hg Pusher', 'email' : 'mjessome@mozilla.com' },
                     'reviews' : [ { 'reviewer' : { 'name' : 'HGP Reviewer', 'email' : 'hgp@moz.com' }}]
                     }]

                }]
        os.chdir('work_dir')
        with mock.patch('hgpusher.bz.get_patch') as get_patch:
            perms = ['scm_level_1', 'scm_level_1', 'scm_level_1', 'scm_level_3', 'scm_level_1']
            def send_message(x, y, routing_keys=[]):
                return
            def get_branch_permissions(branch):
                return perms.pop()
            def email_is_member(email, group):
                return True
            hgpusher.mq.send_message = send_message
            hgpusher.ldap.get_branch_permissions = get_branch_permissions
            # Push a single patch
            for data in should_pass:
                get_patch.return_value = \
                    os.path.join(test_dir, 'work_dir/clean/repo/%s' % (data['patches'][0]['id']))
                active_revision = hgpusher.process_patchset(data)
                self.assertNotEqual(active_revision, False)
            for data in should_fail:
                get_patch.return_value = \
                    os.path.join(test_dir, 'work_dir/clean/repo/%s' % (data['patches'][0]['id']))
                active_revision = hgpusher.process_patchset(data)
                self.assertEqual(active_revision, False)
            os.chdir(test_dir)

        # make sure that the push is going to the base_url only,
        # and not to the clean repository.
        hgpusher.update('repo') # update to reflect pushed
        self.assertNotEqual(active_revision,
                hgpusher.get_revision(os.path.join(test_dir,
                    'work_dir/clean/repo')))
        subprocess.Popen(['sh', '../test/gen_hgrepo.sh', '--clean'])
    """

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
                            [{'author':{'email':'email_addr'}}], 'branch')
                    self.assertTrue(ret)

                    ld_imog.return_value = False
                    ret = has_sufficient_permissions(
                            [{'author':{'email':'email_addr'},
                              'reviews':[]}], 'branch')
                    self.assertFalse(ret)

                    ld_gm.return_value = []
                    ret = has_sufficient_permissions(
                            [{'author':{'email':'email_addr'},
                              'reviews':[]}], 'branch')
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
        for i in range(2):
            rev.append(hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo')))
            try:
                self.assertNotEqual(rev, None)
            except AssertionError:
                shutil.rmtree('active/repo')
                raise
            sleep(2)
            if i == 0:
                shutil.rmtree('active/repo')
        self.assertTrue(rev[0] == rev[1])

    def testMessageHandler(self):
        msg = []
        msg.append({'payload' : {
            'job_type' : 'patchset',
            'branch' : 'try',
            'branch_url' : 'try_url',
            'patchsetid' : 1,
            'try_run' : 1,
            'bug_id' : 1,
            'patches' : [{ 'id' : 1 }] } })
        with mock.patch('hgpusher.clone_branch') as cb:
            with mock.patch('hgpusher.valid_job_message') as vjm:
                # test invalid job messages
                message_handler({'payload':{}})

                vjm.return_value = True
                cb.return_value = None
                message_handler(msg[0])
                cb.assert_called_with('mozilla-central', 'mozilla-central_url')
                cb.return_value = '7124a8c22d'
                with mock.patch('hgpusher.process_patchset') as pp:
                    with mock.patch('hgpusher.mq.send_message') as sm:
                        pp.return_value = (cb.return_value, 'This is a comment')
                        # XXX: Need to check that this case is covered.
                        pp.return_value = ('aaaaaa', 'comment')
                        sm.return_value = True
                        sm.assert_called_once()
                        message_handler(msg[0])

    def testClearBranch(self):
        gen_repos()
        clear_branch('repo')
        self.assertFalse(os.access(os.path.join('clean/', 'repo'), os.F_OK))
        self.assertFalse(os.access(os.path.join('active/', 'repo'), os.F_OK))

    def testImportPatch(self):
        with mock.patch('hgpusher.run_hg') as rhg:
            rhg.return_value = (None, None, 1)
            self.assertEquals(import_patch('repo', 'patch.file', 0), (1, None))
            rhg.return_value = (None, None, 0)
            self.assertEquals(import_patch('repo', 'patch.file', 1), (0, None))


if __name__ == "__main__":
    unittest.main()

