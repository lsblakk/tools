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
from utils import mq_utils

test_dir = os.path.join(os.getcwd(), 'test/')
if os.access(test_dir, os.F_OK):
    shutil.rmtree(test_dir)

class TestHgPusher(unittest.TestCase):
    def setUp(self):
        if not os.access(test_dir, os.F_OK):
            os.mkdir(test_dir)
        hgpusher.mq = mq_utils.mq_util()
        hgpusher.config['work_dir'] = os.path.join(test_dir, 'work_dir')
        os.chdir(test_dir)
        if not os.access('work_dir', os.F_OK):
            os.mkdir('work_dir')
        os.chdir(test_dir)
        hgpusher.config['hg_base_url'] = test_dir

    def testValidDictionaryStructure(self):
        lower = {}
        upper = {}
        for c in string.ascii_lowercase:
            lower[c] = c
        for c in string.ascii_uppercase:
            upper[c] = c
        self.assertTrue(hgpusher.valid_dictionary_structure(lower, lower.keys()))
        self.assertFalse(hgpusher.valid_dictionary_structure(lower, upper.keys()))

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

    def testCloneBranchPass(self):
        subprocess.Popen(['sh', '../gen_hgrepo.sh'])
        sleep(1)
        os.chdir('work_dir')
        rev = hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo'))
        self.assertTrue(os.access('active/repo', os.F_OK))
        try:
            self.assertNotEqual(rev, None)
        except AssertionError:
            shutil.rmtree('active/repo')
            raise
        os.chdir(test_dir)
        shutil.rmtree('work_dir/active/repo')
        subprocess.Popen(['sh', '../gen_hgrepo.sh', '--clean'])

    def testCloneBranchFail(self):
        os.chdir('work_dir')
        rev = hgpusher.clone_branch('bad_repo', os.path.join(test_dir, 'bad_repo'))
        self.assertFalse(os.access('active/repo', os.F_OK))
        self.assertEquals(rev, None)
        os.chdir(test_dir)

    def testProcessPatchset(self):
        subprocess.Popen(['sh', '../gen_hgrepo.sh'])
        sleep(1)
        print "RUNNING TEST"
        os.chdir('work_dir')
        hgpusher.clone_branch('repo', os.path.join(test_dir, 'repo'))
        os.chdir(test_dir)
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
        subprocess.Popen(['sh', '../gen_hgrepo.sh', '--clean'])

    def testHasSufficientPermissions(self):
        p = [ { 'author' : { 'email' : 'bad@email.com'},
                'reviews' : [ { 'reviewer' : { 'email' : 'mjessome@mozilla.com' } } ]
                    } ]
        self.assertTrue(hgpusher.has_sufficient_permissions(p, 'try'))
        self.assertFalse(hgpusher.has_sufficient_permissions(p, 'mozilla-central'))
        p = [ { 'author' : { 'email' : 'mjessome@mozilla.com'},
            'reviews' : [ { 'reviewer' : { 'email' : 'bad@email.com' } } ] }]
        self.assertTrue(hgpusher.has_sufficient_permissions(p, 'try'))
        self.assertFalse(hgpusher.has_sufficient_permissions(p, 'mozilla-central'))
        p = [ { 'author' : { 'email' : 'bad@email.com'},
                'reviews' : [ { 'reviewer' : { 'email' : 'bad@email.com' } } ] }]
        self.assertFalse(hgpusher.has_sufficient_permissions(p, 'try'))
        self.assertFalse(hgpusher.has_sufficient_permissions(p, 'mozilla-central'))

    def testRunHg(self):
        (out, err, rc) = hgpusher.run_hg(['help'])
        self.assertEquals(rc, 0)
        self.assertEquals(err, '')
        (out, err, rc) = hgpusher.run_hg(['bad_command'])
        self.assertNotEqual(rc, 0)
        self.assertNotEqual(err, '')
        self.assertNotEqual(out, '')

    def testHasValidHeader(self):
        subprocess.Popen(['sh', '../gen_headers.sh'])
        sleep(1)    # pause to allow processing
        valid_patches = []
        bad_patches = []
        for rs,ds,fs in os.walk('test'):
            for f in fs:
                if re.match('valid.+\.patch$', f):
                    valid_patches.append('test/%s' % f)
                elif re.match('bad.+\.patch$', f):
                    bad_patches.append('test/%s' % f)
        for f in valid_patches:
            try:
                self.assertEquals(hgpusher.has_valid_header(f, False), True)
            except AssertionError:
                print 'Error with file: %s' % (f)
                run_cmd(['sh', '../gen_headers.sh', '--clean'])
                raise
        for f in bad_patches:
            try:
                self.assertEquals(hgpusher.has_valid_header(f, False), False)
            except AssertionError:
                print 'Error with file: %s' % (f)
                run_cmd(['sh', '../gen_headers.sh', '--clean'])
                raise
        subprocess.Popen(['sh', '../gen_headers.sh', '--clean'])

    def testCloneDuplicate(self):
        # Simply make sure that both checkouts have
        # the same revision number
        subprocess.Popen(['sh', '../gen_hgrepo.sh'])
        if os.access('work_dir/active/repo', os.F_OK):
            shutil.rmtree('work_dir/active/repo')
        sleep(2)
        rev = []
        os.chdir('work_dir')
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
        os.chdir(test_dir)
        shutil.rmtree('work_dir/clean/repo')
        subprocess.Popen(['sh', '../gen_hgrepo.sh', '--clean'])
        self.assertTrue(rev[0] == rev[1])

if __name__ == "__main__":
    unittest.main()

