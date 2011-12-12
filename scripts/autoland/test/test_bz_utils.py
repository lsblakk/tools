import unittest
import os, shutil, sys
import tempfile
import mock
import json
import string
import random
import datetime
# Autoland imports
sys.path.append('..')
from utils import bz_utils
bz = bz_utils.bz_util('https://api-dev.bugzilla.mozilla.org/test/latest/',
                      'https://bugzilla.mozilla.org/attachment.cgi?id=',
                      'lsblakk@mozilla.com', 'password')

class TestBzUtils(unittest.TestCase):
    def testGetPatchBadID(self):
        self.assertEqual(bz.get_patch(-1), None)

    def testGetPatchGoodID(self):
        path = bz.get_patch(1)
        self.assertTrue(os.access(path, os.F_OK))
        os.remove(path)

    def testGetPatchAlternatePath(self):
        dir = tempfile.mkdtemp()
        path = bz.get_patch(1, dir)
        self.assertEquals(path, '%s/1.patch' % (dir))
        self.assertTrue(os.access(path, os.F_OK))
        shutil.rmtree(dir)

    def testGetUserInfoPass(self):
        info = bz.get_user_info('mjessome@mozilla.com')
        for i in ['name', 'email']:
            self.assertTrue(i in info)

    def testGetUserInfoFail(self):
        self.assertEquals(bz.get_user_info(''), None)

    def testWhiteBoardTagPass(self):
        """
        Test all the whiteboard related functions, since we can add,
        remove and replace sequentially this way.
        """
        bug = 10469
        # Clear the whiteboard first...
        bz.replace_whiteboard_tag('.+', '', bug)
        # add_whiteboard_tag
        bz.add_whiteboard_tag('[bz_utils test1]', bug)
        # get_matching_tags
        match = bz.get_matching_bugs('whiteboard', '[bz_utils test1]')
        self.assertTrue((bug, '[bz_utils test1]') in match)
        # replace_whiteboard_tag
        self.assertTrue(bz.replace_whiteboard_tag('\[bz_utils test1\]', '[bz_utils test2]', bug))
        match = bz.get_matching_bugs('whiteboard', '[bz_utils test2]')
        self.assertTrue((bug, '[bz_utils test2]') in match)
        # remove_whiteboard_tag
        self.assertTrue(bz.remove_whiteboard_tag('\[bz_utils test2\]', bug))

    def testWhiteBoardTagFail(self):
        # TODO - this needs to handle 400 bad request to test retries and timeout for put_request
        bug = 104699
        dt = str(datetime.datetime.utcnow())
        match = bz.get_matching_bugs('whiteboard', dt)
        self.assertFalse((bug, dt) in match)
        self.assertFalse(bz.has_comment(dt, bug))
        self.assertFalse(bz.has_recent_comment(dt, bug))

    def testCommentFail(self):
        bug = 104699
        comment = list(string.printable)
        dt = str(datetime.datetime.utcnow())
        random.shuffle(comment)
        comment = ''.join(comment) + dt
        self.assertTrue(bz.notify_bug(comment, bug))
        self.assertFalse(bz.has_comment(comment, bug))
        self.assertFalse(bz.has_recent_comment(dt, bug))

    def testCommentPass(self):
        bug = 10469
        comment = list(string.printable)
        dt = str(datetime.datetime.utcnow())
        random.shuffle(comment)
        comment = str(comment) + dt
        self.assertTrue(bz.notify_bug(comment, bug))
        self.assertTrue(bz.has_comment(comment, bug))
        self.assertTrue(bz.has_recent_comment(dt, bug))

if __name__ == '__main__':
    unittest.main()

