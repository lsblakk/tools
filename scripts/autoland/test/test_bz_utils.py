import unittest
import urllib2
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
bz = bz_utils.bz_util(api_url='https://api-dev.bugzilla.mozilla.org/test/latest/',
                      url='https://bugzilla.mozilla.org/show_bug.cgi?id=',
                      attachment_url='https://bugzilla.mozilla.org/attachment.cgi?id=',
                      username='lsblakk@mozilla.com', password='password')

class TestBzUtils(unittest.TestCase):
    def setUp(self):
        bz.attachment_url = 'https://bugzilla.mozilla.org/attachment.cgi?id='
    def testGetPatchBadID(self):
        self.assertEqual(bz.get_patch('abcdefgbadpatchijklmnop'), None)
        url = bz.attachment_url
        bz.attachment_url = 'https://bugzilla.notreal/attachment.cgi?id='
        self.assertEqual(bz.get_patch(-1), None)
        bz.attachment_url = url

    def testGetPatchGoodID(self):
        path = bz.get_patch(1)
        print path
        self.assertTrue(os.access(path, os.F_OK))
        os.remove(path)

    def testGetPatchAlternatePath(self):
        dir = tempfile.mkdtemp()
        path = bz.get_patch(1, dir)
        self.assertEquals(path, '%s/1.patch' % (dir))
        self.assertTrue(os.access(path, os.F_OK))
        shutil.rmtree(dir)

    def testGetUserInfoPass(self):
        info = bz.get_user_info('lsblakk@mozilla.com')
        for i in ['name', 'email']:
            self.assertTrue(i in info)

    def testGetUserInfoFail(self):
        self.assertEquals(bz.get_user_info(''), None)

    def testWhiteBoardTagPass(self):
        """
        Test all the whiteboard related functions, since we can add,
        remove and replace sequentially this way.
        """
        bug = 10750
        print "clearing whiteboard first..."
        bz.replace_whiteboard_tag('.+', '', bug)
        print "add_whiteboard_tag..."
        bz.add_whiteboard_tag('[bz_utils test1]', bug)
        print "get_matching_tags..."
        match = bz.get_matching_bugs('whiteboard', '[bz_utils test1]')
        self.assertTrue((bug, '[bz_utils test1]') in match)
        print "replace_whiteboard_tag..."
        self.assertTrue(bz.replace_whiteboard_tag('\[bz_utils test1\]', '[bz_utils test2]', bug))
        match = bz.get_matching_bugs('whiteboard', '[bz_utils test2]')
        self.assertTrue((bug, '[bz_utils test2]') in match)
        print "remove_whiteboard_tag..."
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
        dt = str(datetime.datetime.utcnow())
        comment = "Comment should fail " + dt
        print "notify_bug"
        self.assertFalse(bz.notify_bug(comment, bug))
        print "has_comment"
        self.assertFalse(bz.has_comment(comment, bug))
        print "has_recent_comment"
        self.assertFalse(bz.has_recent_comment(dt, bug))

    def testCommentPass(self):
        bug = 10750
        dt = str(datetime.datetime.utcnow())
        comment = "Comment should pass " + dt
        print "notify_bug"
        self.assertTrue(bz.notify_bug(comment, bug))
        print "has_comment"
        self.assertTrue(bz.has_comment(comment, bug))
        print "has_recent_comment"
        self.assertTrue(bz.has_recent_comment(dt, bug))

    def testPutRequest(self):
        with mock.patch('utils.bz_utils.bz_util.request') as bur:
            bur.side_effect = urllib2.HTTPError('path', 400, 'Bad Request',
                    None, None)
            try:
                bz.put_request('path', 'data', 2, 2)
            except Exception, exception:
                self.assertEquals(str(exception), 'PutError')
            self.assertTrue(bur.call_count == 2)

    def testBugsFromComments(self):
        ret = bz.bugs_from_comments("this is a comment with no bug mentioned")
        self.assertEquals(ret, [])
        ret = bz.bugs_from_comments("this comment is about bug 10480 only")
        self.assertEquals(ret, [10480])
        ret = bz.bugs_from_comments("comment is about bugs 10480, 10411")
        self.assertEquals(ret, [10480, 10411])
        ret = bz.bugs_from_comments("commet about b10480")
        self.assertEquals(ret, [10480])

if __name__ == '__main__':
    unittest.main()

