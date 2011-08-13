import unittest
import os, shutil, sys
import tempfile
import json
import mock
from socket import error as sockerr
# Autoland imports
sys.path.append('..')
from utils import mq_utils

class TestMqUtils(unittest.TestCase):
    def setUp(self):
        self.mq = mq_utils.mq_util()
        self.mq.set_host('localhost')
        self.mq.set_exchange('autoland')
    def testConnectNoHost(self):
        self.mq.set_host(None)
        self.assertRaises(AssertionError, self.mq.connect, False)
    def testSetHost(self):
        self.mq.set_host('localhost')
    def testConnectionNoBlockFail(self):
        self.mq.set_host('bad_hostname')
        self.assertEqual(self.mq.listen('queue', str, block=False), None)
    def testDisconnectFail(self):
        self.assertRaises(AssertionError, self.mq._disconnect_)
    def testDisconnect(self):
        self.mq.connect()
        self.assertEqual(self.mq._disconnect_(), None)
    def testSendRec(self):
        class RECEIVED(Exception):
            pass
        def message_handler(message):
            raise RECEIVED
        raised = False
        # rabbitmq must be running
        j = {'msg':'TEST'}
        self.mq.send_message(j, 'test')
        try:
            # For some reason assertRaises won't work here
            self.mq.listen('test', message_handler)
        except RECEIVED:
            raised = True
        self.assertTrue(raised)


if __name__ == '__main__':
    unittest.main()
