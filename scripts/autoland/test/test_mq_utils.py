import unittest
import os, shutil, sys
import tempfile
import json
import mock
from socket import error as sockerr
import subprocess
# Autoland imports
sys.path.append('..')
from utils import mq_utils
import time

# have a rabbitmq server running
#rmq = subprocess.Popen(['rabbitmq-server', '-detached'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#time.sleep(10) # Allow for the server to start
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
        self.assertEqual(self.mq.listen(queue='queue', callback=str, routing_key=['db.message'], block=False), None)
    def testDisconnectFail(self):
        self.assertRaises(AssertionError, self.mq._disconnect_)
    def testDisconnect(self):
        self.mq.connect()
        self.assertEqual(self.mq._disconnect_(), None)
    def testSendRec(self):
        class RECEIVED(Exception):
            print "RECEIVED"
            pass
        def message_handler(message):
            print "Handling message %s" % message
            raise RECEIVED
        raised = False
        # rabbitmq must be running
        j = {'msg':'TEST'}
        self.mq.send_message(message=j, routing_key='db.message')
        listener = mq_utils.mq_util()
        listener.set_host('localhost')
        listener.set_exchange('autoland')
        try:
            # For some reason assertRaises won't work here
            listener.listen(queue='test', callback=message_handler, routing_key='other.words')
        except RECEIVED:
            print "Exception hit"
            raised = True
        self.assertFalse(raised)


if __name__ == '__main__':
    unittest.main()
