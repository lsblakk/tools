import site
site.addsitedir('vendor')
site.addsitedir('vendor/lib/python')

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
        self.mq.set_exchange('autoland-new')
        self.mq.connect()
    def tearDown(self):
        self.mq._disconnect_()
    def testConnectNoHost(self):
        self.mq.set_host(None)
        self.assertRaises(AssertionError, self.mq.connect, False)
    def testSetHost(self):
        self.mq.set_host('localhost')
    def testConnectionNoBlockFail(self):
        self.mq._disconnect_()
        self.mq.set_host('bad_hostname')
        self.mq.connect(block=False)
        self.assertEqual(self.mq.listen(queue='queue', callback=str,
            routing_key='db.message', block=False), None)
    #def testDisconnectFail(self):
        #self.mq._disconnect_()
        #self.assertRaises(AssertionError, self.mq._disconnect_)
    def testDisconnect(self):
        self.mq.connect()
        self.assertEqual(self.mq._disconnect_(), None)
    def testSendRec(self):
        class RECEIVED(Exception):
            print "RECEIVED"
            pass
        def message_handler_topic1(message):
            print "Handling message %s of topic 1" % message
            raise RECEIVED
        def message_handler_topic2(message):
            print "Handling message %s of topic 2" % message
            raise RECEIVED
        raised = False
        # rabbitmq must be running
        j = {'msg':'TEST'}
        self.mq.send_message(message=j, routing_key='autoland.db', durable=False)
        listener = mq_utils.mq_util()
        listener.set_host('localhost')
        listener.set_exchange('autoland-new')
        listener.connect()
        try:
            # For some reason assertRaises won't work here
            listener.listen(queue='test-new', callback=message_handler_topic1,
                    routing_key='autoland.db', durable=False)
        except RECEIVED:
            raised = True
        self.assertFalse(raised)
        # Now try a different routing key
        raised = False
        self.mq.send_message(message=j, routing_key='hgpusher.pushes', durable=False)
        listener2 = mq_utils.mq_util()
        listener2.set_host('localhost')
        listener2.set_exchange('autoland-new')
        listener2.connect()
        try:
            # For some reason assertRaises won't work here
            listener2.listen(queue='test-new', callback=message_handler_topic2,
                    routing_key='hgpusher.pushes', durable=False)
        except RECEIVED:
            raised = True
        self.assertFalse(raised)
if __name__ == '__main__':
    unittest.main()
