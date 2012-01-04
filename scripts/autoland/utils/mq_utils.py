import pika
import sys
from socket import error as sockerr
import time
try:
    import json
except ImportError:
    import simplejson as json
import logging
import datetime

log = logging.getLogger(__name__)

class mq_util():
    def __init__(self, host=None, exchange=''):
        self.connection = None
        self.log = log
        self.last_message = None
        self.host = host
        self.exchange = exchange
        self.channel = None

    def set_host(self, host):
        self.host = host

    def set_exchange(self, exchange):
        self.exchange = exchange

    def connect(self, block=True):
        """
        Connect to the host.
        If block is True, block until connection can be established.
        """
        assert not self.host == None, 'Rabbit host not set'
        while(1):
            try:
                self.connection = pika.BlockingConnection(
                    pika.ConnectionParameters(self.host) )
                break
            except (sockerr, pika.exceptions.AMQPConnectionError):
                if block:
                    print >>sys.stderr, '[RabbitMQ] Failed connection', \
                            'to %s, retry in 60s' % (self.host)
                    log.info('[RabbitMQ] Failed connection ' +
                            'to %s, retry in 60s' % (self.host))
                    time.sleep(60)
                    continue
                else:
                    print >>sys.stderr, '[RabbitMQ] Failed connection', \
                            'to %s' % (self.host)
                    log.info('[RabbitMQ] Failed connection to %s' \
                            % (self.host))
                    return None
        print >>sys.stderr, '[RabbitMQ] Established connection to %s.' \
                % (self.host)
        self.channel = self.connection.channel()

    def _disconnect_(self):
        """
        Disconnect from the host and return and empty channel.
        """
        assert not self.connection == None, 'Not connected to host'
        self.connection.close()
        return None

    def send_message(self, message, routing_key, durable=True, block=True):
        """
        Send a single json message to host on the specified exchange.
        Specify block if it should block until a connection can be made.

        Argument message should be a dictionary, and will have meta tags
        attached to it.
        """
        full_message = { '_meta' : {
                            'sent_time' : str(datetime.datetime.utcnow()),
                            'routing_key' : routing_key,
                            'exchange' : self.exchange,
                         },
                         'payload' : message
                       }
        if not self.channel:
            if not block:
                return None
            self.connect()
        print self.exchange
        self.channel.exchange_declare(exchange=self.exchange, type='direct', durable=durable)
        print "MESSAGE BEING SENT OUT: %s" % ( full_message )
        self.channel.basic_publish(exchange=self.exchange, routing_key=routing_key,
                    body=json.dumps(full_message), properties=pika.BasicProperties(
                        delivery_mode=2,
                ))

    def listen(self, queue, callback, routing_key, durable=True, block=True):
        """
        Passes received messages to function callback, taking one argument.
            - ['_meta'] contains data about the received message
            - ['payload'] contains the message payload
        Specify block if it should block until a connection can be made.
        """
        assert callable(callback), 'callback must be a function'
        def callback_wrapper(ch, method, properties, body):
            try:
                message = json.loads(body)
            except ValueError:
                ch.basic_ack(delivery_tag = method.delivery_tag)
                return
            # make sure that the message has the expected structure.
            if not 'payload' in message:
                message = {'payload' : message}
            if not '_meta' in message:
                message['_meta'] = {}
            message['_meta']['received_time'] = str(datetime.datetime.utcnow())
            callback(message)
            ch.basic_ack(delivery_tag = method.delivery_tag)

        while(True):
            try:
                if not self.channel:
                    if not block:
                        return None
                    self.connect()
                log.info('[RabbitMQ] Listening on %s.' % (routing_key))
                self.channel.exchange_declare(exchange=self.exchange, type='direct', durable=durable)
                result = self.channel.queue_declare(queue=queue, durable=durable)
                queue_name = result.method.queue
                self.channel.queue_bind(queue=result.method.queue,
                        exchange=self.exchange, routing_key=routing_key)
                self.channel.basic_qos(prefetch_count=1)
                self.channel.basic_consume(callback_wrapper, queue=queue_name)
                self.channel.start_consuming()
            except sockerr:
                self.channel = None
                log.info('[RabbitMQ] Connection to %s lost. Reconnecting...'
                        % (self.host))

