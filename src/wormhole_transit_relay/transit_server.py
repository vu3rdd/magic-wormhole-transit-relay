import re
import time
from twisted.python import log
from twisted.protocols.basic import LineReceiver
from autobahn.twisted.websocket import WebSocketServerProtocol
from binascii import hexlify, unhexlify

SECONDS = 1.0
MINUTE = 60*SECONDS
HOUR = 60*MINUTE
DAY = 24*HOUR
MB = 1000*1000


from wormhole_transit_relay.server_state import (
    TransitServerState,
    PendingRequests,
    ActiveConnections,
    ITransitClient,
)
from zope.interface import implementer


@implementer(ITransitClient)
class TransitConnection(LineReceiver):
    delimiter = b'\n'
    _packet_count = 0
    _last_buffer = bytes([])
    _last_length = 0
    # maximum length of a line we will accept before the handshake is complete.
    # This must be >= to the longest possible handshake message.

    MAX_LENGTH = 1024
    started_time = None

    def send(self, data):
        """
        ITransitClient API
        """
        self.transport.write(data)

    def disconnect(self):
        """
        ITransitClient API
        """
        self.transport.loseConnection()

    def connect_partner(self, other):
        """
        ITransitClient API
        """
        self._buddy = other

    def disconnect_partner(self):
        """
        ITransitClient API
        """
        assert self._buddy is not None, "internal error: no buddy"
        if self.factory.log_requests:
            log.msg("buddy_disconnected {}".format(self._buddy.get_token()))
        self._buddy._client.disconnect()
        self._buddy = None

    def connectionMade(self):
        # ideally more like self._reactor.seconds() ... but Twisted
        # doesn't have a good way to get the reactor for a protocol
        # (besides "use the global one")
        self.started_time = time.time()
        self._state = TransitServerState(
            self.factory.transit.pending_requests,
            self.factory.transit.usage,
        )
        self._state.connection_made(self)
        self.transport.setTcpKeepAlive(True)
        self._state._client_type = "tcp"

        # uncomment to turn on state-machine tracing
        # def tracer(oldstate, theinput, newstate):
        #     print("TRACE: {}: {} --{}--> {}".format(id(self), oldstate, theinput, newstate))
        # self._state.set_trace_function(tracer)

    def lineReceived(self, line):
        """
        LineReceiver API
        """
        # old: "please relay {64}\n"
        token = None
        old = re.search(br"^please relay (\w{64})$", line)
        if old:
            token = old.group(1)
            self._state.please_relay(token)

        # new: "please relay {64} for side {16}\n"
        new = re.search(br"^please relay (\w{64}) for side (\w{16})$", line)
        if new:
            token = new.group(1)
            side = new.group(2)
            self._state.please_relay_for_side(token, side)

        if token is None:
            self._state.bad_token()
        else:
            self.setRawMode()

    def rawDataReceived(self, data):
        """
        LineReceiver API
        """
        # We are an IPushProducer to our buddy's IConsumer, so they'll
        # throttle us (by calling pauseProducing()) when their outbound
        # buffer is full (e.g. when their downstream pipe is full). In
        # practice, this buffers about 10MB per connection, after which
        # point the sender will only transmit data as fast as the
        # receiver can handle it.
        self._packet_count += 1
        # detect TCP sender
        sender_handshake = re.search(br"^transit sender (\w{64}) ready\n\n", data)
        if sender_handshake:
            print("handshake: {}".format(data))
            self._state.got_bytes(data)
            return

        sender_go = re.search(br"^go\n", data)
        if sender_go:
            print("go: {}".format(data))
            self._state.got_bytes(data)
            return

        # if len(self._last_buffer) is not 0:
        self._last_buffer += data

        length = int(hexlify(self._last_buffer[0:4]), 16)
        print("enc record len: {}, payload len: {}".format(length, len(self._last_buffer)))
        if len(self._last_buffer) == length + 4:
            print("sending...3")
            self._state.got_bytes(data)
        else: # either length of the payload is bigger or smaller
            if len(self._last_buffer) >= length:
                pCount = 0
                while len(self._last_buffer) > 4:
                    # split payload into length sized packets.
                    length = int(hexlify(self._last_buffer[0:4]), 16)
                    print("{}: length of record: {}".format(pCount, length))
                    payload = self._last_buffer[0:length+4] # one packet (or smaller)
                    self._last_buffer = self._last_buffer[length+4:]
                    # print("{}: length of tcp data payload: {}".format(pCount, len(data)))
                    if len(payload) < (length + 4):
                        self._last_buffer += payload
                        self._last_length = length
                        print("{}: saving into buffer.. len(_buffer): {}".format(pCount, len(self._last_buffer)))
                        return
                    else:
                        print("{}: len: {}, split payload len: {}, len of last_buffer: {}".format(pCount, length, len(payload), len(self._last_buffer)))
                        print("sending...4")
                        self._state.got_bytes(payload)
                    pCount += 1
            else:
                # len(data) < length + 4. we should buffer this data
                # until we get the frame boundary
                print("haven't got enough bytes yet")

    def connectionLost(self, reason):
        self._state.connection_lost()


class Transit(object):
    """
    I manage pairs of simultaneous connections to a secondary TCP port,
    both forwarded to the other. Clients must begin each connection with
    "please relay TOKEN for SIDE\n" (or a legacy form without the "for
    SIDE"). Two connections match if they use the same TOKEN and have
    different SIDEs (the redundant connections are dropped when a match is
    made). Legacy connections match any with the same TOKEN, ignoring SIDE
    (so two legacy connections will match each other).

    I will send "ok\n" when the matching connection is established, or
    disconnect if no matching connection is made within MAX_WAIT_TIME
    seconds. I will disconnect if you send data before the "ok\n". All data
    you get after the "ok\n" will be from the other side. You will not
    receive "ok\n" until the other side has also connected and submitted a
    matching token (and differing SIDE).

    In addition, the connections will be dropped after MAXLENGTH bytes have
    been sent by either side, or MAXTIME seconds have elapsed after the
    matching connections were established. A future API will reveal these
    limits to clients instead of causing mysterious spontaneous failures.

    These relay connections are not half-closeable (unlike full TCP
    connections, applications will not receive any data after half-closing
    their outgoing side). Applications must negotiate shutdown with their
    peer and not close the connection until all data has finished
    transferring in both directions. Applications which only need to send
    data in one direction can use close() as usual.
    """

    # TODO: unused
    MAX_WAIT_TIME = 30*SECONDS
    # TODO: unused
    MAXLENGTH = 10*MB
    # TODO: unused
    MAXTIME = 60*SECONDS

    def __init__(self, usage, get_timestamp):
        self.active_connections = ActiveConnections()
        self.pending_requests = PendingRequests(self.active_connections)
        self.usage = usage
        self._timestamp = get_timestamp
        self._rebooted = self._timestamp()

    def update_stats(self):
        # TODO: when a connection is half-closed, len(active) will be odd. a
        # moment later (hopefully) the other side will disconnect, but
        # _update_stats isn't updated until later.

        # "waiting" doesn't count multiple parallel connections from the same
        # side
        self.usage.update_stats(
            rebooted=self._rebooted,
            updated=self._timestamp(),
            connected=len(self.active_connections._connections),
            waiting=len(self.pending_requests._requests),
            incomplete_bytes=sum(
                tc._total_sent
                for tc in self.active_connections._connections
            ),
        )


@implementer(ITransitClient)
class WebSocketTransitConnection(WebSocketServerProtocol):
    started_time = None

    def send(self, data):
        """
        ITransitClient API
        """
        self.sendMessage(data, isBinary=True)

    def disconnect(self):
        """
        ITransitClient API
        """
        self.sendClose(1000, None)

    def connect_partner(self, other):
        """
        ITransitClient API
        """
        self._buddy = other

    def disconnect_partner(self):
        """
        ITransitClient API
        """
        assert self._buddy is not None, "internal error: no buddy"
        if self.factory.log_requests:
            log.msg("buddy_disconnected {}".format(self._buddy.get_token()))
        self._buddy._client.disconnect()
        self._buddy = None

    def connectionMade(self):
        """
        IProtocol API
        """
        super(WebSocketTransitConnection, self).connectionMade()
        self.started_time = time.time()
        self._first_message = True
        self._state = TransitServerState(
            self.factory.transit.pending_requests,
            self.factory.transit.usage,
        )

        # uncomment to turn on state-machine tracing
        # def tracer(oldstate, theinput, newstate):
        #    print("WSTRACE: {}: {} --{}--> {}".format(id(self), oldstate, theinput, newstate))
        # self._state.set_trace_function(tracer)

    def onOpen(self):
        self._state.connection_made(self)
        self._state._client_type = "websocket"

    def onMessage(self, payload, isBinary):
        """
        We may have a 'handshake' on our hands or we may just have some bytes to relay
        """
        if not isBinary:
            raise ValueError(
                "All messages must be binary"
            )
        if self._first_message:
            self._first_message = False
            token = None
            old = re.search(br"^please relay (\w{64})$", payload)
            if old:
                token = old.group(1)
                self._state.please_relay(token)

            # new: "please relay {64} for side {16}\n"
            new = re.search(br"^please relay (\w{64}) for side (\w{16})$", payload)
            if new:
                token = new.group(1)
                side = new.group(2)
                self._state.please_relay_for_side(token, side)

            if token is None:
                self._state.bad_token()
        else:
            length = payload[0:4]
            print("enc record len: {}, payload len: {}".format(length, len(payload)))
            self._state.got_bytes(payload)

    def onClose(self, wasClean, code, reason):
        """
        IWebSocketChannel API
        """
        self._state.connection_lost()
