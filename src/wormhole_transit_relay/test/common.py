from binascii import hexlify, unhexlify

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from twisted.internet.protocol import (
    ClientFactory,
    Protocol,
)
from twisted.test import iosim
from zope.interface import (
    Interface,
    Attribute,
    implementer,
)
from ..transit_server import (
    Transit,
    TransitConnection,
)
from twisted.internet.protocol import ServerFactory
from ..usage import create_usage_tracker


def handshake(token, side=None):
    """
    :param bytes token: 32 byte token
    :param bytes side: optional 8 byte side
    :returns bytes: data comprising the 'relay' portion of the
        handshake, with or without the side.
    """
    hs = b"please relay " + hexlify(token)
    if side is not None:
        hs += b" for side " + hexlify(side)
    hs += b"\n"
    return hs


def transit_handshake(key, role):
    """
    :param bytes key: 32 byte key
    :param str role: "sender" or "receiver"
    :returns bytes: data for the 'transit' portion of the handshake
        with one part of the key exchange
    """
    if role not in ("sender", "receiver"):
        raise ValueError("Unknown role '{}'".format(role))
    token = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=b"transit_receiver",
    ).derive(
        key,
    )

    return "transit {} {} ready\n\n".format(
        role,
        hexlify(token).decode("ascii"),
    ).encode("utf8")


class IRelayTestClient(Interface):
    """
    The client interface used by tests.
    """

    connected = Attribute("True if we are currently connected else False")

    def send(data):
        """
        Send some bytes.
        :param bytes data: the data to send
        """

    def disconnect():
        """
        Terminate the connection.
        """

    def get_received_data():
        """
        :returns: all the bytes received from the server on this
        connection.
        """

    def reset_data():
        """
        Erase any received data to this point.
        """


class ServerBase:
    log_requests = False

    def setUp(self):
        self._pumps = []
        self._lp = None
        if self.log_requests:
            blur_usage = None
        else:
            blur_usage = 60.0
        self._setup_relay(blur_usage=blur_usage)

    def flush(self):
        did_work = False
        for pump in self._pumps:
            did_work = pump.flush() or did_work
        if did_work:
            self.flush()

    def _setup_relay(self, blur_usage=None, log_file=None, usage_db=None):
        usage = create_usage_tracker(
            blur_usage=blur_usage,
            log_file=log_file,
            usage_db=usage_db,
        )
        self._transit_server = Transit(usage, lambda: 123456789.0)

    def new_protocol(self):
        """
        This should be overridden by derived test-case classes to decide
        if they want a TCP or WebSockets protocol.
        """
        raise NotImplementedError()

    def new_protocol_tcp(self):
        """
        Create a new client protocol connected to the server.
        :returns: a IRelayTestClient implementation
        """
        server_factory = ServerFactory()
        server_factory.protocol = TransitConnection
        server_factory.transit = self._transit_server
        server_factory.log_requests = self.log_requests
        server_protocol = server_factory.buildProtocol(('127.0.0.1', 0))

        @implementer(IRelayTestClient)
        class TransitClientProtocolTcp(Protocol):
            """
            Speak the transit client protocol used by the tests over TCP
            """
            _received = b""
            connected = False

            # override Protocol callbacks

            def connectionMade(self):
                self.connected = True
                return Protocol.connectionMade(self)

            def connectionLost(self, reason):
                self.connected = False
                return Protocol.connectionLost(self, reason)

            def dataReceived(self, data):
                self._received = self._received + data

            # IRelayTestClient

            def send(self, data):
                self.transport.write(data)

            def disconnect(self):
                self.transport.loseConnection()

            def reset_received_data(self):
                self._received = b""

            def get_received_data(self):
                return self._received

        client_factory = ClientFactory()
        client_factory.protocol = TransitClientProtocolTcp
        client_protocol = client_factory.buildProtocol(('127.0.0.1', 31337))

        pump = iosim.connect(
            server_protocol,
            iosim.makeFakeServer(server_protocol),
            client_protocol,
            iosim.makeFakeClient(client_protocol),
        )
        pump.flush()
        self._pumps.append(pump)
        return client_protocol

    def tearDown(self):
        if self._lp:
            return self._lp.stopListening()
