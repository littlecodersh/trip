import socket, struct
from functools import partial

from tornado import gen
from tornado.concurrent import run_on_executor
from tornado.netutil import ExecutorResolver as _Resolver
from tornado.iostream import BaseIOStream, IOStream

SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: ("Request rejected because SOCKS server cannot connect to identd on"
           " the client"),
    0x5D: ("Request rejected because the client program and identd report"
           " different user-ids")
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

GeneralProxyError = SOCKS5AuthError = SOCKS5Error = Exception


class SockIOStream(IOStream):
    def __init__(self, proxy_settings):
        BaseIOStream.__init__(self)
        self.proxy_settings = proxy_settings
        self.socket = None
        self.resolver = Resolver()
        self.peername = self.sockname = None

    @gen.coroutine
    def connect(self, host, port):
        err = None
        proxy_type, rdns, ph, pp, username, password = self.proxy_settings
        rl = yield self.resolver.resolve(ph, pp, 0)
        for r in rl:
            family, socket_type, proto, canonname, sa = r
            sock = None
            try:
                if socket_type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    msg = 'Socket type must be stream or datagram, not {!r}'
                    raise ValueError(msg.format(type))
                elif socket_type == socket.SOCK_DGRAM:
                    raise ValueError('SOCK_DGRAM is not supported for now.')
                self.socket = socket.socket(family, socket_type, proto)
                self.socket.setblocking(False)
                super(SockIOStream, self).connect((ph, pp))
                if proxy_type == 2:
                    yield self._negotiate_socks5(host, port)
                else:
                    raise socket.error('Unknown proxy_type')
                raise gen.Return(self)
            except socket.error as e:
                err = e
                if self.socket:
                    self.socket.close()
                    self.socket = None

        if err:
            raise err
        raise socket.error("gai returned empty list.")

    def _negotiate_socks5(self, host, port):
        """Negotiates a stream connection through a SOCKS5 server."""
        connect_cmd = b"\x01"
        # self.peername, self.sockname
        return self._socks5_request(self, connect_cmd, (host, port))

    @gen.coroutine
    def _socks5_request(self, conn, cmd, dst):
        proxy_type, rdns, host, port, username, password = self.proxy_settings
        if username and password:
            yield self.write(b"\x05\x02\x00\x02")
        else:
            yield self.write(b"\x05\x01\x00")

        chosen_auth = yield self.read_bytes(2)

        if chosen_auth[0:1] != b"\x05":
            raise GeneralProxyError(
                "SOCKS5 proxy server sent invalid data")

        if chosen_auth[1:2] == b"\x02":
            yield self.write(b"\x01" + chr(len(username)).encode()
                         + username
                         + chr(len(password)).encode()
                         + password)
            auth_status = yield self.read_bytes(2)
            if auth_status[0:1] != b"\x01":
                raise GeneralProxyError(
                    "SOCKS5 proxy server sent invalid data")
            if auth_status[1:2] != b"\x00":
                raise SOCKS5AuthError("SOCKS5 authentication failed")
        elif chosen_auth[1:2] != b"\x00":
            if chosen_auth[1:2] == b"\xFF":
                raise SOCKS5AuthError(
                    "All offered SOCKS5 authentication methods were"
                    " rejected")
            else:
                raise GeneralProxyError(
                    "SOCKS5 proxy server sent invalid data")

        yield self.write(b"\x05" + cmd + b"\x00")
        resolved = yield self._write_socks5_address(dst)

        resp = yield self.read_bytes(3)
        if resp[0:1] != b"\x05":
            raise GeneralProxyError(
                "SOCKS5 proxy server sent invalid data")

        status = ord(resp[1:2])
        if status != 0x00:
            # Connection failed: server returned an error
            error = SOCKS5_ERRORS.get(status, "Unknown error")
            raise SOCKS5Error("{0:#04x}: {1}".format(status, error))

        bnd = yield self._read_socks5_address()

        raise gen.Return((resolved, bnd))

    @gen.coroutine
    def _write_socks5_address(self, addr):
        host, port = addr
        proxy_type, rdns, _, _, username, password = self.proxy_settings
        family_to_byte = {socket.AF_INET: b"\x01", socket.AF_INET6: b"\x04"}

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addr_bytes = socket.inet_pton(family, host)
                yield self.write(family_to_byte[family] + addr_bytes)
                host = socket.inet_ntop(family, addr_bytes)
                yield self.write(struct.pack(">H", port))
                raise gen.Return((host, port))
            except socket.error:
                continue

        if rdns:
            host_bytes = host.encode("idna")
            yield self.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
        else:
            addresses = yield self.resolver.getaddrinfo(host, port, socket.AF_UNSPEC,
                                           socket.SOCK_STREAM,
                                           socket.IPPROTO_TCP,
                                           socket.AI_ADDRCONFIG)

            target_addr = addresses[0]
            family = target_addr[0]
            host = target_addr[4][0]

            addr_bytes = socket.inet_pton(family, host)
            yield self.write(family_to_byte[family] + addr_bytes)
            host = socket.inet_ntop(family, addr_bytes)
        yield self.write(struct.pack(">H", port))
        raise gen.Return((host, port))

    @gen.coroutine
    def _read_socks5_address(self):
        atyp = yield self.read_bytes(1)
        if atyp == b"\x01":
            data = yield self.read_bytes(4)
            addr = socket.inet_ntoa(data)
        elif atyp == b"\x03":
            length = yield self.read_bytes(1)
            addr = yield self.read_bytes(length)
        elif atyp == b"\x04":
            data = yield self.read_bytes(16)
            addr = socket.inet_ntop(socket.AF_INET6, data)
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

        data = yield self.read_bytes(2)
        port = struct.unpack(">H", data)[0]
        raise gen.Return((addr, port))

    def close(self, exc_info=False):
        self.resolver.close()
        self.resolver = None
        super(IOStream, self).close(exc_info)


class Resolver(_Resolver):
    @run_on_executor
    def resolve(self, host, port, family=socket.AF_UNSPEC):
        return socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)

    def __getattr__(self, name):
        if name in ('getaddrinfo',):
            return partial(self._execute, getattr(socket, name))
        else:
            raise AttributeError('%s object has no attribute %s' % (self.__class__.__name__, name))

    @run_on_executor
    def _execute(self, fn, *args, **kwargs):
        return fn(*args, **kwargs)
