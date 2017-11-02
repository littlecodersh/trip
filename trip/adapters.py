"""
trip.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Trip uses to define
and maintain connections.

The following is the connections between Trip and Tornado:
    simple_httpclient.SimpleAsyncHTTPClient -> HTTPAdapter
    simple_httpclient._HTTPConnection       -> HTTPAdapter
    http1connection.HTTP1Connection         -> HTTPConnection
    
"""

import os, sys, functools
from io import BytesIO

from tornado import gen, stack_context
from tornado.concurrent import Future
from tornado.http1connection import (
    HTTP1Connection, HTTP1ConnectionParameters,
    _ExceptionLoggingContext, _GzipMessageDelegate)
from tornado.httputil import HTTPMessageDelegate, HTTPInputError, parse_response_start_line
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.log import app_log, gen_log
from tornado.netutil import Resolver, OverrideResolver
from tornado.tcpclient import TCPClient

from requests.adapters import BaseAdapter
from requests.compat import urlsplit
from requests.exceptions import Timeout, HTTPError
from requests.utils import DEFAULT_CA_BUNDLE_PATH


class HTTPAdapter(BaseAdapter):
    """The built-in HTTP Adapter for BaseIOStream.

    Provides a general-case interface for trip sessions to contact HTTP urls
    by implementing the Transport Adapter interface. This class will
    usually be created by the :class:`Session <Session>` class under the
    covers.

    :param max_retries: The maximum number of retries each connection
        should attempt. Note, this applies only to failed DNS lookups, socket
        connections and connection timeouts, never to requests where data has
        made it to the server. By default, Requests does not retry failed
        connections.
        #TODO: If you need granular control over the conditions under
        which we retry a request, import urllib3's ``Retry`` class and pass
        that instead.

    Usage::

      >>> import trip
      >>> s = trip.Session()
      >>> a = trip.adapters.HTTPAdapter(hostname_mapping='/etc/hosts')
      >>> s.mount('http://', a)
    """

    def __init__(self, io_loop=None, hostname_mapping=None,
            max_buffer_size=104857600, max_header_size=None,
            max_body_size=None):
        super(HTTPAdapter, self).__init__()

        self.max_buffer_size = max_buffer_size
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.io_loop = io_loop or IOLoop.current()

        self.resolver = Resolver()
        if hostname_mapping is not None:
            self.resolver = OverrideResolver(resolver=self.resolver,
                mapping=hostname_mapping)

        self.tcp_client = TCPClient(resolver=self.resolver)

    @gen.coroutine
    def send(self, request, stream=False, timeout=None, verify=True,
             cert=None, proxies=None):
        """Sends Request object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param verify: (optional) Whether to verify SSL certificates.
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: trip.adapters.MessageDelegate
        """
        if isinstance(timeout, tuple):
            try:
                connect_timeout, read_timeout = timeout
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {0}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        else:
            connect_timeout, read_timeout = timeout, timeout

        timeout_reason = {}
        if connect_timeout:
            timeout_reason['reason'] = 'while connecting'
            self.io_loop.add_timeout(
                self.io_loop.time() + connect_timeout,
                stack_context.wrap(functools.partial(self._on_timeout, timeout_reason)))

        s = yield self.tcp_client.connect(
            request.host, request.port,
            af=request.af,
            ssl_options=self._get_ssl_options(request, verify, cert),
            max_buffer_size=self.max_buffer_size)

        if not timeout_reason or timeout_reason.get('reason'):
            s.set_nodelay(True)
            timeout_reason.clear()
        else:
            raise gen.Return(Timeout(
                timeout_reason.get('error', 'unknown'),
                request=request))

        connection = HTTPConnection(
            s,
            HTTP1ConnectionParameters(
                no_keep_alive=True,
                max_header_size=self.max_header_size,
                max_body_size=self.max_body_size,
                decompress=request.decompress))

        if read_timeout:
            timeout_reason['reason'] = 'during request'
            self.io_loop.add_timeout(
                self.io_loop.time() + connect_timeout,
                stack_context.wrap(functools.partial(self._on_timeout, timeout_reason)))

        connection.write_headers(request.start_line, request.headers)
        if request.body is not None:
            connection.write(request.body) #TODO: partial sending
        connection.finish()

        future = Future()
        def handle_response(response):
            if isinstance(response, Exception):
                future.set_exception(response)
            else:
                future.set_result(response)
        resp = MessageDelegate(request, connection, handle_response, stream)

        headers_received = yield connection.read_headers(resp)

        if not stream and headers_received:
            yield connection.read_body(resp)

        if not timeout_reason or timeout_reason.get('reason'):
            timeout_reason.clear()
            resp = yield future
            raise gen.Return(resp)
        else:
            raise gen.Return(Timeout(
                timeout_reason.get('error', 'unknown'),
                request=request))

    def _get_ssl_options(self, req, verify, cert):
        if urlsplit(req.url).scheme == "https":
            # If we are using the defaults, don't construct a new SSLContext.
            if req.ssl_options is not None:
                return req.ssl_options
            # deal with verify & cert
            ssl_options = {}

            if verify:
                cert_loc = None

                # Allow self-specified cert location.
                if verify is not True:
                    cert_loc = verify

                if not cert_loc:
                    cert_loc = DEFAULT_CA_BUNDLE_PATH

                if not cert_loc or not os.path.exists(cert_loc):
                    raise IOError("Could not find a suitable TLS CA certificate bundle, "
                                  "invalid path: {0}".format(cert_loc))

                # you may change this to avoid server's certificate check
                ssl_options["cert_reqs"] = 2 # ssl.CERT_REQUIRED
                ssl_options["ca_certs"] = cert_loc

            if cert:
                if not isinstance(cert, basestring):
                    cert_file = cert[0]
                    key_file = cert[1]
                else:
                    cert_file = cert
                    key_file = None

                if cert_file and not os.path.exists(cert_file):
                    raise IOError("Could not find the TLS certificate file, "
                                  "invalid path: {0}".format(conn.cert_file))
                if key_file and not os.path.exists(key_file):
                    raise IOError("Could not find the TLS key file, "
                                  "invalid path: {0}".format(conn.key_file))

                if key_file is not None:
                    ssl_options["keyfile"] = key_file
                if cert_file is not None:
                    ssl_options["certfile"] = cert_file

            # SSL interoperability is tricky.  We want to disable
            # SSLv2 for security reasons; it wasn't disabled by default
            # until openssl 1.0.  The best way to do this is to use
            # the SSL_OP_NO_SSLv2, but that wasn't exposed to python
            # until 3.2.  Python 2.7 adds the ciphers argument, which
            # can also be used to disable SSLv2.  As a last resort
            # on python 2.6, we set ssl_version to TLSv1.  This is
            # more narrow than we'd like since it also breaks
            # compatibility with servers configured for SSLv3 only,
            # but nearly all servers support both SSLv3 and TLSv1:
            # http://blog.ivanristic.com/2011/09/ssl-survey-protocol-support.html
            if (2, 7) <= sys.version_info:
                # In addition to disabling SSLv2, we also exclude certain
                # classes of insecure ciphers.
                ssl_options["ciphers"] = "DEFAULT:!SSLv2:!EXPORT:!DES"
            else:
                # This is really only necessary for pre-1.0 versions
                # of openssl, but python 2.6 doesn't expose version
                # information.
                ssl_options["ssl_version"] = 3 # ssl.PROTOCOL_TLSv1
            return ssl_options
        return None

    def _on_timeout(self, info=None):
        """Timeout callback.

        Raise a timeout HTTPError when a timeout occurs.

        :info string key: More detailed timeout information.
        """
        if info:
            reason = info.get('reason', 'unknown')
            info.clear()
            info['error'] = 'Timeout {0}'.format(reason)

    def close(self):
        """Cleans up adapter specific items."""
        pass


class HTTPConnection(HTTP1Connection):
    """Implements the HTTP/1.x protocol.
    """

    def __init__(self, stream, params=None):
        HTTP1Connection.__init__(self, stream, True, params)

    def _parse_delegate(self, delegate):
        if self.params.decompress:
            return delegate, _GzipMessageDelegate(delegate, self.params.chunk_size)
        return delegate, delegate

    @gen.coroutine
    def read_headers(self, delegate):
        try:
            _delegate, delegate = self._parse_delegate(delegate)
            header_future = self.stream.read_until_regex(
                b"\r?\n\r?\n",
                max_bytes=self.params.max_header_size)
            if self.params.header_timeout is None:
                header_data = yield header_future
            else:
                try:
                    header_data = yield gen.with_timeout(
                        self.stream.io_loop.time() + self.params.header_timeout,
                        header_future,
                        quiet_exceptions=StreamClosedError)
                except gen.TimeoutError:
                    self.close()
                    raise gen.Return(False)
            start_line, headers = self._parse_headers(header_data)

            start_line = parse_response_start_line(start_line)
            self._response_start_line = start_line

            self._disconnect_on_finish = not self._can_keep_alive(
                start_line, headers)

            with _ExceptionLoggingContext(app_log):
                header_future = delegate.headers_received(start_line, headers)
                if header_future is not None:
                    yield header_future
            if self.stream is None:
                # We've been detached.
                raise gen.Return(False)

            # determine body skip
            #TODO: 100 <= code < 200
            if (self._request_start_line is not None and
                    self._request_start_line.method == 'HEAD'):
                _delegate.skip_body = True
            code = start_line.code
            if code == 304:
                # 304 responses may include the content-length header
                # but do not actually have a body.
                # http://tools.ietf.org/html/rfc7230#section-3.3
                _delegate.skip_body = True
            if code >= 100 and code < 200:
                # 1xx responses should never indicate the presence of
                # a body.
                if ('Content-Length' in headers or
                        'Transfer-Encoding' in headers):
                    raise HTTPInputError(
                        "Response code %d cannot have body" % code)
                # TODO: client delegates will get headers_received twice
                # in the case of a 100-continue.  Document or change?
                yield self.read_headers(delegate)

            # return the response with no body set
            with _ExceptionLoggingContext(app_log):
                delegate.finish()
        except HTTPInputError as e:
            gen_log.info("Malformed HTTP message from %s: %s",
                         self.context, e)
            self.close()

            self._clear_callbacks()

            raise gen.Return(False)
        finally:
            header_future = None
        raise gen.Return(True)

    @gen.coroutine
    def read_body(self, delegate):
        _delegate, delegate = self._parse_delegate(delegate)
        need_delegate_close = True

        if not _delegate.skip_body:
            try:
                body_future = self._read_body(
                    _delegate.code, _delegate.headers, delegate)
                if body_future is not None:
                    if self._body_timeout is None:
                        yield body_future
                    else:
                        try:
                            yield gen.with_timeout(
                                self.stream.io_loop.time() + self._body_timeout,
                                body_future,
                                quiet_exceptions=StreamClosedError)
                        except gen.TimeoutError:
                            gen_log.info("Timeout reading body from %s",
                                         self.context)
                            self.stream.close()
                            raise gen.Return(False)

                self._read_finished = True
                need_delegate_close = False

                # If we're waiting for the application to produce an asynchronous
                # response, and we're not detached, register a close callback
                # on the stream (we didn't need one while we were reading)
                if (not self._finish_future.done() and
                        self.stream is not None and
                        not self.stream.closed()):
                    self.stream.set_close_callback(self._on_connection_close)
                    yield self._finish_future
                if self._disconnect_on_finish:
                    self.close()
                if self.stream is None:
                    raise gen.Return(False)
            except HTTPInputError as e:
                gen_log.info("Malformed HTTP message from %s: %s",
                             self.context, e)
                self.close()
                raise gen.Return(False)
            finally:
                if need_delegate_close:
                    with _ExceptionLoggingContext(app_log):
                        delegate.on_connection_close(self.stream.error)
                self._clear_callbacks()
        raise gen.Return(True)

    @gen.coroutine
    def read_stream_body(self, delegate, chunk_size=1, stream_callback=None):
        _delegate, delegate = self._parse_delegate(delegate)
        remain_content = False
        need_delegate_close = True

        if not _delegate.skip_body:
            try:
                body_future = self._read_stream_body(chunk_size, delegate)
                if body_future is not None:
                    if self._body_timeout is None:
                        remain_content = yield body_future
                    else:
                        try:
                            remain_content = yield gen.with_timeout(
                                self.stream.io_loop.time() + self._body_timeout,
                                body_future,
                                quiet_exceptions=StreamClosedError)
                        except gen.TimeoutError:
                            gen_log.info("Timeout reading body from %s",
                                         self.context)
                            self.stream.close()
                            remain_content = False
                need_delegate_close = False

                if not remain_content:
                    self._read_finished = True
                    if (not self._finish_future.done() and
                            self.stream is not None and
                            not self.stream.closed()):
                        self.stream.set_close_callback(self._on_connection_close)
                        yield self._finish_future
                    if self._disconnect_on_finish:
                        self.close()
            except HTTPInputError as e:
                gen_log.info("Malformed HTTP message from %s: %s",
                             self.context, e)
                self.close()
                remain_content = False
            finally:
                if need_delegate_close:
                    with _ExceptionLoggingContext(app_log):
                        delegate.on_connection_close(self.stream.error)
                if not remain_content:
                    self._clear_callbacks()
        raise gen.Return(remain_content)

    @gen.coroutine
    def _read_stream_body(self, content_length, delegate):
        while 0 < content_length:
            try:
                body = yield self.stream.read_bytes(
                    min(self.params.chunk_size, content_length), partial=True)
            except StreamClosedError:
                # with partial stream will update close status after receiving
                # the last chunk, so we catch StreamClosedError instead
                raise gen.Return(False)
            content_length -= len(body)
            if not self._write_finished or self.is_client:
                with _ExceptionLoggingContext(app_log):
                    ret = delegate.data_received(body)
                    if ret is not None:
                        yield ret
        raise gen.Return(True)


class MessageDelegate(HTTPMessageDelegate):
    """ Message delegate.
    """

    def __init__(self, request, connection,
            final_callback, stream=False):
        self.code = None
        self.reason = None
        self.headers = None
        self.body = None
        self.chunks = []

        self.request = request
        self.connection = connection
        self.final_callback = final_callback
        self.stream = stream

        self.io_loop = IOLoop.current()

        self.skip_body = False

    def headers_received(self, start_line, headers):
        """Called when the HTTP headers have been received and parsed.

        :arg start_line: a `.RequestStartLine` or `.ResponseStartLine`
            depending on whether this is a client or server message.
        :arg headers: a `.HTTPHeaders` instance.

        Some `.HTTPConnection` methods can only be called during
        ``headers_received``.

        May return a `.Future`; if it does the body will not be read
        until it is done.
        """
        self.code = start_line.code
        self.reason = start_line.reason
        self.headers = headers

    def data_received(self, chunk):
        """Called when a chunk of data has been received.

        May return a `.Future` for flow control.
        """
        if self.body:
            self.body.write(chunk)
        else:
            self.chunks.append(chunk)

    def finish(self):
        """Called after the last chunk of data has been received."""
        data = b''.join(self.chunks)
        if self.stream:
            buffer_ = BytesIO()
        else:
            buffer_ = BytesIO(data)
        self.body = buffer_
        self._run_callback(self)

    def on_connection_close(self, error=None):
        """Called if the connection is closed without finishing the request.

        If ``headers_received`` is called, either ``finish`` or
        ``on_connection_close`` will be called, but not both.
        """
        message = "Connection closed"
        error = error or HTTPError(599, message)
        self._run_callback(error)

    def _run_callback(self, response):
        if self.final_callback is not None:
            final_callback = self.final_callback
            self.final_callback = None
            self.io_loop.add_callback(final_callback, response)
