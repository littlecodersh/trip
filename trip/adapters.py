"""
trips.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that Trip uses to define
and maintain connections.

The following is the connections between Trip and Tornado:
    simple_httpclient.SimpleAsyncHTTPClient -> HTTPAdapter
    simple_httpclient._HTTPConnection       -> HTTPAdapter
    http1connection.HTTP1Connection         -> HTTPConnection
    
"""

from io import BytesIO
from socket import AF_INET, AF_UNSPEC

from tornado import gen
from tornado.concurrent import Future
from tornado.http1connection import (
    HTTP1Connection, HTTP1ConnectionParameters,
    _ExceptionLoggingContext, _GzipMessageDelegate)
from tornado.httputil import (
    RequestStartLine, HTTPMessageDelegate,
    HTTPInputError, parse_response_start_line)
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.log import app_log, gen_log
from tornado.netutil import Resolver, OverrideResolver
from tornado.tcpclient import TCPClient

from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response
from requests.utils import get_encoding_from_headers


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
        s = yield self.tcp_client.connect(
            request.host, request.port,
            af=request.af,
            ssl_options=request.ssl_options,
            max_buffer_size=self.max_buffer_size)
        s.set_nodelay(True)

        connection = HTTPConnection(
            s,
            HTTP1ConnectionParameters(
                no_keep_alive=True,
                max_header_size=self.max_header_size,
                max_body_size=self.max_body_size,
                decompress=request.decompress))

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

        resp = yield future
        raise gen.Return(resp)

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
