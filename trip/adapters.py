from io import BytesIO
from socket import AF_INET, AF_UNSPEC

from tornado import gen
from tornado.concurrent import TracebackFuture
from tornado.http1connection import (
    HTTP1Connection, HTTP1ConnectionParameters,
    _ExceptionLoggingContext)
from tornado.httputil import (
    RequestStartLine, HTTPMessageDelegate,
    HTTPInputError, parse_response_start_line)
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.log import app_log
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

        connection = HTTP1Connection(
            s, True,
            HTTP1ConnectionParameters(
                no_keep_alive=True,
                max_header_size=self.max_header_size,
                max_body_size=self.max_body_size,
                decompress=request.decompress))

        connection.write_headers(request.start_line, request.headers)
        if request.body is not None:
            connection.write(request.body)
        connection.finish()

        future = TracebackFuture()
        def handle_response(response):
            # if raise_error and response.error:
            #     future.set_exception(response.error)
            # else:
            #     future.set_result(response)
            future.set_result(response)
        resp = MessageDelegate(request, handle_response)
        connection.read_response(resp)
        yield future # body is automatically set in resp

        raise gen.Return(resp)

    def close(self):
        """Cleans up adapter specific items."""
        pass

class HTTPConnection(HTTP1Connection):
    """Implements the HTTP/1.x protocol.
    """

    def __init__(self, stream, params=None):
        HTTP1Connection.__init__(self, stream, True, params)

    @gen.coroutine
    def _read_message(self, delegate):
        need_delegate_close = False
        try:
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
            need_delegate_close = True
            with _ExceptionLoggingContext(app_log):
                header_future = delegate.headers_received(start_line, headers)
                if header_future is not None:
                    yield header_future
            if self.stream is None:
                # We've been detached.
                need_delegate_close = False
                raise gen.Return(False)
            skip_body = False

            if (self._request_start_line is not None and
                    self._request_start_line.method == 'HEAD'):
                skip_body = True
            code = start_line.code
            if code == 304:
                # 304 responses may include the content-length header
                # but do not actually have a body.
                # http://tools.ietf.org/html/rfc7230#section-3.3
                skip_body = True
            if code >= 100 and code < 200:
                # 1xx responses should never indicate the presence of
                # a body.
                if ('Content-Length' in headers or
                        'Transfer-Encoding' in headers):
                    raise HTTPInputError(
                        "Response code %d cannot have body" % code)
                # TODO: client delegates will get headers_received twice
                # in the case of a 100-continue.  Document or change?
                yield self._read_message(delegate)

            if not skip_body:
                body_future = self._read_body(
                    start_line.code, headers, delegate)
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
            with _ExceptionLoggingContext(app_log):
                delegate.finish()
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
                    delegate.on_connection_close()
            header_future = None
            self._clear_callbacks()
        raise gen.Return(True)


class MessageDelegate(HTTPMessageDelegate):
    """ Message delegate.
    """

    def __init__(self, request, final_callback):
        self.code = None
        self.reason = None
        self.headers = None
        self.data = None
        self.chunks = []

        self.request = request
        self.final_callback = final_callback

        self.io_loop = IOLoop.current()

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
        self.chunks.append(chunk)

    def finish(self):
        """Called after the last chunk of data has been received."""
        data = b''.join(self.chunks)
        if self.request.stream:
            buffer_ = BytesIO()
        else:
            buffer_ = BytesIO(data)
        self.body = buffer_
        self.io_loop.add_callback(self.final_callback, buffer_)

    def on_connection_close(self):
        """Called if the connection is closed without finishing the request.

        If ``headers_received`` is called, either ``finish`` or
        ``on_connection_close`` will be called, but not both.
        """
        pass
