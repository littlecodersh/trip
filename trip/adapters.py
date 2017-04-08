from socket import AF_INET, AF_UNSPEC

from tornado import gen
from tornado.concurrent import TracebackFuture
from tornado.http1connection import (
    HTTP1Connection, HTTP1ConnectionParameters)
from tornado.httputil import (
    RequestStartLine, HTTPMessageDelegate)
from tornado.ioloop import IOLoop
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
        resp = MessageDelegate(handle_response)
        connection.read_response(resp)
        yield future # body is automatically set in resp

        raise gen.Return(resp)

    def close(self):
        """Cleans up adapter specific items."""
        pass



class MessageDelegate(HTTPMessageDelegate):
    """ Message delegate.
    """

    def __init__(self, final_callback):
        self.code = None
        self.reason = None
        self.headers = None
        self.data = None
        self.chunks = []
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
        self.body = data
        self.io_loop.add_callback(self.final_callback, data)

    def on_connection_close(self):
        """Called if the connection is closed without finishing the request.

        If ``headers_received`` is called, either ``finish`` or
        ``on_connection_close`` will be called, but not both.
        """
        pass
