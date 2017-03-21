from tornado.tcpclient import TCPClient
from tornado.netutil import Resolver
from tornado.httputil import RequestStartLine

from requests.adapters import BaseAdapter
from requests.models import PreparedRequest

pr = PreparedRequest()

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

    Usage::

      >>> import trip
      >>> s = trip.Session()
      >>> a = trip.adapters.HTTPAdapter(max_retries=3)
      >>> s.mount('http://', a)
    """
    def __init__(self, io_loop=None):
        super(HTTPAdapter, self).__init__()
        self.tcp_client = TCPClient(resolver=Resolver(io_loop=io_loop), io_loop=io_loop)
    def send(self, request, stream=False, timeout=None, verify=True,
             cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param verify: (optional) Whether to verify SSL certificates.
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
        pass
    def close(self):
        """Cleans up adapter specific items."""
        pass

class _Connection(object):
    def __init__(self, prepared_request, io_loop, final_callback, tcp_client):
        self.request = prepared_request
        self.io_loop = io_loop
        self.final_callback = final_callback
        self.tcp_client = tcp_client

        port = 443 if self.request.url.startswith('https') else 80
        af = socket.AF_INET
        # if request.allow_ipv6 is False:
        #     af = socket.AF_INET
        # else:
        #     af = socket.AF_UNSPEC

        self.tcp_client.connect(self.request.url, port, af=af,
            callback=self._on_connect)
    def _on_connect(self, stream):
        pass
