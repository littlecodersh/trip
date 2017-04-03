from socket import AF_INET, AF_UNSPEC

from tornado import gen
from tornado.tcpclient import TCPClient
from tornado.netutil import Resolver, OverrideResolver
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
            max_buffer_size=None):
        super(HTTPAdapter, self).__init__()
        self.resolver = Resolver()
        if hostname_mapping is not None:
            self.resolver = OverrideResolver(resolver=self.resolver,
                mapping=hostname_mapping)
        self.tcp_client = TCPClient(resolver=self.resolver)

    @gen.coroutine
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
        steam = yield self.tcp_client.connect(host, port, af=af,
                                    ssl_options=ssl_options,
                                    max_buffer_size=self.max_buffer_size,
                                    callback=self._on_connect)

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
