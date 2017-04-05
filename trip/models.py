from socket import AF_INET, AF_UNSPEC

from requests.models import PreparedRequest
from requests.compat import urlparse, urlsplit

from tornado.httpclient import HTTPRequest
from tornado.httputil import (split_host_and_port,
    RequestStartLine, HTTPHeaders)


class Request(object):
    """A user-created :class:`Request <Request>` object.

    :param rRequest: PreparedRequest from requests package.
    :param tRequest: HTTPRequest instance from tornado package.

    Usage::

      >>> import requests, trip
      >>> req = trip.models.Request(requests.Request('GET', 'http://httpbin.org/get'))
      <Request [GET]>
    """

    def __init__(self, rRequest=None, tRequest=None):
        """
        host, port
        """
        self.host = None
        self.port = None
        self.ssl_options = None
        self.decompress = None
        self.start_line = None
        self.headers = None
        self.body = None

        if bool(rRequest) == bool(tRequest): # xor
            raise ValueError('Either rRequest or tRequest should be provided.')
        elif rRequest is not None:
            self._init_with_r_request(rRequest)
        else:
            self._init_with_t_request(tRequest)

    def _init_with_r_request(self, request):
        if not isinstance(request, PreparedRequest):
            raise ValueError('param rRequest should be \
                PreparedRequest from requests package.')
        parsed = urlsplit(request.url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Unsupported url scheme: %s' % request.url)
        netloc = parsed.netloc
        if '@' in netloc:
            userpass, _, netloc = netloc.rpartition('@')
        self.host, self.port = split_host_and_port(netloc)
        if self.port is None:
            self.port = 443 if parsed.scheme == 'https' else 80
        self.ssl_options = None
        self.af = AF_INET
        self.decompress = 'gzip' in \
            request.headers.get('Accept-Encoding', '')
        req_path = ((parsed.path or '/') +
            (('?' + parsed.query) if parsed.query else ''))
        self.start_line = RequestStartLine(request.method, req_path, '')
        self.headers = HTTPHeaders(request.headers)
        if 'Connection' not in self.headers:
            self.headers['Connection'] = 'close'
        if 'Host' not in self.headers:
            self.headers['Host'] = self.host
        self.body = request.body

    def _init_with_t_request(self, request):
        if isinstance(request, HTTPRequest):
            raise ValueError('param tRequest should be \
                HTTPRequest instance from tornado package.')

        # from tornado.simple_httpclient L214-L242
        self.parsed = urlparse.urlsplit(_unicode(self.request.url))
        if self.parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported url scheme: %s" %
                             self.request.url)
        # urlsplit results have hostname and port results, but they
        # didn't support ipv6 literals until python 2.7.
        netloc = self.parsed.netloc
        if "@" in netloc:
            userpass, _, netloc = netloc.rpartition("@")
        host, port = httputil.split_host_and_port(netloc)
        if port is None:
            port = 443 if self.parsed.scheme == "https" else 80
        if re.match(r'^\[.*\]$', host):
            # raw ipv6 addresses in urls are enclosed in brackets
            host = host[1:-1]
        self.parsed_hostname = host  # save final host for _on_connect

        if request.allow_ipv6 is False:
            af = socket.AF_INET
        else:
            af = socket.AF_UNSPEC

        ssl_options = self._get_ssl_options(self.parsed.scheme)

        timeout = min(self.request.connect_timeout, self.request.request_timeout)
        if timeout:
            self._timeout = self.io_loop.add_timeout(
                self.start_time + timeout,
                stack_context.wrap(functools.partial(self._on_timeout, "while connecting")))


class Response(object):
    pass
