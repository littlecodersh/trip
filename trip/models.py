from socket import AF_INET, AF_UNSPEC

from requests.models import (
    PreparedRequest as _PreparedRequest,
    Request as _Request, 
    Response as _Response)
from requests.compat import urlparse, urlsplit

from tornado.httpclient import HTTPRequest
from tornado.httputil import (split_host_and_port,
    RequestStartLine, HTTPHeaders)


class Request(_Request):
    """A user-created :class:`Request <Request>` object.

    Used to prepare a :class:`PreparedRequest <PreparedRequest>`, which is sent to the server.

    :param method: HTTP method to use.
    :param url: URL to send.
    :param headers: dictionary of headers to send.
    :param files: dictionary of {filename: fileobject} files to multipart upload.
    :param data: the body to attach to the request. If a dictionary is provided, form-encoding will take place.
    :param json: json for the body to attach to the request (if files or data is not specified).
    :param params: dictionary of URL parameters to append to the URL.
    :param auth: Auth handler or (user, pass) tuple.
    :param cookies: dictionary or CookieJar of cookies to attach to this request.
    # :param hooks: dictionary of callback hooks, for internal usage.

    Usage::

      >>> import trip
      >>> req = trip.Request('GET', 'http://httpbin.org/get')
      >>> req.prepare()
      <PreparedRequest [GET]>
    """

    def __init__(self,
            method=None, url=None, headers=None, files=None, data=None,
            params=None, auth=None, cookies=None, hooks=None, json=None,
            request=None):
        if isinstance(request, HTTPRequest):
            request = self._transform_tornado_request(request)
        elif not isinstance(request, _Request):
            request = None
        _Request.__init__(self,
            method  = method or getattr(request, 'method', None),
            url     = url or getattr(request, 'url', None),
            headers = headers or getattr(request, 'headers', None),
            files   = files or getattr(request, 'files', None),
            data    = data or getattr(request, 'data', None),
            params  = params or getattr(request, 'params', None),
            auth    = auth or getattr(request, 'auth', None),
            cookies = cookies or getattr(request, 'cookies', None),
            hooks   = hooks or getattr(request, 'hooks', None),
            json    = json or getattr(request, 'json', None))

    def prepare(self):
        """Constructs a :class:`PreparedRequest <PreparedRequest>`.

        PreparedRequest is actually for transmission and combines
        one to one to a single actual request
        """
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p

    def _transform_tornado_request(self, request):
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


class PreparedRequest(_PreparedRequest):
    """The fully mutable :class:`PreparedRequest <PreparedRequest>` object,
    containing the exact bytes that will be sent to the server and combine
    one to one to a single actual request

    Generated from either a :class:`Request <Request>` object or manually.
    The only difference matters is param headers is a
    `tornado.httputil.HTTPHeaders` object.

    Usage::

      >>> import trip
      >>> req = trip.Request('GET', 'http://httpbin.org/get')
      >>> r = req.prepare()
      <PreparedRequest [GET]>

      >>> s = trip.Session()
      >>> s.send(r)
      <Response [200]>
    """
    def __init__(self):
        _PreparedRequest.__init__(self)
        self.host = None
        self.port = None
        self.ssl_options = None
        self.af = None
        self.decompress = None
        self.start_line = None
        self.headers = None
        self.body = None

    def prepare(self,
            method=None, url=None, headers=None, files=None, data=None,
            params=None, auth=None, cookies=None, hooks=None, json=None):
        """Prepares the entire request with the given parameters."""

        _PreparedRequest.prepare(self, method, url, headers, files, data,
            params, auth, cookies, hooks, json)

        parsed = urlsplit(self.url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Unsupported url scheme: %s' % self.url)
        netloc = parsed.netloc
        if '@' in netloc:
            userpass, _, netloc = netloc.rpartition('@')
        self.host, self.port = split_host_and_port(netloc)
        if self.port is None:
            self.port = 443 if parsed.scheme == 'https' else 80

        self.ssl_options = None

        self.af = AF_INET

        self.decompress = 'gzip' in \
            self.headers.get('Accept-Encoding', '')

        req_path = ((parsed.path or '/') +
            (('?' + parsed.query) if parsed.query else ''))
        self.start_line = RequestStartLine(self.method, req_path, '')

        self.headers = HTTPHeaders(self.headers)

        if 'Connection' not in self.headers:
            self.headers['Connection'] = 'close'
        if 'Host' not in self.headers:
            self.headers['Host'] = self.host


class Response(_Response):
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.
    """
    
    def __init__(self):
        _Response.__init__(self)
