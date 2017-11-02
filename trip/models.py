"""
trip.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power Trip.
"""

import codecs
import functools
import socket
from socket import AF_INET

from requests.models import (
    PreparedRequest as _PreparedRequest,
    Request as _Request, 
    Response as _Response,
    ITER_CHUNK_SIZE, CONTENT_CHUNK_SIZE)
from requests.compat import (
    urlparse, urlsplit, chardet,
    str as _str, json as complexjson)
from requests.cookies import _copy_cookie_jar
from requests.utils import (
    iter_slices, guess_json_utf, default_headers)
from requests.exceptions import StreamConsumedError

from tornado import gen, httputil, stack_context
from tornado.concurrent import Future
from tornado.httpclient import HTTPRequest
from tornado.httputil import (split_host_and_port,
    RequestStartLine, HTTPHeaders, HTTPMessageDelegate)
from tornado.gen import Return

from .utils import iter_slices_future


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
        self.headers = default_headers()
        self.ssl_options = None

        self.host = None
        self.port = None
        self.af = None
        self.decompress = None
        self.start_line = None

    def prepare(self,
            method=None, url=None, headers=None, files=None, data=None,
            params=None, auth=None, cookies=None, hooks=None, json=None):
        """Prepares the entire request with the given parameters."""

        _PreparedRequest.prepare(self, method, url, headers, files, data,
            params, auth, cookies, hooks, json)
        self.adapt_prepare()

    def adapt_prepare(self):
        """Prepares the special trip parameters."""

        parsed = urlsplit(self.url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Unsupported url scheme: %s' % self.url)
        netloc = parsed.netloc
        if '@' in netloc:
            userpass, _, netloc = netloc.rpartition('@')
        self.host, self.port = split_host_and_port(netloc)
        if self.port is None:
            self.port = 443 if parsed.scheme == 'https' else 80

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

    def copy(self):
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy() if self.headers is not None else None
        p._cookies = _copy_cookie_jar(self._cookies)
        p.body = self.body
        p.hooks = self.hooks
        p._body_position = self._body_position
        return p


class Response(_Response):
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.
    """
    
    def __init__(self):
        _Response.__init__(self)

    # @property
    # def is_redirect(self):
    # @property
    # def is_permanent_redirect(self):
    # @property
    # def next(self):

    @property
    def apparent_encoding(self):
        """The apparent encoding, provided by the chardet library."""
        def _encoding(content):
            return chardet.detect(content)['encoding']

        @gen.coroutine
        def _stream_apparent_encoding():
            content = yield self.content
            raise Return(_encoding(content))

        if not isinstance(self.raw, HTTPMessageDelegate):
            raise TypeError('self.raw must be a trip.adapters.MessageDelegate')

        if self.raw.stream:
            return _stream_apparent_encoding()
        else:
            return _encoding(self.content)

    @property
    def text(self):
        """Content of the response, in unicode.

        If Response.encoding is None, encoding will be guessed using
        ``chardet``.

        The encoding of the response content is determined based solely on HTTP
        headers, following RFC 2616 to the letter. If you can take advantage of
        non-HTTP knowledge to make a better guess at the encoding, you should
        set ``r.encoding`` appropriately before accessing this property.
        """

        def _unicode(content):
            result = None
            # Try charset from content-type
            encoding = self.encoding

            if not content:
                return _str('')

            # Fallback to auto-detected encoding.
            if self.encoding is None:
                encoding = chardet.detect(content)['encoding']

            # Decode unicode from given encoding.
            try:
                result = _str(content, encoding, errors='replace')
            except (LookupError, TypeError):
                # A LookupError is raised if the encoding was not found which could
                # indicate a misspelling or similar mistake.
                #
                # A TypeError can be raised if encoding is None
                #
                # So we try blindly encoding.
                result = _str(content, errors='replace')

            return result

        @gen.coroutine
        def _stream_text():
            content = yield self.content
            raise Return(_unicode(content))

        if not isinstance(self.raw, HTTPMessageDelegate):
            raise TypeError('self.raw must be a trip.adapters.MessageDelegate')

        if self.raw.stream:
            return _stream_text()
        else:
            return _unicode(self.content)

    def json(self, **kwargs):
        r"""Returns the json-encoded content of a response, if any.

        :param \*\*kwargs: Optional arguments that ``json.loads`` takes.
        :raises ValueError: If the response body does not contain valid json.
        """

        def _json(content, text):
            if not self.encoding and content and len(content) > 3:
                # No encoding set. JSON RFC 4627 section 3 states we should expect
                # UTF-8, -16 or -32. Detect which one to use; If the detection or
                # decoding fails, fall back to `self.text` (using chardet to make
                # a best guess).
                encoding = guess_json_utf(content)
                if encoding is not None:
                    try:
                        return complexjson.loads(
                            content.decode(encoding), **kwargs
                        )
                    except UnicodeDecodeError:
                        # Wrong UTF codec detected; usually because it's not UTF-8
                        # but some other 8-bit codec.  This is an RFC violation,
                        # and the server didn't bother to tell us what codec *was*
                        # used.
                        pass
            return complexjson.loads(text, **kwargs)

        @gen.coroutine
        def _stream_json():
            content = yield self.content
            text = yield self.text
            raise Return(_json(content, text))

        if not isinstance(self.raw, HTTPMessageDelegate):
            raise TypeError('self.raw must be a trip.adapters.MessageDelegate')

        if self.raw.stream:
            return _stream_json()
        else:
            return _json(self.content, self.text)

    def iter_content(self, chunk_size=1, decode_unicode=False):
        """Iterates over the response data.  When stream=True is set on the
        request, this avoids reading the content at once into memory for
        large responses.  The chunk size is the number of bytes it should
        read into memory.  This is not necessarily the length of each item
        returned as decoding can take place.

        chunk_size must be of type int or None. A value of None will
        function differently depending on the value of `stream`.
        stream=True will read data as it arrives in whatever size the
        chunks are received. If stream=False, data is returned as
        a single chunk.

        If decode_unicode is True, content will be decoded using the best
        available encoding based on the response.
        """

        def generate():
            decode = decode_unicode
            if self.encoding is None:
                decode = False
            if decode:
                decoder = codecs.getincrementaldecoder(
                    self.encoding)(errors='replace')

            if self.raw.stream:
                content_remain = {'': ''}
                while content_remain:
                    future = Future()

                    def callback(status):
                        chunk = self.raw.body.getvalue()
                        self.raw.body.truncate(0)
                        self.raw.body.seek(0)
                        if decode:
                            chunk = decoder.decode(chunk)
                        if not status:
                            content_remain.clear()
                        future.set_result(chunk)

                    self.raw.connection.read_stream_body(
                        self.raw, chunk_size, callback=callback)
                    yield future

                    while not future.done():
                        yield future
            else:
                self.raw.body.seek(0)
                while True:
                    chunk = self.raw.body.read(chunk_size)
                    if decode:
                        chunk = decoder.decode(chunk)
                    if not chunk:
                        break
                    else:
                        yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError('chunk_size must be an int, it is instead a %s.'
                % type(chunk_size))
        elif not isinstance(self.raw, HTTPMessageDelegate):
            raise TypeError('self.raw must be a trip.adapters.MessageDelegate')

        if self._content_consumed:
            # simulate reading small chunks of the content
            if self.raw.stream:
                return iter_slices_future(self, chunk_size, decode_unicode)
            else:
                return iter_slices(self._content, chunk_size)
        else:
            return generate()

    def iter_lines(self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=None, delimiter=None):
        """Iterates over the response data, one line at a time.  When
        stream=True is set on the request, this avoids reading the
        content at once into memory for large responses.

        .. note:: This method is not reentrant safe.
        """

        if getattr(self.raw, 'stream', False):
            return self._iter_stream_lines(chunk_size, decode_unicode, delimiter)
        else:
            return _Response.iter_lines(self, chunk_size, decode_unicode, delimiter)

    def _iter_stream_lines(self, chunk_size=ITER_CHUNK_SIZE,
            decode_unicode=None, delimiter=None):
        """ stream version of iter_lines.

        Basic Usage::

          >>> import trip
          >>> @trip.coroutine
          >>> def main():
          >>>     url = 'http://httpbin.org/get'
          >>>     r = yield trip.get(url, stream=True)
          >>>     for line in r.iter_lines(1):
          >>>         line = yield line
          >>>         if line is not None:
          >>>             print(line)
          >>> trip.IOLoop.current().run_sync(main)
          {
            "args": {},
            "headers": {}
            "origin": "0.0.0.0",
            "url": "http://httpbin.org/get"
          }
        """

        content = {'': []}
        pending = {'': None}

        def handle_content(f):

            chunk = f.result()

            if pending[''] is not None:
                chunk = pending[''] + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending[''] = lines.pop()
            else:
                pending[''] = None

            content[''] = lines[1:]
            f._result = lines[0] if lines else None

        for future in self.iter_content(chunk_size, decode_unicode):

            future.add_done_callback(handle_content)
            yield future

            for line in content['']:
                future = Future()
                future.set_result(line)
                yield future

        if pending[''] is not None:
            future = Future()
            future.set_result(pending[''])
            yield future

    @gen.coroutine
    def _get_stream_content(self):
        if self._content is False: # no content has been set
            chunks = []
            for chunk in self.iter_content(CONTENT_CHUNK_SIZE):
                chunk = yield chunk
                chunks.append(chunk)
            self._content = b''.join(chunks)
        raise gen.Return(self._content)

    @property
    def content(self):
        """ Content of the response.
        If stream is True, a trip.Future object will be returned.
        If stream is False, content will be returned in bytes.
        """

        if self._content is False:
            # Read the contents.
            if self._content_consumed:
                raise RuntimeError(
                    'The content for this response was already consumed')

            if self.status_code == 0 or self.raw is None:
                self._content = None
                self._content_consumed = True

            if not self.raw.stream:
                self._content = b''.join(self.iter_content(CONTENT_CHUNK_SIZE))

        if self.raw.stream:
            return self._get_stream_content()
        else:
            return self._content

    def close(self):
        pass
