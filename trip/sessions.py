"""
trip.session
~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
trip (cookies, auth, proxies).
"""

from datetime import timedelta

import requests
from requests.auth import _basic_auth_str
from requests.compat import (cookielib, urljoin, urlparse)
from requests.cookies import (
    cookiejar_from_dict, merge_cookies, RequestsCookieJar,
    MockRequest, MockResponse)
from requests.exceptions import TooManyRedirects
from requests.hooks import default_hooks, dispatch_hook
from requests.models import DEFAULT_REDIRECT_LIMIT
from requests.sessions import (
    SessionRedirectMixin as _SessionRedirectMixin,
    merge_hooks, merge_setting,
    preferred_clock)
from requests.status_codes import codes
from requests.structures import CaseInsensitiveDict
from requests.utils import (
    get_auth_from_url, get_encoding_from_headers,
    requote_uri, should_bypass_proxies)
from requests._internal_utils import to_native_string
from urllib3._collections import HTTPHeaderDict

from tornado import gen
from tornado.concurrent import Future

from .adapters import HTTPAdapter
from .models import PreparedRequest, Request, Response
from .utils import default_headers


class SessionRedirectMixin(_SessionRedirectMixin):
    """Session redirect mix in.  """

    def resolve_redirects(self, resp, req, stream=False, timeout=None,
                          verify=True, cert=None, proxies=None, yield_requests=False, **adapter_kwargs):
        """Receives a Response. Returns a generator of Responses or Requests."""

        hist = []  # keep track of history

        url = self.get_redirect_target(resp)
        while url:
            prepared_request = req.copy()

            # Update history and keep track of redirects.
            # resp.history must ignore the original request in this loop
            hist.append(resp)
            resp.history = hist[1:]

            # Consume socket so it can be released
            resp.content

            if self.max_redirects <= len(resp.history):
                raise TooManyRedirects('Exceeded %s redirects.' % self.max_redirects, response=resp)

            # Release the connection
            resp.close()

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith('//'):
                parsed_rurl = urlparse(resp.url)
                url = '%s:%s' % (to_native_string(parsed_rurl.scheme), url)

            # The scheme should be lower case...
            parsed = urlparse(url)
            url = parsed.geturl()

            # Facilitate relative 'location' headers, as allowed by RFC 7231.
            # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
            # Compliant with RFC3986, we percent encode the url.
            if not parsed.netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)

            prepared_request.url = to_native_string(url)

            self.rebuild_method(prepared_request, resp)

            # https://github.com/requests/requests/issues/1084
            if resp.status_code not in (codes.temporary_redirect, codes.permanent_redirect):
                # https://github.com/requests/requests/issues/3490
                purged_headers = ('Content-Length', 'Content-Type', 'Transfer-Encoding')
                for header in purged_headers:
                    prepared_request.headers.pop(header, None)
                prepared_request.body = None

            headers = prepared_request.headers
            try:
                del headers['Cookie']
            except KeyError:
                pass

            # Extract any cookies sent on the response to the cookiejar
            # in the new request. Because we've mutated our copied prepared
            # request, use the old one that we haven't yet touched.
            prepared_request._cookies.extract_cookies(
                MockResponse(HTTPHeaderDict(resp.headers)), MockRequest(req))
            merge_cookies(prepared_request._cookies, self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)

            # Rebuild auth and proxy information.
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)

            # Override the original request.
            req = prepared_request
            req.adapt_prepare()

            if yield_requests:
                yield req
            else:
                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs
                )

                yield resp

                while not resp.done():
                    yield resp
                resp = resp.result()

                self.cookies.extract_cookies(
                    MockResponse(HTTPHeaderDict(resp.headers)), MockRequest(prepared_request))

                # extract redirect url, if any, for the next loop
                url = self.get_redirect_target(resp)

    def rebuild_proxies(self, prepared_request, proxies):
        """This method re-evaluates the proxy configuration by considering the
        environment variables. If we are redirected to a URL covered by
        NO_PROXY, we strip the proxy configuration. Otherwise, we set missing
        proxy keys for this URL (in case they were stripped by a previous
        redirect).

        This method also replaces the Proxy-Authorization header where
        necessary.

        :rtype: dict
        """
        proxies = proxies if proxies is not None else {}
        headers = prepared_request.headers
        url = prepared_request.url
        scheme = urlparse(url).scheme
        new_proxies = proxies.copy()
        no_proxy = proxies.get('no_proxy')

        bypass_proxy = should_bypass_proxies(url, no_proxy=no_proxy)
        # if self.trust_env and not bypass_proxy:
        #     environ_proxies = get_environ_proxies(url, no_proxy=no_proxy)
        # 
        #     proxy = environ_proxies.get(scheme, environ_proxies.get('all'))
        # 
        #     if proxy:
        #         new_proxies.setdefault(scheme, proxy)

        if 'Proxy-Authorization' in headers:
            del headers['Proxy-Authorization']

        try:
            username, password = get_auth_from_url(new_proxies[scheme])
        except KeyError:
            username, password = None, None

        if username and password:
            headers['Proxy-Authorization'] = _basic_auth_str(username, password)

        return new_proxies


class Session(SessionRedirectMixin):
    """A Trip session.

    Provides cookie persistence, and configuration.

    Basic Usage::

      >>> import trip
      >>> s = trip.Session()
      >>> s.get('http://httpbin.org/get')
      <Response [200]>

    Or as a context manager:: #TODO

      >>> with requests.Session() as s:
      >>>     s.get('http://httpbin.org/get')
      <Response [200]>
    """

    def __init__(self):
        self.headers = default_headers()
        self.auth = None
        self.proxies = {}
        self.hooks = default_hooks()
        self.params = {}
        self.stream = False
        self.verify = True
        self.cert = None
        self.max_redirects = DEFAULT_REDIRECT_LIMIT
        self.trust_env = True
        self.cookies = cookiejar_from_dict({})
        self.adapter = HTTPAdapter()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def prepare_request(self, request):
        cookies = request.cookies or {}

        # Bootstrap CookieJar.
        if not isinstance(cookies, cookielib.CookieJar):
            cookies = cookiejar_from_dict(cookies)

        # Merge with session cookies
        merged_cookies = merge_cookies(
            merge_cookies(RequestsCookieJar(), self.cookies), cookies)

        # Set environment's basic authentication if not explicitly set.
        # auth = request.auth
        # if self.trust_env and not auth and not self.auth:
        #     auth = get_netrc_auth(request.url)

        p = PreparedRequest()
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            files=request.files,
            data=request.data,
            json=request.json,
            headers=merge_setting(request.headers,
                self.headers, dict_class=CaseInsensitiveDict),
            params=merge_setting(request.params, self.params),
            auth=merge_setting(request.auth, self.auth),
            cookies=merged_cookies,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p

    def prepare_response(self, req, resp):
        """Builds a :class:`Response <trip.Response>` object from a tornado
        response. This should not be called from user code, and is only exposed
        for use when subclassing the
        :class:`HTTPAdapter <trip.adapters.HTTPAdapter>`

        :param req: The :class:`PreparedRequest <PreparedRequest>` used to
        generate the response.
        :param resp: The :class:`MessageDelegate <MessageDelegate>` response
        object.
        :rtype: requests.Response
        """

        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = getattr(resp, 'code', None)

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(getattr(resp, 'headers', {}))

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = getattr(resp, 'reason', '')

        if isinstance(req.url, bytes):
            response.url = req.url.decode('utf-8')
        else:
            response.url = req.url

        # Add new cookies from the server
        headerDict = HTTPHeaderDict(response.headers)
        response.cookies.extract_cookies(
            MockResponse(headerDict), MockRequest(req))
        self.cookies.extract_cookies(
            MockResponse(headerDict), MockRequest(req))

        response.request = req
        # response.connection = self

        return response

    def request(self, method, url,
            params=None, data=None, headers=None, cookies=None, files=None,
            auth=None, timeout=None, allow_redirects=True, proxies=None,
            hooks=None, stream=None, verify=None, cert=None, json=None):

        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        request = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            request.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            'timeout': timeout,
            'allow_redirects': allow_redirects,
        }
        send_kwargs.update(settings)

        return self.send(request, **send_kwargs)

    def get(self, url, **kwargs):
        r"""Sends a GET request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('GET', url, **kwargs)

    def options(self, url, **kwargs):
        r"""Sends a OPTIONS request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', True)
        return self.request('OPTIONS', url, **kwargs)

    def head(self, url, **kwargs):
        r"""Sends a HEAD request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('HEAD', url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        r"""Sends a POST request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param json: (optional) json to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request('POST', url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        r"""Sends a PUT request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request('PUT', url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        r"""Sends a PATCH request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param data: (optional) Dictionary, bytes, or file-like object to send in the body of the :class:`Request`.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request('PATCH', url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        r"""Sends a DELETE request. Returns :class:`Response` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        :rtype: requests.Response
        """

        return self.request('DELETE', url, **kwargs)

    @gen.coroutine
    def send(self, req, **kwargs):
        """Send a given PreparedRequest.

        :rtype: trip.gen.Future
        """

        if not isinstance(req, PreparedRequest):
            raise ValueError('You can only send PreparedRequests.')

        allow_redirects = kwargs.pop('allow_redirects', True)
        start_time = preferred_clock()

        r = yield self.adapter.send(req, **kwargs)

        if isinstance(r, Exception):
            raise gen.Return(r)
        else:
            r = self.prepare_response(req, r)

        r.elapsed = timedelta(seconds=(preferred_clock()-start_time))

        # Response manipulation hooks
        r = dispatch_hook('response', req.hooks, r, **kwargs)

        # Persist cookies
        if r.history:
            # If the hooks create history then we want those cookies too
            for resp in r.history:
                self.cookies.extract_cookies(
                    MockResponse(HTTPHeaderDict(resp.headers)), MockRequest(resp.request))

        self.cookies.extract_cookies(
            MockResponse(HTTPHeaderDict(r.headers)), MockRequest(req))

        # Redirect resolving generator.
        redirect_gen = self.resolve_redirects(r, req, **kwargs)

        # Resolve redirects if allowed.
        history = []
        if allow_redirects:
            for resp in redirect_gen:
                resp = yield resp
                history.append(resp)

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = history

        # If redirects aren't being followed, store the response on the Request for Response.next().
        if not allow_redirects:
            try:
                r._next = next(self.resolve_redirects(r, req, yield_requests=True, **kwargs))
            except StopIteration:
                pass

        raise gen.Return(r)

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        """
        Check the environment and merge it with some settings.

        :rtype: dict
        """
        # Gather clues from the surrounding environment.
        # if self.trust_env:
        #     # Set environment's proxies.
        #     no_proxy = proxies.get('no_proxy') if proxies is not None else None
        #     env_proxies = get_environ_proxies(url, no_proxy=no_proxy)
        #     for (k, v) in env_proxies.items():
        #         proxies.setdefault(k, v)
        # 
        #     # Look for requests environment configuration and be compatible
        #     # with cURL.
        #     if verify is True or verify is None:
        #         verify = (os.environ.get('REQUESTS_CA_BUNDLE') or
        #                   os.environ.get('CURL_CA_BUNDLE'))

        # Merge all the kwargs.
        proxies = merge_setting(proxies, self.proxies)
        stream = merge_setting(stream, self.stream)
        verify = merge_setting(verify, self.verify)
        cert = merge_setting(cert, self.cert)

        return {'verify': verify, 'proxies': proxies, 'stream': stream,
                'cert': cert}

    def close(self):
        pass


session = Session
