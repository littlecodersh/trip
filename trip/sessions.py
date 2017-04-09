from functools import partial

import requests
from requests.compat import cookielib
from requests.cookies import (
    cookiejar_from_dict, merge_cookies, RequestsCookieJar,
    extract_cookies_to_jar, MockRequest, MockResponse)
from requests.sessions import merge_setting
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers
from urllib3._collections import HTTPHeaderDict

import tornado
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.concurrent import Future

from .adapters import HTTPAdapter
from .models import PreparedRequest, Request, Response
from .utils import default_headers


class Session(object):
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
        self.adapter = HTTPAdapter()
        self.cookies = cookiejar_from_dict({})
        self.headers = default_headers()
        self.params = {}

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
            # auth=merge_setting(auth, self.auth),
            cookies=merged_cookies,
            # hooks=merge_hooks(request.hooks, self.hooks),
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

        # proxies = proxies or {}
        # 
        # settings = self.merge_environment_settings(
        #     prep.url, proxies, stream, verify, cert
        # )
        # 
        # # Send the request.
        # send_kwargs = {
        #     'timeout': timeout,
        #     'allow_redirects': allow_redirects,
        # }
        send_kwargs = {}
        # send_kwargs.update(settings)

        return self.send(request, **send_kwargs)

    def get(self, url, params=None, headers=None):
        return self.request('GET', url, params, headers=headers)

    def post(self, url, params=None,
            data=None, headers=None, files=None):
        return self.request('POST', url, data=data,
            headers=headers, files=files)

    def send(self, request, **kwargs):
        """Send a given PreparedRequest.

        :rtype: trip.gen.Future
        """

        if not isinstance(request, PreparedRequest):
            raise ValueError('You can only send PreparedRequests.')

        future = Future()

        def handle_future(f):
            response = self.prepare_response(request, f.result())
            future.set_result(response)

        resp = self.adapter.send(request, **kwargs)
        resp.add_done_callback(handle_future)

        return future


session = Session
