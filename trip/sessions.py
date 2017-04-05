from functools import partial

import requests
from requests.compat import cookielib
from requests.cookies import (
    cookiejar_from_dict, merge_cookies, RequestsCookieJar,
    extract_cookies_to_jar, MockRequest, MockResponse)
from requests.models import (
    PreparedRequest as RPreparedRequest,
    Request as RRequest,
    Response as RResponse)
from requests.sessions import merge_setting
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers
from urllib3._collections import HTTPHeaderDict

import tornado
from tornado import gen
from tornado.httpclient import (
    AsyncHTTPClient,
    HTTPRequest as TRequest,
    HTTPResponse as TResponse)
from tornado.concurrent import Future

from .adapters import HTTPAdapter
from .models import Request
from .utils import default_headers


class Session(object):

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

        p = RPreparedRequest()
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
        request = Request(rRequest=p)
        return request

    def prepare_response(self, future, request, raw):
        response = Response()
        response.status_code = getattr(raw, 'code', None)
        response.headers = CaseInsensitiveDict(getattr(raw, 'headers', {}))
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = raw.buffer
        response.reason = raw.reason
        if isinstance(raw.effective_url, bytes):
            response.url = raw.effective_url.decode('utf-8')
        else:
            response.url = raw.effective_url

        headerDict = HTTPHeaderDict(response.headers)
        response.cookies.extract_cookies(
            MockResponse(headerDict), MockRequest(request))
        self.cookies.extract_cookies(
            MockResponse(headerDict), MockRequest(request))

        response.request = request
        # response.connection = self

        future.set_result(response)

    def request(self, method, url,
            params=None, data=None, headers=None, cookies=None, files=None,
            auth=None, timeout=None, allow_redirects=True, proxies=None,
            hooks=None, stream=None, verify=None, cert=None, json=None):
        req = RRequest(
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
        resp = self.adapter.send(request, **send_kwargs)

        return resp

    def get(self, url, params=None, headers=None):
        return self.request('GET', url, params, headers=headers)

    def post(self, url, params=None,
            data=None, headers=None, files=None):
        return self.request('POST', url, data=data,
            headers=headers, files=files)


session = Session
