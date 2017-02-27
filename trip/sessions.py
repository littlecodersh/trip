import requests
import tornado
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.concurrent import Future

class Session(object):
    def __init__(self):
        self.cookies = requests.cookies.cookiejar_from_dict({})
    def request(self, method, url, params=None,
            data=None, headers=None, cookies=None, files=None):
        resultFuture = Future()
        preparedRequest = requests.models.PreparedRequest()
        preparedRequest.prepare(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            params=params or {},
            cookies=requests.cookies.merge_cookies(
                requests.cookies.merge_cookies(
                requests.cookies.RequestsCookieJar(), self.cookies),
                cookies or {}) )
        tornadoRequest = HTTPRequest(
            method=preparedRequest.method,
            url=preparedRequest.url,
            body=preparedRequest.body,
            headers=preparedRequest.headers,)
        client = AsyncHTTPClient()
        def setResult(response):
            client.close()
            r = self.build_response(response)
            requests.cookies.extract_cookies_to_jar(
                self.cookies, preparedRequest, r.raw)
            resultFuture.set_result(r)
        client.fetch(tornadoRequest, setResult)
        return resultFuture
    def get(self, url, params=None, headers=None):
        return self.request('GET', url, params, headers=headers)
    def post(self, url, params=None,
            data=None, headers=None, files=None):
        return self.request('POST', url, data=data,
            headers=headers, files=files)
    def build_response(self, raw):
        response = requests.models.Response()
        response.status_code = getattr(raw, 'code', None)
        response.headers = getattr(raw, 'headers', {})
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        response.raw = raw.buffer
        if isinstance(raw.effective_url, bytes):
            response.url = raw.effective_url.decode('utf-8')
        else:
            response.url = raw.effective_url
        response.request = raw
        return response
