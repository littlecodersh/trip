from .sessions import Session

def request(method, url, params=None,
        data=None, headers=None, cookies=None, files=None):
    return Session().request(method, url, params,
        data, headers, cookies, files)

def get(url, params=None, headers=None):
    return Session().get(url, params, headers)

def post(url, params=None,
        data=None, headers=None, files=None):
    return Session().post(url, params,
        data, headers, files)
