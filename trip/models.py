from requests.models import PreparedRequest

from tornado.httpclient import HTTPRequest

from .exceptions import ParamsError

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
        if bool(rRequest) != bool(tRequest): # xor
            raise ParamsError('Either rRequest or tRequest should be provided.')
        elif rRequest is not None:
            self._init_with_r_request(rRequest)
        else:
            self._init_with_t_request(tRequest)

    def _init_with_r_request(self, request):
        if not isinstance(rRequest, PreparedRequest):
            raise ParamsError('param rRequest should be \
                PreparedRequest from requests package.')

    def _init_with_t_request(self, request):
        if isinstance(tRequest, HTTPRequest):
            raise ParamsError('param tRequest should be \
                HTTPRequest instance from tornado package.')


class Response(object):
    pass
