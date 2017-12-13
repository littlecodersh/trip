from requests.exceptions import RequestException

from tornado.httpclient import HTTPError
from tornado.httputil import responses


class TripException(RequestException, HTTPError):
    """There was an ambiguous exception that occurred while handling your
    request.
    """

    def __init__(self, code, *args, **kwargs):
        """Initialize TripException with `request` and `response` objects."""
        self.code = code
        m, r = (args + (None, None))[:2]
        self.message = kwargs.pop('message', responses.get(code, "Unknown"))
        self.message = m or self.message
        self.response = kwargs.pop('response', None)
        self.response = r or self.response
        RequestException.__init__(self, code, self.message, self.response, **kwargs)

class Timeout(TripException):
    """The request timed out."""
