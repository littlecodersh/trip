from requests.exceptions import RequestException

from tornado.httpclient import HTTPError


class TripException(RequestException, HTTPError):
    """There was an ambiguous exception that occurred while handling your
    request.
    """

    def __init__(self, *args, **kwargs):
        """Initialize TripException with `request` and `response` objects."""
        RequestException.__init__(self, *args, **kwargs)

class Timeout(TripException):
    """The request timed out."""
