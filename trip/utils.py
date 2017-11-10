import codecs

from requests.compat import urlsplit
from requests.structures import CaseInsensitiveDict

from tornado.concurrent import Future
from tornado.httputil import split_host_and_port

from .__version__ import __version__

def default_user_agent(name="python-trip"):
    """
    Return a string representing the default user agent.

    :rtype: str
    """
    return '%s/%s' % (name, __version__)


def default_headers():
    """
    :rtype: requests.structures.CaseInsensitiveDict
    """
    return CaseInsensitiveDict({
        'User-Agent': default_user_agent(),
        'Accept-Encoding': ', '.join(('gzip', 'deflate')),
        'Accept': '*/*',
        # 'Connection': 'keep-alive',
        'Connection': 'close',
    })


def iter_slices_future(r, slice_length, decode_unicode=False):
    """Iterate over slices of a string."""
    pos, string = 0, r._content
    if r.encoding is None:
        decode_unicode = False
    if decode_unicode:
        decoder = codecs.getincrementaldecoder(r.encoding)(errors='replace')

    if slice_length is None or slice_length <= 0:
        slice_length = len(string)

    while pos < len(string):
        future = Future()
        chunk = string[pos:pos + slice_length]
        if decode_unicode:
            chunk = decoder.decode(chunk)
        future.set_result(chunk)
        yield future
        pos += slice_length

    chunk = decoder.decode(b'', final=True)
    if chunk:
        future = Future()
        future.set_result(chunk)
        yield future


def get_host_and_port(url):
    """ Get host and port from url."""
    parsed = urlsplit(url)
    netloc = parsed.netloc
    if '@' in netloc:
        userpass, _, netloc = netloc.rpartition('@')
    host, port = split_host_and_port(netloc)
    if port is None:
        port = 443 if parsed.scheme == 'https' else 80
    return (host, port)
