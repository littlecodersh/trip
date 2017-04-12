import codecs

from requests.structures import CaseInsensitiveDict

from tornado.concurrent import Future

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

