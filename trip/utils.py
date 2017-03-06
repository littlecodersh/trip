from requests.structures import CaseInsensitiveDict

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
