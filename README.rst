Trip: Async HTTP for Humans
===========================

.. image:: https://img.shields.io/pypi/v/trip.svg
    :target: https://pypi.python.org/pypi/trip

.. image:: https://img.shields.io/pypi/l/trip.svg
    :target: https://pypi.python.org/pypi/trip

.. image:: https://img.shields.io/pypi/pyversions/trip.svg
    :target: https://pypi.python.org/pypi/trip

.. image:: https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg
    :target: https://saythanks.io/to/littlecodersh

.. image:: https://github.com/littlecodersh/trip/blob/master/README.md
    :target: https://img.shields.io/badge/chinese---%3E-yellow.svg

Trip is an async HTTP library for Python, network blocking will no longer bother you.

Coroutine in python 2.7+ can be this simple:

.. code-block:: python

    import trip

    @trip.coroutine
    def main():
        r = yield trip.get('https://httpbin.org/get', auth=('user', 'pass'))
        print(r.content)

    trip.run(main)

With Trip, you may finish
`one hundred requests in one piece of time <https://gist.github.com/littlecodersh/6803d2c3382de9a7793a0189db72f538>`_.

Trip gets its name from two powerful site packages and aims to combine them together.
Trip refers to 'Tornado & Requests In Pair', TRIP.
To put them together, I reused much of their codes about structure and dealing.
Actually I only made little effort to make a mixture. Thanks to 
`Tornado <https://github.com/tornadoweb/tornado>`_ and 
`Requests <https://github.com/requests/requests>`_.

Through using Trip, you may take full advantage of Requests, including:
Sessions with Cookie persistence, browser-style SSL verification, automatic content decoding,
basic/digest authentication, elegant key/value Cookies.
Meanwhile, your requests are coroutine like using AsyncHTTPClient of Tornado, network blocking will
not be a problem.

Found difficult optimizing spiders' time consuming?
Found tricky using asyncio http packages?
Found heavy custimizing big spider framework?
Try Trip, you will not regret!

Installation
------------

Paste it into your console and enjoy:

.. code-block:: bash

    $ python -m pip install trip


Documents
---------

Documents are here: http://trip.readthedocs.io/zh/latest/


Advanced usage
--------------

Some of the advaced features are listed here:

Using async and await in python 3:

.. code-block:: python

    import trip

    async def main():
        r = await trip.get('https://httpbin.org/get', auth=('user', 'pass'))
        print(r.content)

    trip.run(main)

Sessions with Cookie persistence

.. code-block:: python

    import trip

    @trip.coroutine
    def main():
        s = trip.Session()
        r = yield s.get(
            'https://httpbin.org/cookies/set',
            params={'name': 'value'},
            allow_redirects=False)
        r = yield s.get('https://httpbin.org/cookies')
        print(r.content)

    trip.run(main)

Event hooks

.. code-block:: python

    import trip

    @trip.coroutine
    def main():
        def print_url(r, *args, **kwargs):
            print(r.url)
        def record_hook(r, *args, **kwargs):
            r.hook_called = True
            return r
        url = 'http://httpbin.org/get'
        r = yield trip.get('http://httpbin.org', hooks={'response': [print_url, record_hook]})
        print(r.hook_called)

    trip.run(main)


How to contribute
-----------------

#. You may open an issue to share your ideas with me.
#. Or fork this `project <http://github.com/littlecodersh/trip>`_ and do it your own on **master** branch.
#. Please write demo codes of bugs or new features. You know, codes help.
#. Finally if you finish your work and make a pull request, I will merge it in time after essential tests.
