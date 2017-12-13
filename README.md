# Trip: Async HTTP for Humans

[![pypi][pypi-image]][pypi]
[![][pyversion-image]][pypi]
[![][thanks-image]][thanks]
[![][chinese-image]][chinese]

TRIP, Tornado & Requests In Pair, an async HTTP library for Python.

Simple as Requests, Trip let you get rid of annoying network blocking.

Coroutine in python 2.7+ can be this simple:

```python
import trip

@trip.coroutine
def main():
    r = yield trip.get('https://httpbin.org/get', auth=('user', 'pass'))
    print(r.content)

trip.run(main)
```

With Trip, you may finish [one hundred requests in one piece of time][demo].

Trip gets its name from two powerful site packages and aims to combine them together.
Trip refers to 'Tornado & Requests In Pair', TRIP.
To put them together, I reused much of their codes about structure and dealing.
Actually I only made little effort to make a mixture. Thanks to [Tornado][tornado] 
and [Requests][requests].

Through using Trip, you may take full advantage of Requests, including:
Sessions with Cookie persistence, browser-style SSL verification, automatic content decoding,
basic/digest authentication, elegant key/value Cookies.
Meanwhile, your requests are coroutine like using AsyncHTTPClient of Tornado, network blocking will
not be a problem.

Found difficult optimizing spiders' time consuming?
Found tricky using asyncio http packages?
Found heavy custimizing big spider framework?
Try Trip, you will not regret!

## Installation

Paste it into your console and enjoy:

```bash
python -m pip install trip
```

## Documents

Documents are here: [http://trip.readthedocs.io/zh/latest/][document]

## Advanced usage

Some of the advaced features are listed here:

**Using async and await in python 3**

```python
import trip

async def main():
    r = await trip.get('https://httpbin.org/get', auth=('user', 'pass'))
    print(r.content)

trip.run(main)
```

**Sessions with Cookie persistence**

```python
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
```

**Event hooks**

```python
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
```

**Timeouts**

```python
import trip

@trip.coroutine
def main():
    r = yield trip.get('http://github.com', timeout=0.001)
    print(r)

trip.run(main)
```

**Proxy**

```python
import trip

proxies = {
    'http': '127.0.0.1:8080',
    'https': '127.0.0.1:8081',
}

@trip.coroutine
def main():
    r = yield trip.get('https://httpbin.org/get', proxies=proxies)
    print(r.content)

trip.run(main)
```

## How to contribute

1. You may open an issue to share your ideas with me.
2. Or fork this [project][homepage] and do it your own on **master** branch.
3. Please write demo codes of bugs or new features. You know, codes help.
4. Finally if you finish your work and make a pull request, I will merge it in time after essential tests.

## Similiar projects

* [curequests][curequests]: Curio + Requests, Async HTTP for Humans.
* [grequests][grequests]: Gevent + Requests.
* [requests-threads][requests-threads]: Twisted Deferred Thread backend for Requests.
* [requests-futures][requests-futures]: Asynchronous Python HTTP Requests for Humans using Futures.

[pyversion-image]: https://img.shields.io/pypi/pyversions/trip.svg
[pypi]: https://pypi.python.org/pypi/trip
[pypi-image]: https://img.shields.io/pypi/v/trip.svg
[chinese]: https://github.com/littlecodersh/trip/blob/master/README_CN.md
[chinese-image]: https://img.shields.io/badge/README-切换语言-yellow.svg
[thanks]: https://saythanks.io/to/littlecodersh
[thanks-image]: https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg
[demo]: https://gist.github.com/littlecodersh/6803d2c3382de9a7793a0189db72f538
[tornado]: https://github.com/tornadoweb/tornado
[requests]: https://github.com/requests/requests
[document]: http://trip.readthedocs.io/
[homepage]: http://github.com/littlecodersh/trip
[curequests]: https://github.com/guyskk/curequests
[grequests]: https://github.com/kennethreitz/grequests
[requests-threads]: https://github.com/requests/requests-threads
[requests-futures]: https://github.com/ross/requests-futures
