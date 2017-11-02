# Trip: 让协程与网络服务人类

[![pypi][pypi-image]][pypi]
[![][pyversion-image]][pypi]
[![][thanks-image]][thanks]
[![][english-image]][english]

Trip 是一个协程的网络库，使用如Requests一般简单的操作就可以让网络延时不再阻塞你的程序。

Python的协程可以这么简单（兼容Python 2.7-3.7）：

```python
import trip

@trip.coroutine
def main():
    r = yield trip.get('https://httpbin.org/get', auth=('user', 'pass'))
    print(r.content)

trip.run(main)
```

有了协程，同样的代码量，[一百份请求一份时间][demo]。

Trip的名字来源于其两个依赖包，也旨在将两个包的内容融合起来：'Tornado & Requests In Pair'。
在兼容中使用了大量上述两个包结构和处理的代码，我只是做了一些简单的整合工作，感谢
[Tornado][tornado]与[Requests][requests]让我能如此轻易的完成本项目的编写。


通过使用Trip，你可以充分使用Requests的各种特性，包括但不限于：带持久 Cookie 的会话、
浏览器式的 SSL 认证、自动内容解码、 基本/摘要式的身份认证、 优雅的 key/value Cookie。
同时你的请求又和使用Tornado的AsyncHTTPClient一般是协程的，网络延时不再会阻塞你的
程序，在程序正常运行的时候你可以同时等待多项任务的完成。

爬虫耗时太久优化困难吗？各种协程网络框架难以使用吗？大型爬虫框架臃肿无法灵活定制吗？
试试Trip，你不会后悔的！

无论你是使用的2.7，3.3，3.7，Trip都可以完美运行。

## 安装

安装Trip非常简单，只需要在命令行中输入：

```bash
python -m pip install trip
```

## 文档

你可以在[这里][document]找到本项目详细的文档。

如果在阅读文档过程当中遇到了问题，
也可以加入qq群与我们讨论：462703741。


## 进阶应用

这里展示部分的进阶应用：

**使用async与await**

```python
import trip

async def main():
    r = await trip.get('https://httpbin.org/get', auth=('user', 'pass'))
    print(r.content)

trip.run(main)
```

**Cookie的持久化**

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

**事件挂钩**

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

**超时**

```python
import trip

@trip.coroutine
def main():
    r = yield trip.get('http://github.com', timeout=0.001)
    print(r)

trip.run(main)
```

## 如何贡献代码

1. 你可以开启issue与我交流你的想法。
2. 或者fork这个[项目][homepage]并在 **master** 分支上进行你的修改。
3. 请务必带上出现问题或者新功能的相关代码，这会给我们的交流带来巨大的帮助。
4. 最后如果你完成了修改可以通过pull request的方式提交，我会尽快完成测试并合并。

[pyversion-image]: https://img.shields.io/pypi/pyversions/trip.svg
[pypi]: https://pypi.python.org/pypi/trip
[pypi-image]: https://img.shields.io/pypi/v/trip.svg
[english]: https://github.com/littlecodersh/trip/blob/master/README_EN.md
[english-image]: https://img.shields.io/badge/english---%3E-yellow.svg
[thanks]: https://saythanks.io/to/littlecodersh
[thanks-image]: https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg
[demo]: https://gist.github.com/littlecodersh/6803d2c3382de9a7793a0189db72f538
[tornado]: https://github.com/tornadoweb/tornado
[requests]: https://github.com/requests/requests
[document]: http://trip.readthedocs.io/
[homepage]: http://github.com/littlecodersh/trip
