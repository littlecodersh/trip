import time

import requests, trip

url = 'http://httpbin.org/get'
times = 10

@trip.coroutine
def fetch():
    r = yield trip.session().get(url)
    raise trip.gen.Return(r)

@coroutine
def main():
    start_time = time.time()
    l = yield [fetch() for i in range(times)]
    print(time.time() - start_time)
    print(l)

trip.IOLoop.current().run_sync(main)

def fetch():
    r = requests.get(url)
    return r

start_time = time.time()
l = [fetch() for i in range(times)]
print(time.time() - start_time)
