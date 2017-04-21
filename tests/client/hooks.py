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

if __name__ == '__main__':
    trip.run(main)
