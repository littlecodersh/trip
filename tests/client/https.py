import trip

@trip.coroutine
def main():
    s = trip.Session()
    # r = yield s.get('https://httpbin.org/get?name=value')
    print(r.content)

if __name__ == '__main__':
    trip.run(main)
