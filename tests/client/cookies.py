import trip

@trip.coroutine
def main():
    s = trip.Session()
    r = yield s.get('http://httpbin.org/cookies/set?name=value')
    print(r.content)
    print(r.history)
    print(s.cookies.get_dict())

if __name__ == '__main__':
    trip.run(main)
