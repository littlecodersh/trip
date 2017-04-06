import flask

app = flask.Flask(__name__)

@app.route('/')
def _():
    print(flask.request.cookies)
    resp = flask.make_response('Hello world')
    resp.set_cookie('value', 'hi')
    return resp

app.run()

"""
Usage::

    import trips

    @trips.gen.coroutine
    def main():
        s = trips.session()
        r = yield s.get('http://127.0.0.1:5000/')
        print(r.cookies.get_dict())
        r = yield s.get('http://127.0.0.1:5000/')
        print(r.raw)

    trips.ioloop.IOLoop.current().run_sync(main)

"""
