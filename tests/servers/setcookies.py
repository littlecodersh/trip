import flask

app = flask.Flask(__name__)

@app.route('/')
def _():
    print(flask.request.cookies)
    resp = flask.make_response('Hello world')
    resp.set_cookie('value', 'hi')
    return resp

app.run()
