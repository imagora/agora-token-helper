# -*- coding: utf-8 -*-
__author__ = "winking324@gmail.com"


import os
import json
import time
import flask
import logging
from helper import generate


app = flask.Flask(__name__)
app.logger.setLevel(logging.INFO)

try:
    with open('configs/project.json') as f:
        project = json.load(f)
except Exception as e:
    print('Fatal: read config file error: {}'.format(repr(e)))
    exit(1)

app_id = project.get('appID', '')
app_cert = project.get('appCert', '')
if not app_id or not app_cert:
    print('Error: appID or appCert not set')
    exit(1)


@app.route('/token', methods=('POST',))
@app.route('/token/<version>', methods=('POST',))
def token(version='6'):
    print('{} {} {} {}'.format(
        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        flask.request.method,
        flask.request.remote_addr,
        flask.request.path))

    query_info = flask.request.get_json(force=True)
    ok, res = generate.generate_token(app_id, app_cert, version, **query_info)
    return json.dumps(res), 200 if ok else 400


if __name__ == '__main__':
    app.run(debug=False, host=os.getenv('SAMPLE_HOST', '0.0.0.0'), port=int(os.getenv('SAMPLE_PORT', 8080)))
