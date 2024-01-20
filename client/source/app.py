from flask import Flask, jsonify
from os import getenv

from client import client

app = Flask(__name__)


@app.route('/login')
def login():
    c = client('server', 1337)
    c.send_public()
    c.get_challenge()
    c.send_signed()
    m = c.get_message()
    return jsonify({'msg': m})



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=int(getenv('PORT')))
