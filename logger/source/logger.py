from flask import Flask, render_template, request, jsonify
from os import getenv

from utils.message import message

app = Flask(__name__)
app._static_folder = 'static'
messages = []

@app.route('/api/reset', methods=['GET'])
def reset_messages():
    global messages
    messages = []
    return jsonify({'status': 'ok'})

@app.route('/api/add/<sender>', methods=['POST'])
def add_message(sender):
    if sender not in ['server', 'client']:
        return jsonify({'error': 'Invalid sender'})

    content = request.form.get('message')
    if not content:
        return jsonify({'error': 'Invalid/Missing message'})

    messages.append(message(f'{sender}:  {content}', sender))

    return jsonify({'status': 'ok'})


@app.route('/')
def get_logs():
    return render_template('index.html', messages=messages)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=int(getenv('PORT')))
