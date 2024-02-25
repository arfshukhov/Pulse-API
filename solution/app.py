from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/ping', methods=['POST'])
def send():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run()