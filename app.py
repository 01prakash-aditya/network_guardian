from flask import Flask, render_template, jsonify
from scanner import run_network_scan

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    try:
        data = run_network_scan()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)