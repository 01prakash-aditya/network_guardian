from flask import Flask, render_template, jsonify, request
from scanner import run_network_scan, run_custom_scan, get_network_interfaces

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    try:
        scan_type = request.args.get('type', 'local')
        
        kwargs = {}
        if scan_type == 'interface':
            kwargs['interface'] = request.args.get('interface', 'eno1')
        elif scan_type == 'subnet':
            kwargs['subnet'] = request.args.get('subnet', '192.168.1.0/24')
        elif scan_type == 'retry':
            kwargs['retry'] = int(request.args.get('retry', 3))
        elif scan_type == 'bandwidth':
            kwargs['bandwidth'] = int(request.args.get('bandwidth', 256))
        
        data = run_network_scan(scan_type, **kwargs)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/interfaces')
def interfaces():
    try:
        ifaces = get_network_interfaces()
        return jsonify({"interfaces": ifaces})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/custom_scan')
def custom_scan():
    try:
        target = request.args.get('target', '')
        if not target:
            return jsonify({"error": "No target specified"}), 400
        data = run_custom_scan(target)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
