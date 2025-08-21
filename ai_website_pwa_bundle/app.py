from flask import Flask, request, send_from_directory, jsonify
from werkzeug.utils import secure_filename
import os
import socket

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB
ALLOWED_EXTENSIONS = {'.py'}

def allowed(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/manifest.json')
def manifest():
    return send_from_directory('.', 'manifest.json')

@app.route('/service-worker.js')
def sw():
    return send_from_directory('.', 'service-worker.js')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/downloads/<path:path>')
def downloads(path):
    return send_from_directory('downloads', path, as_attachment=False)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if not allowed(f.filename):
        return jsonify({'error': 'Only .py files accepted'}), 400
    filename = secure_filename(f.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(save_path)
    return jsonify({'status': 'ok', 'filename': filename})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    print("\nApp running at:")
    print(f"  → http://127.0.0.1:{port}  (localhost only)")
    print(f"  → http://{local_ip}:{port}  (your Wi-Fi/LAN IP)")
    print(f"  → http://ai.local:{port}  (if mapped in hosts file)\n")

    app.run(host='0.0.0.0', port=port)
