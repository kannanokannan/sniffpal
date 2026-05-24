"""
SniffPal Pi Server
Lightweight Flask server for Raspberry Pi — serves the React app,
runs scheduled captures every 30 minutes, stores last 48 digests.

Usage:
    cd pi
    sudo python3 server.py

Access:
    http://sniffpal.local:8080
    http://<pi-ip>:8080
"""

from flask import Flask, jsonify, send_from_directory
import os, json, glob, subprocess, threading, sys
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__, static_folder='../dist', static_url_path='')

DIGEST_DIR  = os.path.join(os.path.dirname(__file__), 'digests')
MAX_DIGESTS = 48
os.makedirs(DIGEST_DIR, exist_ok=True)

# ── Serve React app ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    try:
        return send_from_directory(app.static_folder, path)
    except Exception:
        return send_from_directory(app.static_folder, 'index.html')

# ── API: list all digests ────────────────────────────────────────────────────

@app.route('/api/digests')
def get_digests():
    files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')), reverse=True)
    digests = []
    for f in files[:MAX_DIGESTS]:
        try:
            with open(f) as fh:
                d = json.load(fh)
                # Return summary only (not full packet data) for the list
                digests.append({
                    'timestamp':   d.get('timestamp'),
                    'capturedAt':  d.get('capturedAt'),
                    'packetCount': d.get('packetCount', 0),
                    'file':        os.path.basename(f),
                })
        except Exception:
            pass
    return jsonify(digests)

# ── API: get latest digest (full packets for SniffPal parser) ────────────────

@app.route('/api/digests/latest')
def get_latest():
    files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')), reverse=True)
    if not files:
        return jsonify({'error': 'No captures yet'}), 404
    try:
        with open(files[0]) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: get a specific digest by filename ───────────────────────────────────

@app.route('/api/digests/<filename>')
def get_digest(filename):
    path = os.path.join(DIGEST_DIR, filename)
    if not os.path.exists(path):
        return jsonify({'error': 'Not found'}), 404
    try:
        with open(path) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: trigger a manual capture ────────────────────────────────────────────

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    threading.Thread(target=run_capture, daemon=True).start()
    return jsonify({'status': 'started'})

# ── API: server status ───────────────────────────────────────────────────────

@app.route('/api/status')
def status():
    files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')), reverse=True)
    return jsonify({
        'status':   'running',
        'digests':  len(files),
        'latest':   os.path.basename(files[0]) if files else None,
        'maxDigests': MAX_DIGESTS,
    })

# ── Capture + digest ─────────────────────────────────────────────────────────

def run_capture():
    """Run a 30-minute capture and store the digest."""
    import tempfile

    ts       = datetime.now().strftime('%Y%m%d-%H%M%S')
    raw_path = tempfile.mktemp(suffix='.json')
    capture_script = os.path.join(
        os.path.dirname(__file__), '..', 'scapy-capture-tool', 'capture.py'
    )

    print(f'[SniffPal Pi] Starting capture at {ts}...', flush=True)

    try:
        subprocess.run(
            ['sudo', 'python3', capture_script,
             '-i', 'wlan0', '-t', '1800', '-o', raw_path],
            check=True,
            timeout=1900,
        )

        with open(raw_path) as f:
            raw = json.load(f)

        digest = {
            'timestamp':   ts,
            'capturedAt':  datetime.now().isoformat(),
            'packetCount': len(raw),
            'packets':     raw,  # full packets — SniffPal parser runs client-side
        }

        digest_path = os.path.join(DIGEST_DIR, f'digest-{ts}.json')
        with open(digest_path, 'w') as f:
            json.dump(digest, f)

        print(f'[SniffPal Pi] Saved digest: digest-{ts}.json ({len(raw)} packets)', flush=True)

        # Enforce max 48 digests — delete oldest
        files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')))
        for old in files[:-MAX_DIGESTS]:
            os.remove(old)
            print(f'[SniffPal Pi] Removed old digest: {os.path.basename(old)}', flush=True)

    except subprocess.CalledProcessError as e:
        print(f'[SniffPal Pi] Capture failed: {e}', flush=True)
    except subprocess.TimeoutExpired:
        print('[SniffPal Pi] Capture timed out after 1900s', flush=True)
    except Exception as e:
        print(f'[SniffPal Pi] Error: {e}', flush=True)
    finally:
        if os.path.exists(raw_path):
            os.remove(raw_path)

# ── Scheduler: capture every 30 minutes ─────────────────────────────────────

scheduler = BackgroundScheduler()
scheduler.add_job(run_capture, 'interval', minutes=30, id='scheduled_capture')
scheduler.start()

print('[SniffPal Pi] Scheduler started — capturing every 30 minutes', flush=True)
print('[SniffPal Pi] Access the dashboard at http://sniffpal.local:8080', flush=True)

# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print('\n[SniffPal Pi] Shutting down...', flush=True)
        scheduler.shutdown()
        sys.exit(0)
