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

from flask import Flask, jsonify, send_from_directory, request, Response
import os, json, glob, subprocess, threading, sys, time
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

try:
    import psutil
except Exception:
    psutil = None

app = Flask(__name__, static_folder='../dist', static_url_path='')

DIGEST_DIR    = os.path.join(os.path.dirname(__file__), 'digests')
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
MAX_DIGESTS   = 48
os.makedirs(DIGEST_DIR, exist_ok=True)
capture_lock = threading.Lock()
capture_state = {
    'running': False,
    'startedAt': None,
    'finishedAt': None,
    'packets': 0,
    'devices': 0,
    'protocols': {},
    'lastMessage': None,
    'error': None,
}

DEFAULT_SETTINGS = {
    'interval':  10,     # minutes
    'interface': 'wlan0',
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                return {**DEFAULT_SETTINGS, **json.load(f)}
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)

# ── Serve React app ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    if path.startswith('sniffpal/'):
        path = path[len('sniffpal/'):]
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

# ── API: settings ────────────────────────────────────────────────────────────

@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(load_settings())

@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.get_json(silent=True) or {}
    settings = load_settings()
    if 'interval' in data:
        settings['interval'] = int(data['interval'])
    if 'interface' in data:
        settings['interface'] = str(data['interface'])
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f)
    # Reschedule the capture job with new interval
    try:
        scheduler.reschedule_job(
            'capture_job', trigger='interval', minutes=settings['interval']
        )
    except Exception as e:
        print(f'[SniffPal Pi] Reschedule failed: {e}', flush=True)
    return jsonify({'status': 'saved', 'settings': settings})

# ── API: trigger a manual capture ────────────────────────────────────────────

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    with capture_lock:
        if capture_state['running']:
            return jsonify({'status': 'already_running', 'capture': dict(capture_state)})
    threading.Thread(target=run_capture, daemon=True).start()
    return jsonify({'status': 'started'})

@app.route('/api/capture/events')
def capture_events():
    def stream():
        while True:
            with capture_lock:
                state = dict(capture_state)
            yield f"data: {json.dumps(state)}\n\n"
            if not state.get('running'):
                break
            time.sleep(1)
    return Response(stream(), mimetype='text/event-stream')

# ── API: server status ───────────────────────────────────────────────────────

@app.route('/api/status')
def status():
    settings = load_settings()
    files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')), reverse=True)
    with capture_lock:
        capture = dict(capture_state)
    return jsonify({
        'status':     'running',
        'digests':    len(files),
        'latest':     os.path.basename(files[0]) if files else None,
        'maxDigests': MAX_DIGESTS,
        'settings':   settings,
        'capture':    capture,
        'system':     get_system_metrics(),
    })

def get_system_metrics():
    if psutil is None:
        return None
    try:
        net = psutil.net_io_counters()
        mem = psutil.virtual_memory()
        return {
            'cpuPercent': psutil.cpu_percent(interval=None),
            'ramPercent': mem.percent,
            'ramUsedMB': round(mem.used / 1024 / 1024),
            'ramTotalMB': round(mem.total / 1024 / 1024),
            'netSentMB': round(net.bytes_sent / 1024 / 1024, 1),
            'netRecvMB': round(net.bytes_recv / 1024 / 1024, 1),
        }
    except Exception:
        return None

# ── Capture + digest ─────────────────────────────────────────────────────────

def run_capture():
    """Run a capture using current settings and store the digest."""
    import tempfile

    with capture_lock:
        if capture_state['running']:
            return
        capture_state.update({
            'running': True,
            'startedAt': datetime.now().isoformat(),
            'finishedAt': None,
            'packets': 0,
            'devices': 0,
            'protocols': {},
            'lastMessage': 'Starting capture',
            'error': None,
        })

    settings = load_settings()
    iface    = settings['interface']
    interval = settings['interval']
    duration = interval * 60  # capture for full interval in seconds

    ts       = datetime.now().strftime('%Y%m%d-%H%M%S')
    raw_path = tempfile.mktemp(suffix='.json')
    capture_script = os.path.join(
        os.path.dirname(__file__), '..', 'scapy-capture-tool', 'capture.py'
    )

    print(f'[SniffPal Pi] Starting capture on {iface} for {duration}s at {ts}...', flush=True)

    try:
        capture_cmd = ['python3', capture_script, '-i', iface, '-t', str(duration), '-o', raw_path]
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            capture_cmd = ['sudo', *capture_cmd]

        proc = subprocess.Popen(
            capture_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        deadline = time.time() + duration + 60
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            print(line, flush=True)
            if line.startswith('SNIFFPAL_PROGRESS '):
                try:
                    progress = json.loads(line.replace('SNIFFPAL_PROGRESS ', '', 1))
                    with capture_lock:
                        capture_state.update({
                            'packets': progress.get('packets', capture_state['packets']),
                            'devices': progress.get('devices', capture_state['devices']),
                            'protocols': progress.get('protocols', capture_state['protocols']),
                            'lastMessage': f"{progress.get('packets', 0)} packets captured",
                        })
                except Exception:
                    pass
            elif 'Captured ' in line and ' packets' in line:
                try:
                    count = int(line.split('Captured ', 1)[1].split(' packets', 1)[0])
                    with capture_lock:
                        capture_state['packets'] = count
                        capture_state['lastMessage'] = line
                except Exception:
                    pass
            else:
                with capture_lock:
                    capture_state['lastMessage'] = line
            if time.time() > deadline:
                proc.kill()
                raise subprocess.TimeoutExpired(capture_cmd, duration + 60)

        rc = proc.wait(timeout=5)
        if rc != 0:
            raise subprocess.CalledProcessError(rc, capture_cmd)

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
        with capture_lock:
            capture_state.update({
                'packets': len(raw),
                'lastMessage': f'Saved digest: digest-{ts}.json',
                'error': None,
            })

        # Enforce max 48 digests — delete oldest
        files = sorted(glob.glob(os.path.join(DIGEST_DIR, '*.json')))
        for old in files[:-MAX_DIGESTS]:
            os.remove(old)
            print(f'[SniffPal Pi] Removed old digest: {os.path.basename(old)}', flush=True)

    except subprocess.CalledProcessError as e:
        print(f'[SniffPal Pi] Capture failed: {e}', flush=True)
        with capture_lock:
            capture_state['error'] = 'Capture failed. Start the Pi server with sudo so Scapy can read packets.'
            capture_state['lastMessage'] = capture_state['error']
    except subprocess.TimeoutExpired:
        print(f'[SniffPal Pi] Capture timed out', flush=True)
        with capture_lock:
            capture_state['error'] = 'Capture timed out'
            capture_state['lastMessage'] = 'Capture timed out'
    except Exception as e:
        print(f'[SniffPal Pi] Error: {e}', flush=True)
        with capture_lock:
            capture_state['error'] = str(e)
            capture_state['lastMessage'] = str(e)
    finally:
        if os.path.exists(raw_path):
            os.remove(raw_path)
        with capture_lock:
            capture_state['running'] = False
            capture_state['finishedAt'] = datetime.now().isoformat()

# ── Scheduler: use saved settings interval ───────────────────────────────────

_startup_settings = load_settings()
_startup_interval = _startup_settings['interval']

scheduler = BackgroundScheduler()
scheduler.add_job(run_capture, 'interval', minutes=_startup_interval, id='capture_job')
scheduler.start()

print(f'[SniffPal Pi] Scheduler started — capturing every {_startup_interval} minutes', flush=True)
print(f'[SniffPal Pi] Interface: {_startup_settings["interface"]}', flush=True)
print('[SniffPal Pi] Access the dashboard at http://sniffpal.local:8080', flush=True)

# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print('\n[SniffPal Pi] Shutting down...', flush=True)
        scheduler.shutdown()
        sys.exit(0)
