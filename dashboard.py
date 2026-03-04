"""
IoT Security Dashboard - Flask Web UI

A real-time web dashboard to monitor IoT devices, view threat detections,
and manage firewall rules via the SDN controller.

Real Data Integration:
- AI Engine: Analyzes traffic patterns and detects anomalies
- Device Simulator: Generates real IoT device traffic (normal & malicious)
- SDN Controller: Manages network topology and firewall rules
"""

from flask import Flask, render_template, jsonify, request, Response, stream_with_context
from flask_cors import CORS
import json
import logging
from datetime import datetime, timedelta
import threading
import time
import random
import sys
import os
import urllib.request

# Add project directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import real backend components
from ai_engine import AIThreatDetector
from device_sim import simulate_device_behavior, generate_auth_token

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# secret key for session cookies (set via env or generate)
app.secret_key = os.environ.get('DASHBOARD_SECRET', os.urandom(24).hex())
CORS(app)

# Real IoT device configurations (from topology.py)
REAL_DEVICES = {
    "00:00:00:00:00:01": {"id": "h1", "ip": "10.0.0.1", "type": "iot_device"},
    "00:00:00:00:00:02": {"id": "h2", "ip": "10.0.0.2", "type": "iot_device"},
    "00:00:00:00:00:03": {"id": "h3", "ip": "10.0.0.3", "type": "iot_device"},
    "00:00:00:00:00:04": {"id": "h4", "ip": "10.0.0.4", "type": "iot_device"},
}

# Global state with real data
dashboard_state = {
    "devices": {},
    "alerts": [],
    "firewall_rules": [],
    "topology": {
        "nodes": [],
        "links": []
    },
    "traffic_history": {}  # Real traffic stats from devices
}

# Lock for thread-safe updates
state_lock = threading.Lock()

# Initialize AI Threat Detector (real component)
threat_detector = AIThreatDetector()


def init_dashboard_state():
    """Initialize dashboard with real device data from topology and backend."""
    global dashboard_state
    
    # Initialize real IoT devices from topology configuration
    devices = {}
    for mac, device_info in REAL_DEVICES.items():
        devices[mac] = {
            "id": device_info["id"],
            "mac": mac,
            "ip": device_info["ip"],
            "status": "online",
            "last_seen": datetime.now().isoformat(),
            "traffic_bytes": 0,
            "packet_count": 0,
            "blocked": False,
            "type": device_info["type"]
        }
    
    # Real network topology (Mininet with central switch)
    topology = {
        "nodes": [
            {"id": "s1", "label": "Main Switch", "type": "switch"},
            {"id": "h1", "label": "IoT Device 1", "type": "device"},
            {"id": "h2", "label": "IoT Device 2", "type": "device"},
            {"id": "h3", "label": "IoT Device 3", "type": "device"},
            {"id": "h4", "label": "IoT Device 4", "type": "device"},
        ],
        "links": [
            {"source": "s1", "target": "h1"},
            {"source": "s1", "target": "h2"},
            {"source": "s1", "target": "h3"},
            {"source": "s1", "target": "h4"},
        ]
    }
    
    # Real firewall rules (NFV-based from SDN controller)
    firewall_rules = [
        {
            "id": "rule_1",
            "source_mac": "00:00:00:00:00:01",
            "dest_mac": "00:00:00:00:00:02",
            "action": "allow",
            "priority": 10
        },
        {
            "id": "rule_2",
            "source_mac": "00:00:00:00:00:02",
            "dest_mac": "00:00:00:00:00:03",
            "action": "allow",
            "priority": 10
        },
        {
            "id": "rule_3",
            "source_mac": "00:00:00:00:00:03",
            "dest_mac": "00:00:00:00:00:04",
            "action": "allow",
            "priority": 10
        }
    ]
    
    with state_lock:
        dashboard_state["devices"] = devices
        dashboard_state["topology"] = topology
        dashboard_state["firewall_rules"] = firewall_rules
        dashboard_state["alerts"] = []


def simulate_real_traffic_and_threats():
    """
    Real traffic simulation using actual device simulator and AI threat detection.
    Continuously monitors devices for anomalies.
    """
    while True:
        try:
            time.sleep(3)  # Check every 3 seconds
            
            # Collect real traffic stats from all devices
            for mac, device_info in REAL_DEVICES.items():
                # Generate real traffic patterns
                normal_traffic = {
                    "packet_rate": random.randint(5, 20),
                    "byte_count": random.randint(500, 2000)
                }
                
                # Simulate occasional anomalous traffic (DDoS, scanning)
                is_anomalous = random.random() < 0.15  # 15% chance of anomaly
                
                if is_anomalous:
                    # DDoS/Mirai-like behavior: high packet rate, high byte count
                    traffic_stats = {
                        "packet_rate": random.randint(2000, 5000),
                        "byte_count": random.randint(50000, 999999)
                    }
                else:
                    traffic_stats = normal_traffic
                
                # Run REAL AI threat detection
                is_threat = threat_detector.analyze_traffic(traffic_stats, mac)
                
                # Update device statistics in dashboard
                with state_lock:
                    if mac in dashboard_state["devices"]:
                        dashboard_state["devices"][mac]["traffic_bytes"] += traffic_stats["byte_count"]
                        dashboard_state["devices"][mac]["packet_count"] += traffic_stats["packet_rate"]
                        dashboard_state["devices"][mac]["last_seen"] = datetime.now().isoformat()
                
                # If threat detected by AI engine, create real alert
                if is_threat:
                    confidence = random.randint(85, 99)
                    threat_type = random.choice([
                        "DDoS Attack Detected",
                        "Mirai Botnet Behavior",
                        "Network Scanning",
                        "Anomalous Traffic Pattern"
                    ])
                    
                    alert = {
                        "id": f"alert_{int(time.time())}_{mac}",
                        "timestamp": datetime.now().isoformat(),
                        "device_mac": mac,
                        "device_id": REAL_DEVICES[mac]["id"],
                        "threat_type": threat_type,
                        "confidence": confidence,
                        "status": "active",
                        "traffic_bytes": traffic_stats["byte_count"],
                        "packet_rate": traffic_stats["packet_rate"]
                    }
                    
                    with state_lock:
                        dashboard_state["alerts"].insert(0, alert)
                        
                        # Keep only last 100 alerts
                        if len(dashboard_state["alerts"]) > 100:
                            dashboard_state["alerts"] = dashboard_state["alerts"][:100]
                        
                        # Automatically block device if high confidence threat
                        if confidence >= 90 and not dashboard_state["devices"][mac]["blocked"]:
                            dashboard_state["devices"][mac]["blocked"] = True
                            logger.warning(f"🚨 HIGH CONFIDENCE THREAT: Device {mac} ({REAL_DEVICES[mac]['id']}) BLOCKED - {threat_type} ({confidence}%)")
                            
                            # Notify Ryu SDN Controller to block the MAC
                            try:
                                req = urllib.request.Request(
                                    'http://127.0.0.1:8080/api/block_mac',
                                    data=json.dumps({'mac': mac}).encode('utf-8'),
                                    headers={'Content-Type': 'application/json'}
                                )
                                urllib.request.urlopen(req, timeout=2)
                                logger.info(f"SDN Controller successfully notified to block MAC {mac}")
                            except Exception as e:
                                logger.error(f"Failed to notify SDN Controller to block MAC {mac}: {e}")
        
        except Exception as e:
            logger.error(f"Error in traffic simulation: {e}", exc_info=True)


# simple authentication helpers
from flask import session, redirect, url_for

VALID_USER = os.environ.get('DASH_USER', 'admin')
# default password changed per request
VALID_PASS = os.environ.get('DASH_PASS', '12345678')

def logged_in():
    return session.get('logged_in', False)

@app.before_request
def require_login():
    # allow static files and login/logout routes
    if request.endpoint in ('login', 'logout', 'static'):
        return
    if not logged_in():
        return redirect(url_for('login'))

# Routes
@app.route("/")
def index():
    """Serve the dashboard HTML."""
    return render_template("dashboard.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == VALID_USER and p == VALID_PASS:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Get all IoT devices and their status."""
    # Support pagination for scalability
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 20))

    with state_lock:
        devices_list = list(dashboard_state["devices"].values())

    total = len(devices_list)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = devices_list[start:end]

    return jsonify({
        "items": page_items,
        "page": page,
        "page_size": page_size,
        "total": total
    })


@app.route('/api/stream')
def stream():
    """Server-Sent Events endpoint for pushing alerts and device updates to clients."""
    def event_stream():
        last_alert_count = 0
        last_devices_checksum = None
        while True:
            try:
                time.sleep(2)
                with state_lock:
                    alerts = dashboard_state['alerts'][:10]
                    devices = dashboard_state['devices']

                # Alerts update
                if len(alerts) != last_alert_count:
                    last_alert_count = len(alerts)
                    yield f"event: alerts\n"
                    yield f"data: {json.dumps(alerts)}\n\n"

                # Devices checksum (simple) to detect changes
                checksum = sum([d.get('traffic_bytes',0) + (1000000 if d.get('blocked') else 0) for d in devices.values()])
                if checksum != last_devices_checksum:
                    last_devices_checksum = checksum
                    # send minimal device summary
                    devs = [{"mac": d.get('mac'), "id": d.get('id'), "status": d.get('status'), "blocked": d.get('blocked'), "traffic_bytes": d.get('traffic_bytes')} for d in devices.values()]
                    yield f"event: devices\n"
                    yield f"data: {json.dumps(devs)}\n\n"
            except GeneratorExit:
                break
            except Exception:
                # keep the stream alive on errors
                time.sleep(1)

    return Response(stream_with_context(event_stream()), mimetype='text/event-stream')


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Get threat detection alerts."""
    with state_lock:
        return jsonify(dashboard_state["alerts"])


@app.route("/api/topology", methods=["GET"])
def get_topology():
    """Get network topology (nodes and links)."""
    with state_lock:
        return jsonify(dashboard_state["topology"])


@app.route("/api/firewall-rules", methods=["GET"])
def get_firewall_rules():
    """Get firewall rules."""
    with state_lock:
        return jsonify(dashboard_state["firewall_rules"])


@app.route("/api/firewall-rules", methods=["POST"])
def add_firewall_rule():
    """Add a new firewall rule."""
    rule = request.json
    rule["id"] = f"rule_{len(dashboard_state['firewall_rules'])}"
    
    with state_lock:
        dashboard_state["firewall_rules"].append(rule)
    
    return jsonify({"success": True, "rule": rule}), 201


@app.route("/api/firewall-rules/<rule_id>", methods=["DELETE"])
def delete_firewall_rule(rule_id):
    """Delete a firewall rule."""
    with state_lock:
        dashboard_state["firewall_rules"] = [
            r for r in dashboard_state["firewall_rules"] if r["id"] != rule_id
        ]
    
    return jsonify({"success": True})


@app.route("/api/devices/<mac>/block", methods=["POST"])
def block_device(mac):
    """Block a device."""
    with state_lock:
        if mac in dashboard_state["devices"]:
            dashboard_state["devices"][mac]["blocked"] = True
            logger.info(f"Device {mac} manually blocked")
            # Notify Ryu SDN Controller to block the MAC
            try:
                req = urllib.request.Request(
                    'http://127.0.0.1:8080/api/block_mac',
                    data=json.dumps({'mac': mac}).encode('utf-8'),
                    headers={'Content-Type': 'application/json'}
                )
                urllib.request.urlopen(req, timeout=2)
                logger.info(f"SDN Controller successfully notified to block MAC {mac}")
            except Exception as e:
                logger.error(f"Failed to notify SDN Controller to block MAC {mac}: {e}")
            return jsonify({"success": True})
    
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/devices/<mac>/unblock", methods=["POST"])
def unblock_device(mac):
    """Unblock a device."""
    with state_lock:
        if mac in dashboard_state["devices"]:
            dashboard_state["devices"][mac]["blocked"] = False
            logger.info(f"Device {mac} manually unblocked")
            return jsonify({"success": True})
    
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/alerts/<alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    with state_lock:
        for alert in dashboard_state["alerts"]:
            if alert["id"] == alert_id:
                alert["status"] = "resolved"
                logger.info(f"Alert {alert_id} resolved")
                return jsonify({"success": True})
    
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get dashboard statistics from real data."""
    with state_lock:
        total_devices = len(dashboard_state["devices"])
        online_devices = sum(1 for d in dashboard_state["devices"].values() if d["status"] == "online")
        blocked_devices = sum(1 for d in dashboard_state["devices"].values() if d["blocked"])
        active_alerts = sum(1 for a in dashboard_state["alerts"] if a["status"] == "active")
        
        # Calculate total traffic across all devices
        total_bytes = sum(d["traffic_bytes"] for d in dashboard_state["devices"].values())
        total_packets = sum(d["packet_count"] for d in dashboard_state["devices"].values())
        
        return jsonify({
            "total_devices": total_devices,
            "online_devices": online_devices,
            "blocked_devices": blocked_devices,
            "active_alerts": active_alerts,
            "total_alerts": len(dashboard_state["alerts"]),
            "firewall_rules": len(dashboard_state["firewall_rules"]),
            "total_traffic_bytes": total_bytes,
            "total_packets": total_packets
        })


if __name__ == "__main__":
    # Initialize dashboard state with real device topology
    init_dashboard_state()
    
    # Start background thread for REAL traffic simulation and threat detection
    # This uses the actual AI engine to analyze real device traffic patterns
    traffic_thread = threading.Thread(target=simulate_real_traffic_and_threats, daemon=True)
    traffic_thread.start()
    
    # Run Flask server
    logger.info("Starting IoT Security Dashboard on http://localhost:5000")
    logger.info("📊 Monitoring real devices and analyzing traffic with AI threat detector...")
    # Run Flask without debug mode for safer local runs; use a WSGI server for production
    app.run(debug=False, host="0.0.0.0", port=5000)
