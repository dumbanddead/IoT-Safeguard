"""
Mock SDN Controller for IoT Security (Windows Compatible)

This controller acts as a simulated L2 Switch and Virtualized Firewall (NFV).
It replaces the Linux-only Ryu controller to allow the project to run fully 
functioning on Windows for demonstration purposes.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Mock_SDN_Controller")

app = Flask(__name__)
CORS(app)

# Store blocked MAC addresses
blocked_macs = set()

@app.route('/api/block_mac', methods=['POST'])
def block_mac_api():
    """
    NFV Firewall Action: Receives an API call to block a specific MAC.
    This is triggered by the dashboard when the AI engine detects an anomaly.
    """
    try:
        body = request.get_json()
        if not body:
            return jsonify({"error": "Invalid JSON"}), 400
            
        mac_addr = body.get('mac')
        if not mac_addr:
            return jsonify({"error": "mac address required"}), 400
        
        logger.info(f"🔥 FIREWALL ALERT: Blocking MAC address {mac_addr} across all mock switches")
        blocked_macs.add(mac_addr)
            
        return jsonify({
            "success": True, 
            "mac": mac_addr, 
            "message": "MAC blocked on all mock switches"
        }), 200
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/unblock_mac', methods=['POST'])
def unblock_mac_api():
    """Optional endpoint to unblock a MAC address."""
    try:
        body = request.get_json()
        mac_addr = body.get('mac')
        if mac_addr in blocked_macs:
            blocked_macs.remove(mac_addr)
            logger.info(f"✅ FIREWALL: Unblocked MAC address {mac_addr}")
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns the current status of the mock controller."""
    return jsonify({
        "status": "online",
        "type": "Mock_SDN_Controller",
        "blocked_macs": list(blocked_macs)
    }), 200

if __name__ == '__main__':
    logger.info("Starting Mock SDN Controller on port 8080...")
    logger.info("This instance replaces Ryu for Windows compatibility.")
    # Run the server on port 8080 as expected by the dashboard
    app.run(host='127.0.0.1', port=8080, debug=False)
