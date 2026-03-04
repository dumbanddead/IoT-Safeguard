# IoT Security with SDN, NFV, and AI

## Architecture Overview
This project simulates an IoT environment secured via a Software-Defined Network (SDN).
It demonstrates coupling a centralized controller (Ryu) capable of dynamically configuring virtual firewalls (NFV) based on signals from Artificial Intelligence anomaly detection models.

## Components
1. **Network Simulation:** A Mininet topology script (`topology.py`) simulates a central switch with multiple interconnected IoT devices (hosts).
2. **SDN Controller:** A Ryu controller script (`controller.py`) acts as the "brain," managing traffic and enforcing the Virtual Firewall.
3. **AI Anomaly Detection:** A mock engine (`ai_engine.py`) designed to receive traffic statistics and flag malicious behavior.
4. **Device Simulator:** An IoT device sim (`device_sim.py`) that acts as a secure sensor node via HMAC perception-layer authentication, capable of anomalous traffic generation (like DDoS/Mirai floods).

## Prerequisites
To run the full simulation on any platform (including Windows), you need:
- Python 3.x
- Flask (`pip install Flask flask-cors`)

## How to Run

1. **Start the Mock Controller:**
   Open a terminal and run the mock SDN controller application (listens on port 8080):
   ```bash
   python controller.py
   ```

2. **Start the Mock Topology Simulation:**
   In another terminal, run the topology script to simulate the network:
   ```bash
   python topology.py
   ```

3. **Run the Dashboard (required for browser UI):**
   The HTML template is served by a Flask backend which provides APIs, a
   login page, and an SSE stream. Do *not* open the template directly from
   disk.   

   Before starting the server set some environment variables for the HMAC
   simulator and the login credentials, e.g.:
   ```bash
   export SECRET_KEY='demo-secret-123'        # used by device_sim.py
   export DASH_USER='admin'                  # dashboard username
   export DASH_PASS='12345678'               # dashboard password (default changed)
   export DASHBOARD_SECRET='supersecret'     # Flask session secret
   python3 dashboard.py
   ```
   
   On Windows PowerShell you can use `setx` or `$env:VAR='value'` instead.

   Point your browser at <http://localhost:5000/> and enter the username
   and password above.  The page will redirect to the dashboard once
   authenticated; unauthenticated API calls return 302 to `/login`.

4. **Simulate AI Inference:**
   You can run `python3 ai_engine.py` individually to see how the threat detection model operates conceptually.

5. **Simulate IoT Traffic:**
   You can run `python3 device_sim.py` to test the mock authentication mechanism and data transfer at the Perception Layer.
