"""
IoT Device Traffic & Perception Layer Simulator

This script simulates IoT devices generating normal or malicious traffic,
incorporating concepts of cryptography/authentication to secure the 
Perception Layer.
"""

import time
import random
import hmac
import hashlib

# Shared secret key between devices and network gateway - read from env for security
import os

SECRET_KEY = os.environ.get('SECRET_KEY')
if SECRET_KEY is None:
    raise RuntimeError('SECRET_KEY environment variable not set. Set it to a shared secret for HMAC.')
SECRET_KEY = SECRET_KEY.encode()

def generate_auth_token(device_id):
    """
    Simulation of Authentication (Perception Layer) using HMAC.
    In a real scenario, this uses TLS or DTLS for full encryption.
    """
    timestamp = str(int(time.time()))
    message = f"{device_id}:{timestamp}".encode()
    token = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
    return token, timestamp

def verify_auth_token(device_id, token, timestamp):
    """
    Verifies the device's token. Protects against replay attacks with timestamp check.
    """
    # Prevent replay attacks by making sure the token isn't older than 5 seconds
    if time.time() - int(timestamp) > 5:
        return False
        
    message = f"{device_id}:{timestamp}".encode()
    expected = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)

def simulate_device_behavior(device_id, is_malicious=False):
    """
    Simulates a device sending data, either normal telemetry or a DDoS flood.
    """
    token, timestamp = generate_auth_token(device_id)
    print(f"[{device_id}] Authenticating... HMAC Token: {token[0:10]}...")
    
    if not verify_auth_token(device_id, token, timestamp):
        print(f"[{device_id}] Authentication failed! Connection dropped.")
        return
        
    print(f"[{device_id}] Authentication successful. Securing layer...")
    
    for i in range(5):
        if is_malicious:
            # Simulate DDoS / anomalous behavior like Mirai
            payload = "Malicious Payload Flood!" * 10
            print(f"[{device_id} - ANOMALY] Sending heavy payload: {len(payload)} bytes")
            time.sleep(0.1) # Fast bursts
        else:
            # Simulate normal telemetry (e.g., temperature sensor)
            payload = f"Temperature: {random.uniform(20.0, 25.0):.2f}C"
            print(f"[{device_id} - NORMAL] Sending encrypted telemetry: {payload}")
            time.sleep(1.0) # Normal slow interval

if __name__ == "__main__":
    print("--- Simulating Normal IoT Device ---")
    simulate_device_behavior("Sensor-A", is_malicious=False)
    
    print("\n--- Simulating Compromised IoT Device (Mirai style) ---")
    simulate_device_behavior("Sensor-B", is_malicious=True)
