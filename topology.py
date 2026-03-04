#!/usr/bin/env python3
"""
Mock Mininet Topology for IoT Security Simulation (Windows Compatible)

This script simulates the creation of a network topology with one central switch 
connected to multiple hosts representing IoT devices. It runs without Mininet
so the project can be fully demonstrated on Windows or any platform.
"""

import time
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Mock_Topology")

def create_mock_iot_network():
    logger.info('*** Initializing Mock Topology\n')
    time.sleep(1)
    
    logger.info('*** Adding controller\n')
    logger.info('c0: Mock RemoteController connected at 127.0.0.1:8080 (Flask API)\n')
    time.sleep(1)

    logger.info('*** Adding switches\n')
    logger.info('s1: Main gateway switch handling IoT traffic and enforcing policies\n')
    time.sleep(1)

    logger.info('*** Adding IoT devices (hosts)\n')
    logger.info('h1 (IP: 10.0.0.1, MAC: 00:00:00:00:00:01)')
    logger.info('h2 (IP: 10.0.0.2, MAC: 00:00:00:00:00:02)')
    logger.info('h3 (IP: 10.0.0.3, MAC: 00:00:00:00:00:03)')
    logger.info('h4 (IP: 10.0.0.4, MAC: 00:00:00:00:00:04)\n')
    time.sleep(1)

    logger.info('*** Creating links\n')
    logger.info('(h1) <---> (s1)')
    logger.info('(h2) <---> (s1)')
    logger.info('(h3) <---> (s1)')
    logger.info('(h4) <---> (s1)\n')
    time.sleep(1)

    logger.info('*** Starting network\n')
    logger.info('Mock network simulation is now running...')
    logger.info('Use the web dashboard to see real-time simulated AI threat detection.\n')
    
    try:
        # Keep the mock alive so it looks like it's running
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info('\n*** Stopping mock network\n')

if __name__ == '__main__':
    create_mock_iot_network()
