#!/usr/bin/env python3

import os
import json
import warnings
from dotenv import load_dotenv
import requests
from requests.auth import HTTPDigestAuth
import urllib3

# Disable SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

class ArkimeCaller:
    def __init__(self):
        self.base_url = os.getenv('ARKIME_URL', 'https://localhost:8005').rstrip('/')
        self.username = os.getenv('ARKIME_USERNAME')
        self.password = os.getenv('ARKIME_PASSWORD')
        self.verify_ssl = os.getenv('ARKIME_VERIFY_SSL', 'false').lower() == 'true'

        if not self.username or not self.password:
            raise ValueError("ARKIME_USERNAME and ARKIME_PASSWORD must be set in .env file")
        
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(self.username, self.password)
        self.session.verify = self.verify_ssl
        self.session.timeout = 30

    def get_basic_traffic_information(self, ip, time_window_hours):
        """Get traffic metrics for IP within specified time window"""
        params = {
            'date': time_window_hours,
            'expression': f'ip=={ip}',
            'fields': 'source.ip,destination.ip,network.bytes,network.packets',
            'length': 1000
        }

        try:
            response = self.session.get(f'{self.base_url}/api/sessions', params=params)
            
            if response.status_code != 200:
                return self._error_response(ip, time_window_hours, f"HTTP {response.status_code}")
            
            data = response.json()
            sessions = data.get('data', [])
            total_available = data.get('recordsTotal', 0)
            
            if len(sessions) == 0:
                return self._error_response(ip, time_window_hours, "No sessions found")

            # Calculate metrics
            outgoing = incoming = bytes_sent = bytes_received = 0
            destinations = set()
            sources = set()
            
            for session in sessions:
                src = session.get('source', {}).get('ip', '')
                dst = session.get('destination', {}).get('ip', '')
                bytes_count = session.get('network', {}).get('bytes', 0)
                
                if src == ip:  # Outgoing
                    outgoing += 1
                    bytes_sent += bytes_count
                    if dst:
                        destinations.add(dst)
                elif dst == ip:  # Incoming
                    incoming += 1
                    bytes_received += bytes_count
                    if src:
                        sources.add(src)
            
            return {
                "ip_address": ip,
                "time_window_hours": time_window_hours,
                "total_matching_sessions": total_available,
                "analyzed_sessions": len(sessions),
                "outgoing_connections": outgoing,
                "incoming_connections": incoming,
                "total_bytes_sent": bytes_sent,
                "total_bytes_received": bytes_received,
                "unique_destinations": len(destinations),
                "unique_sources": len(sources)
            }
            
        except Exception as e:
            return self._error_response(ip, time_window_hours, str(e))

    def _error_response(self, ip, time_window_hours, error_msg):
        """Return standardized error response"""
        return {
            "ip_address": ip,
            "time_window_hours": time_window_hours,
            "error": error_msg,
            "total_matching_sessions": 0,
            "analyzed_sessions": 0,
            "outgoing_connections": 0,
            "incoming_connections": 0,
            "total_bytes_sent": 0,
            "total_bytes_received": 0,
            "unique_destinations": 0,
            "unique_sources": 0
        }
