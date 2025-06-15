#!/usr/bin/env python3

import os
import json
from dotenv import load_dotenv
import requests
from requests.auth import HTTPDigestAuth

load_dotenv()

class ArkimeCaller:
    def __init__(self):
        self.base_url = os.getenv('ARKIME_URL', 'http://localhost:8005')
        self.username = os.getenv('ARKIME_USERNAME')
        self.password = os.getenv('ARKIME_PASSWORD')
        self.verify_ssl = os.getenv('ARKIME_VERIFY_SSL', 'true').lower() == 'true'

        if not self.username or not self.password:
            raise ValueError("ARKIME_USERNAME and ARKIME_PASSWORD must be set in .env file")
        
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(self.username, self.password)
        self.session.verify = self.verify_ssl

        print("Set up done")
    
    def get_basic_traffic_information(self,ip, time_window=1):
        """
        try to get these:
            "time_window": "1h",
            "outgoing_connections": 47,
            "incoming_connections": 3,
            "total_bytes_sent": 1234567,
            "total_bytes_received": 987654,
            "unique_destinations": 15,
            "unique_sources": 2,
        """

        # query parameters for Arkime
        params = {
            'date': time_window, 
            'expression': f'ip=={ip}',
            'fields': 'source.ip,destination.ip,network.bytes'
        }

        response = self.session.get(f'{self.base_url}/api/sessions', params=params)
        sessions = response.json().get('data', [])

        outgoing = incoming = bytes_sent = bytes_received = 0
        destinations = set()
        sources = set()
        
        for session in sessions:
            src = session.get('source.ip', '')
            dst = session.get('destination.ip', '')
            bytes_count = session.get('network.bytes', 0)
            
            if src == ip_address:  # Outgoing
                outgoing += 1
                bytes_sent += bytes_count
                if dst:
                    destinations.add(dst)
            elif dst == ip_address:  # Incoming
                incoming += 1
                bytes_received += bytes_count
                if src:
                    sources.add(src)
        
        return {
            "ip_address": ip,
            "time_window": time_window,
            "outgoing_connections": outgoing,
            "incoming_connections": incoming,
            "total_bytes_sent": bytes_sent,
            "total_bytes_received": bytes_received,
            "unique_destinations": len(destinations),
            "unique_sources": len(sources)
        }
