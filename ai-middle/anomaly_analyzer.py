#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import pandas as pd
import numpy as np
from anomalous_ip import AnomalousIP


class AnomalyAnalyzer:
    def __init__(self):
        self.anomaly_data = []
        self.loaded_files = []
    
    def load_log_file(self, file_path: str) -> bool:
        """Load single JSON log file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            required = ['timestamp', 'update_count', 'nodes_in_graph', 'node_anomalies']
            if not all(field in data for field in required):
                print(f"Warning: {file_path} missing required fields")
                return False
            
            data['source_file'] = os.path.basename(file_path)
            self.anomaly_data.append(data)
            self.loaded_files.append(file_path)
            return True
            
        except (json.JSONDecodeError, FileNotFoundError, Exception) as e:
            print(f"Error loading {file_path}: {e}")
            return False
    
    def _parse_time_range(self, time_range: str) -> datetime:
        """Parse time range string to cutoff datetime"""
        now = datetime.now()
        unit = time_range[-1]
        value = int(time_range[:-1])
        
        if unit == 'h':
            return now - timedelta(hours=value)
        elif unit == 'd':
            return now - timedelta(days=value)
        elif unit == 'w':
            return now - timedelta(weeks=value)
        else:
            raise ValueError(f"Invalid time range: {time_range}. Use '24h', '7d', '1w'")
    
    def _is_file_in_time_range(self, filename: str, cutoff_time: datetime) -> bool:
        """Check if file timestamp is within time range"""
        try:
            parts = filename.split('_')
            if len(parts) >= 3:
                timestamp_str = f"{parts[1]}_{parts[2]}"
                file_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                return file_time >= cutoff_time
        except (ValueError, IndexError):
            pass
        return True
    
    def calculate_composite_score(self, anomaly: Dict, method: str = "weighted") -> float:
        """Calculate composite anomaly score"""
        recon_error = anomaly.get('recon_error', 0.0)
        mlp_score = anomaly.get('mlp_score', 0.0)
        
        if method == "weighted":
            return 0.8 * recon_error + 0.2 * (mlp_score * 20)
        elif method == "max":
            return max(min(recon_error / 15.0, 1.0), mlp_score)
        elif method == "geometric":
            if recon_error > 0 and mlp_score > 0:
                return ((recon_error / 15.0) * mlp_score) ** 0.5
            return recon_error / 15.0
        else:  # normalized fallback
            return recon_error
    
    def get_all_anomalies_flattened(self) -> List[Dict]:
        """Get all anomalies as flat list with metadata"""
        all_anomalies = []
        
        for log_entry in self.anomaly_data:
            metadata = {
                'log_timestamp': log_entry.get('timestamp', 'unknown'),
                'update_count': log_entry.get('update_count', 0),
                'source_file': log_entry.get('source_file', 'unknown'),
                'total_nodes_in_graph': log_entry.get('nodes_in_graph', 0)
            }
            
            for anomaly in log_entry.get('node_anomalies', []):
                enhanced_anomaly = {**anomaly, **metadata}
                enhanced_anomaly['composite_score'] = self.calculate_composite_score(anomaly)
                all_anomalies.append(enhanced_anomaly)
        
        return all_anomalies
    
    def summarize_top_anomalies(self, top_n: int = 10, score_method: str = "weighted") -> None:
        """Generate summary of top anomalous nodes, return a list 2 of anomalous objects whose scores are top"""
        if not self.anomaly_data:
            print("No anomaly data loaded.")
            return
        
        all_anomalies = self.get_all_anomalies_flattened()
        if not all_anomalies:
            print("No anomalies found.")
            return
        
        # Sort by composite score
        sorted_anomalies = sorted(all_anomalies, 
                                key=lambda x: self.calculate_composite_score(x, score_method), 
                                reverse=True)
        
        # Detection methods
        methods = pd.Series([a['detected_by'] for a in all_anomalies]).value_counts()
        for method, count in methods.items():
            print(f"  {method}: {count} ({count/len(all_anomalies)*100:.1f}%)")
        
        anomalous_ips = []

        for i, anomaly in enumerate(sorted_anomalies[:top_n], 1):
            score = self.calculate_composite_score(anomaly, score_method)
            anomalous_ips.append(AnomalousIP(
                ip=anomaly.get('ip', 'N/A'),
                recon_error=anomaly['recon_error'],
                mlp_score=anomaly['mlp_score'],
                detected_by=anomaly['detected_by'],
                log_timestamp=anomaly['log_timestamp'],
                total_nodes_in_graph=anomaly['total_nodes_in_graph'],
                source_file=anomaly['source_file'],
                composite_score = score
            ))
        
        return anomalous_ips
