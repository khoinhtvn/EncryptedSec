#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import pandas as pd
import numpy as np
from anomalous_node import AnomalousNode


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
    
    def summarize_top_anomalies(self, threshold: float = 100.0, score_method: str = "weighted", 
                           filter_fps: bool = True) -> List[AnomalousNode]:
        """Generate summary of anomalous nodes above threshold"""
        if not self.anomaly_data:
            print("No anomaly data loaded.")
            return []
        
        all_anomalies = self.get_all_anomalies_flattened()
        if not all_anomalies:
            print("No anomalies found.")
            return []
        
        # Apply false positive filtering if requested
        if filter_fps:
            all_anomalies = self.filter_false_positives(all_anomalies)
            print(f"After filtering: {len(all_anomalies)} anomalies remaining")
        
        # Recalculate composite scores with specified method
        for anomaly in all_anomalies:
            anomaly['composite_score'] = self.calculate_composite_score(anomaly, score_method)
        
        # Filter by threshold instead of taking top N
        filtered_anomalies = [a for a in all_anomalies if a['composite_score'] > threshold]
        
        # Sort by composite score (highest first)
        sorted_anomalies = sorted(filtered_anomalies, 
                                key=lambda x: x['composite_score'], 
                                reverse=True)
        
        print(f"Found {len(sorted_anomalies)} nodes with composite score > {threshold}")
        
        # Create AnomalousNode objects for all qualifying anomalies
        anomalous_nodes = []
        for anomaly in sorted_anomalies:
            node = AnomalousNode(
                ip=anomaly.get('ip', 'N/A'),
                recon_error=anomaly['recon_error'],
                mlp_score=anomaly['mlp_score'],
                detected_by=anomaly['detected_by'],
                log_timestamp=anomaly['log_timestamp'],
                total_nodes_in_graph=anomaly['total_nodes_in_graph'],
                source_file=anomaly['source_file'],
                composite_score=anomaly['composite_score']
            )
            anomalous_nodes.append(node)
        
        return anomalous_nodes
