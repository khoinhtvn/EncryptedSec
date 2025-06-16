"""
LogWatcher

Use Python Watchdog to monitor AI Detector logs at "/sec/ai-detector/output/anomaly_logs/" and feed to AnomalyAnalyzer
"""
#!/usr/bin/env python3

import queue
import threading
import time
import json
from datetime import datetime
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
from anomaly_analyzer import AnomalyAnalyzer
from anomalous_node import AnomalousNode
from arkime_caller import ArkimeCaller

LOG_PATH = "/sec/ai-middle/logs/"

class ArkimeProcessor(FileSystemEventHandler):
    
    def __init__(self):
        # The queue that connects producer and consumer
        self.file_queue = queue.Queue()
        
        # Start background worker
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        print("Background worker started")
    
    # PRODUCER: Fast file detection
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.json'):
            print(f"NEW ALERT FOUND: {event.src_path}")
            self.file_queue.put(event.src_path)  # Add to queue instantly
    
    # CONSUMER: Slow processing in background
    def _worker_loop(self):
        while True:
            try:
                file_path = self.file_queue.get(timeout=1.0)
                print(f"PROCESSING ALERT: {file_path}")
                self._process_file(file_path)
                self.file_queue.task_done()
            except queue.Empty:
                continue  # No files to process, keep waiting
    
    def _process_file(self, file_path):
        # Read alert file
        anomalous_nodes = self._read_alert(file_path)
        
        # Query Arkime for each IP
        results = []

        for node in anomalous_nodes:
            result = self._query_arkime(node.ip)
            results.append(result)
            print(result)

        # Create a new log file, ended with current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"arkime_analysis_{timestamp}.json"

        with open(LOG_PATH + filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"COMPLETED PROCESSING ALERT: {file_path}")
    
    # use Anomaly Analyzer to parse the log and calculate composite scores
    def _read_alert(self, file_path):
        analyzer = AnomalyAnalyzer()

        analyzer.load_log_file(file_path)
        # Only extract the top 1 most suspicious IPs for an alert file
        return analyzer.summarize_top_anomalies(1)
        
    
    def _query_arkime(self, ip):
        caller = ArkimeCaller()
        # set time window to get info is within the last 1 hour
        return caller.get_basic_traffic_information(ip,1)

# Usage
processor = ArkimeProcessor()
# check for new files every 1 sec
observer = PollingObserver(timeout=1)
observer.schedule(processor, "/sec/ai-detector/output/anomaly_logs/", recursive=False)
observer.start()

print("Watching for .json files... (Press Ctrl+C to stop)")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()