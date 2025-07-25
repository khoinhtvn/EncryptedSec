"""
LogWatcher

Use Python Watchdog to monitor AI Detector logs at "/sec/ai-detector/output/anomaly_logs/" and feed to AnomalyAnalyzer
"""
#!/usr/bin/env python3

import queue
import threading
import time
import json
import os
import re
from datetime import datetime
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
from anomaly_analyzer import AnomalyAnalyzer
from anomalous_node import AnomalousNode
from arkime_caller import ArkimeCaller

LOG_PATH = "/sec/ai-middle/logs/"
THRESHOLD = 100


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
        if not event.is_directory and event.src_path.endswith(".json"):
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
        anomalous_nodes = self._read_alert(file_path)

        if not anomalous_nodes:
            print(f"No anomalies found in {file_path}, skipping...")
            return

        formatted_timestamp = self._parse_timestamp_from_filename(file_path)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"arkime_analysis_{timestamp}.ndjson"

        with open(LOG_PATH + filename, "w") as f:
            for node in anomalous_nodes:
                result = self._query_arkime(node.ip)

                document = {
                    "@timestamp": formatted_timestamp,
                    "ip_address": result.get("ip_address"),
                    "time_window_hours": result.get("time_window_hours"),
                    "total_matching_sessions": result.get("total_matching_sessions", 0),
                    "analyzed_sessions": result.get("analyzed_sessions", 0),
                    "outgoing_connections": result.get("outgoing_connections", 0),
                    "incoming_connections": result.get("incoming_connections", 0),
                    "total_bytes_sent": result.get("total_bytes_sent", 0),
                    "total_bytes_received": result.get("total_bytes_received", 0),
                    "unique_destinations": result.get("unique_destinations", 0),
                    "unique_sources": result.get("unique_sources", 0),
                    "composite_score": node.composite_score,
                }

                if "error" in result:
                    document["arkime_error"] = result["error"]

                f.write(json.dumps(document) + "\n")

        print(f"COMPLETED PROCESSING ALERT: {file_path}")

    def _parse_timestamp_from_filename(self, file_path):
        try:
            # Extract just the filename from the full path
            filename = os.path.basename(file_path)

            # Extract timestamp
            pattern = r"(\d{8})_(\d{6})"
            match = re.search(pattern, filename)

            if not match:
                print(f"Warning: No timestamp found in filename: {filename}")
                return None

            date_str = match.group(1)  # YYYYMMDD
            time_str = match.group(2)  # HHMMSS

            dt = datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S")

            # Format time like "@timestamp":"2025-06-20T15:29:26.000Z"
            formatted_timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            return formatted_timestamp

        except Exception as e:
            print(f"Error parsing timestamp from {file_path}: {e}")
            return None

    # use Anomaly Analyzer to parse the log and calculate composite scores
    def _read_alert(self, file_path):
        analyzer = AnomalyAnalyzer()

        analyzer.load_log_file(file_path)
        # Only extract the IPs having a composite score over 100
        return analyzer.summarize_top_anomalies(THRESHOLD)

    def _query_arkime(self, ip):
        caller = ArkimeCaller()
        # set time window to get info is within the last 1 hour
        return caller.get_basic_traffic_information(ip, 1)


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
