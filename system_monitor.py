"""
System Monitor - Tracks CPU, RAM, and Disk I/O during module execution
"""

import psutil
import time
import threading
from typing import Dict, List, Tuple


class SystemMonitor:
    """Monitors system resources during module execution"""

    def __init__(self, interval: float = 0.1):
        """
        Initialize system monitor

        Args:
            interval: Sampling interval in seconds (default: 0.1s)
        """
        self.interval = interval
        self.monitoring = False
        self.monitor_thread = None

        # Metrics storage
        self.cpu_samples: List[float] = []
        self.ram_delta_samples: List[float] = []  # Delta from baseline in MB
        self.ram_baseline_mb: float = 0.0          # RAM used before test starts
        self.disk_io_start: Tuple[int, int] = (0, 0)
        self.disk_io_end: Tuple[int, int] = (0, 0)

        # Detection tracking
        self.detection_time: float = None
        self.test_start_time: float = None

    def _get_used_ram_mb(self) -> float:
        """Return current system RAM used in MB"""
        mem = psutil.virtual_memory()
        return (mem.total - mem.available) / (1024 * 1024)

    def start(self):
        """Start monitoring system resources"""
        self.monitoring = True
        self.cpu_samples = []
        self.ram_delta_samples = []
        self.test_start_time = time.time()

        # Capture RAM baseline BEFORE the test begins
        self.ram_baseline_mb = self._get_used_ram_mb()

        # Get initial disk I/O
        disk_io = psutil.disk_io_counters()
        self.disk_io_start = (disk_io.read_bytes, disk_io.write_bytes)

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        """Stop monitoring system resources"""
        self.monitoring = False

        # Get final disk I/O
        disk_io = psutil.disk_io_counters()
        self.disk_io_end = (disk_io.read_bytes, disk_io.write_bytes)

        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)

    def mark_detection(self):
        """Mark the time when AV detection occurred"""
        if self.test_start_time and not self.detection_time:
            self.detection_time = time.time() - self.test_start_time

    def _monitor_loop(self):
        """Monitoring loop running in separate thread"""
        while self.monitoring:
            # CPU usage (non-blocking, uses last interval)
            cpu = psutil.cpu_percent(interval=None)
            self.cpu_samples.append(cpu)

            # RAM delta: how much MORE RAM is being used compared to baseline
            current_ram = self._get_used_ram_mb()
            delta = current_ram - self.ram_baseline_mb
            # Clamp to 0 so we never report negative delta
            self.ram_delta_samples.append(max(0.0, delta))

            time.sleep(self.interval)

    def get_results(self) -> Dict:
        """
        Get monitoring results

        Returns:
            Dictionary containing all metrics
        """
        # CPU metrics
        cpu_avg = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0
        cpu_peak = max(self.cpu_samples) if self.cpu_samples else 0

        # RAM delta metrics in MB (activity above baseline)
        ram_avg = sum(self.ram_delta_samples) / len(self.ram_delta_samples) if self.ram_delta_samples else 0
        ram_peak = max(self.ram_delta_samples) if self.ram_delta_samples else 0

        # Disk I/O metrics in MB
        disk_read_mb = (self.disk_io_end[0] - self.disk_io_start[0]) / (1024 * 1024)
        disk_write_mb = (self.disk_io_end[1] - self.disk_io_start[1]) / (1024 * 1024)

        return {
            'cpu_avg': round(cpu_avg, 1),
            'cpu_peak': round(cpu_peak, 1),
            'ram_avg': round(ram_avg, 2),    # Delta MB average
            'ram_peak': round(ram_peak, 2),  # Delta MB peak
            'disk_read_mb': round(disk_read_mb, 2),
            'disk_write_mb': round(disk_write_mb, 2),
            'detection_time': round(self.detection_time, 2) if self.detection_time else None
        }

    def reset(self):
        """Reset all metrics"""
        self.cpu_samples = []
        self.ram_delta_samples = []
        self.ram_baseline_mb = 0.0
        self.disk_io_start = (0, 0)
        self.disk_io_end = (0, 0)
        self.detection_time = None
        self.test_start_time = None
