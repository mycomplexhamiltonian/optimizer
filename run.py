#!/usr/bin/env python3
"""
Network Optimizer with TRUE Drift Compensation - STABLE VERSION with RESET
Uses A/B/A testing pattern with stability enforcement and network reset on instability
"""
import subprocess
import time
import sys
import os
import socket
import numpy as np
from scipy import stats
import random
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from collections import defaultdict, deque
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Configuration
TEST_IPS = ["13.115.28.52", "54.150.62.59", "52.199.243.141"]
INTERFACE = "enp39s0"

# Testing parameters
BURST_DURATION_MS = 300       # 300ms test bursts (reduced to avoid throttling)
SAMPLES_PER_TEST = 2          # 2 samples per condition (reduced for faster testing)
STABILITY_THRESHOLD = 0.15    # Max 15% CV for stability
PARALLEL_CONNECTIONS = 10     # Parallel TCP connections
CONNECTION_TIMEOUT = 0.8      # 800ms timeout
MIN_IMPROVEMENT_THRESHOLD = 0.05  # 5% improvement required
QUICK_MODE = False           # Set True to only test high-impact settings
TEST_ITERATIONS = 1          # Number of times to run the full test suite
# MAX_RETRIES removed - now using infinite retries
MAX_DRIFT_PERCENT = 15      # Maximum acceptable drift percentage
INSTABILITY_THRESHOLD = 2.5  # If latency > baseline * this, network is unstable
RESET_WAIT_TIME = 30        # Seconds to wait after network reset

class DriftCompensatingOptimizer:
    def __init__(self):
        self.interface = INTERFACE
        self.best_ip = None
        self.original_settings = {}
        self.abort_testing = False
        self.baseline_cache = {}  # Cache for baseline latencies
        self.stability_wait_time = 5  # Seconds to wait when unstable
        self.good_baseline = None  # Track the good baseline separately
        self.ip_rotation_index = 0  # For rotating through IPs after resets
        self.instability_count = 0  # Track consecutive instabilities
        self.last_reset_time = 0   # Track when we last did a reset
        self.results_file = None  # Real-time results file
        self.test_start_time = time.time()  # Track when testing started
        self.skipped_optimizations = []  # Track which optimizations were skipped
        
        # COMPLETE list of optimizations with priority levels
        self.all_optimizations = {
            # HIGH PRIORITY - Test these first
            'tcp_congestion': {
                'param': 'net.ipv4.tcp_congestion_control',
                'values': ['cubic', 'bbr', 'yeah', 'htcp', 'hybla', 'illinois', 'vegas'],
                'type': 'sysctl',
                'priority': 1
            },
            'tcp_fastopen': {
                'param': 'net.ipv4.tcp_fastopen',
                'values': ['0', '1', '3'],
                'type': 'sysctl',
                'priority': 1
            },
            'busy_poll': {
                'param': 'net.core.busy_poll',
                'values': ['0', '50', '100', '200'],
                'type': 'sysctl',
                'priority': 1
            },
            'busy_read': {
                'param': 'net.core.busy_read',
                'values': ['0', '50', '100', '200'],
                'type': 'sysctl',
                'priority': 1
            },
            'rx_coalesce': {
                'param': 'rx-usecs',
                'values': ['0', '1', '10', '25'],
                'type': 'ethtool_coalesce',
                'priority': 1
            },
            'tx_coalesce': {
                'param': 'tx-usecs',
                'values': ['0', '1', '10', '25'],
                'type': 'ethtool_coalesce',
                'priority': 1
            },
            'adaptive_rx': {
                'param': 'adaptive-rx',
                'values': ['on', 'off'],
                'type': 'ethtool_coalesce',
                'priority': 1
            },
            'adaptive_tx': {
                'param': 'adaptive-tx',
                'values': ['on', 'off'],
                'type': 'ethtool_coalesce',
                'priority': 1
            },
            
            # MEDIUM PRIORITY
            'tcp_slow_start': {
                'param': 'net.ipv4.tcp_slow_start_after_idle',
                'values': ['0', '1'],
                'type': 'sysctl',
                'priority': 2
            },
            'tcp_tw_reuse': {
                'param': 'net.ipv4.tcp_tw_reuse',
                'values': ['0', '1', '2'],
                'type': 'sysctl',
                'priority': 2
            },
            'tcp_low_latency': {
                'param': 'net.ipv4.tcp_low_latency',
                'values': ['0', '1'],
                'type': 'sysctl',
                'priority': 2
            },
            'tcp_no_metrics': {
                'param': 'net.ipv4.tcp_no_metrics_save',
                'values': ['0', '1'],
                'type': 'sysctl',
                'priority': 2
            },
            'netdev_budget': {
                'param': 'net.core.netdev_budget',
                'values': ['300', '600', '1000'],
                'type': 'sysctl',
                'priority': 2
            },
            'netdev_backlog': {
                'param': 'net.core.netdev_max_backlog',
                'values': ['1000', '5000', '10000'],
                'type': 'sysctl',
                'priority': 2
            },
            'napi_weight': {
                'param': 'net.core.dev_weight',
                'values': ['64', '128', '256'],
                'type': 'sysctl',
                'priority': 2
            },
            'ring_rx': {
                'param': 'rx',
                'values': ['512', '1024', '2048', '4096'],
                'type': 'ethtool_ring',
                'priority': 2
            },
            'ring_tx': {
                'param': 'tx',
                'values': ['512', '1024', '2048', '4096'],
                'type': 'ethtool_ring',
                'priority': 2
            },
            
            # LOW PRIORITY - Less likely to help for 100 websockets
            'tcp_fin_timeout': {
                'param': 'net.ipv4.tcp_fin_timeout',
                'values': ['60', '30', '15'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_syn_retries': {
                'param': 'net.ipv4.tcp_syn_retries',
                'values': ['6', '3', '2'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_synack_retries': {
                'param': 'net.ipv4.tcp_synack_retries',
                'values': ['5', '2', '1'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_retries2': {
                'param': 'net.ipv4.tcp_retries2',
                'values': ['15', '8', '5'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_keepalive_time': {
                'param': 'net.ipv4.tcp_keepalive_time',
                'values': ['7200', '600', '120'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_keepalive_intvl': {
                'param': 'net.ipv4.tcp_keepalive_intvl',
                'values': ['75', '30', '10'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_keepalive_probes': {
                'param': 'net.ipv4.tcp_keepalive_probes',
                'values': ['9', '5', '3'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_rmem': {
                'param': 'net.ipv4.tcp_rmem',
                'values': ['4096 87380 6291456', '4096 131072 6291456', '8192 131072 12582912'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_wmem': {
                'param': 'net.ipv4.tcp_wmem',
                'values': ['4096 16384 4194304', '4096 65536 16777216', '8192 65536 16777216'],
                'type': 'sysctl',
                'priority': 3
            },
            'tcp_mem': {
                'param': 'net.ipv4.tcp_mem',
                'values': ['786432 1048576 1572864', '1572864 2097152 3145728'],
                'type': 'sysctl',
                'priority': 3
            }
        }
        
        # Filter based on priority
        if QUICK_MODE:
            self.optimizations = {k: v for k, v in self.all_optimizations.items() if v['priority'] == 1}
            print("⚡ Quick mode: Testing only HIGH priority optimizations")
        else:
            self.optimizations = self.all_optimizations
    
    def perform_network_reset(self):
        """Perform a full network reset when instability detected"""
        print("\n" + "="*70)
        print("🔄 PERFORMING NETWORK RESET")
        print("="*70)
        
        self.last_reset_time = time.time()
        
        # Kill all connections to test IPs
        print("  1. Killing all test connections...")
        for ip in TEST_IPS:
            subprocess.run(f"ss -K dst {ip} 2>/dev/null", shell=True, capture_output=True)
        
        # Clear conntrack
        print("  2. Clearing connection tracking...")
        subprocess.run("conntrack -F 2>/dev/null", shell=True, capture_output=True)
        
        # Clear route cache
        print("  3. Flushing route cache...")
        subprocess.run("ip route flush cache 2>/dev/null", shell=True, capture_output=True)
        
        # Reset TCP metrics
        print("  4. Clearing TCP metrics...")
        subprocess.run("ip tcp_metrics flush all 2>/dev/null", shell=True, capture_output=True)
        
        # Restart network interface (if safe to do so)
        print("  5. Cycling network interface...")
        subprocess.run(f"ethtool -r {self.interface} 2>/dev/null", shell=True, capture_output=True)
        
        # Rotate to next IP
        self.ip_rotation_index = (self.ip_rotation_index + 1) % len(TEST_IPS)
        new_ip = TEST_IPS[self.ip_rotation_index]
        print(f"  6. Rotating to next test IP: {new_ip}")
        self.best_ip = new_ip
        
        # Clear baseline cache
        print("  7. Clearing baseline cache...")
        self.baseline_cache = {}
        self.instability_count = 0
        
        # Wait for network to settle
        print(f"  8. Waiting {RESET_WAIT_TIME}s for network to settle...")
        for i in range(RESET_WAIT_TIME, 0, -1):
            print(f"     {i}s remaining...", end='\r')
            time.sleep(1)
        print(" " * 50, end='\r')  # Clear the line
        
        # Re-establish baseline
        print("  9. Re-establishing baseline...")
        result = self.measure_latency(samples=5)
        if result:
            self.good_baseline = result['p50']
            self.baseline_cache['baseline'] = result['p50']
            print(f"  ✅ New baseline established: {result['p50']:.1f}μs")
        else:
            print("  ⚠️ Could not establish new baseline")
        
        print("="*70 + "\n")
    
    def check_and_handle_instability(self, current_latency):
        """Check if network is unstable and handle it"""
        if not self.good_baseline:
            return False
        
        # Check if we've crossed the instability threshold
        if current_latency > self.good_baseline * INSTABILITY_THRESHOLD:
            self.instability_count += 1
            
            # If we've seen instability 3+ times in a row, do a reset
            if self.instability_count >= 3:
                # Don't reset too frequently
                time_since_reset = time.time() - self.last_reset_time
                if time_since_reset > 60:  # At least 1 minute between resets
                    print(f"\n⚠️ Severe instability detected ({current_latency:.0f}μs vs {self.good_baseline:.0f}μs baseline)")
                    print(f"   Instability count: {self.instability_count}")
                    self.perform_network_reset()
                    return True
            return False
        else:
            # Reset counter if we get a good reading
            if current_latency < self.good_baseline * 1.5:
                self.instability_count = 0
            return False
    
    def init_results_file(self):
        """Initialize real-time results file"""
        # Create results directory if it doesn't exist
        results_dir = "optimization_results"
        os.makedirs(results_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_file = f"{results_dir}/realtime_{timestamp}.txt"
        
        with open(self.results_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("NETWORK OPTIMIZATION - REAL-TIME RESULTS\n")
            f.write("="*80 + "\n\n")
            f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Test IPs: {', '.join(TEST_IPS)}\n")
            f.write(f"Mode: {'Quick (HIGH priority only)' if QUICK_MODE else 'Full (all priorities)'}\n")
            f.write("\n" + "="*80 + "\n\n")
            f.write("LIVE RESULTS (saved as found):\n")
            f.write("-"*60 + "\n\n")
        
        print(f"📝 Real-time results file: {self.results_file}")
    
    def save_test_result(self, opt_name, test_value, original, improvement, improvement_pct, drift, baseline_avg, test_avg):
        """Save a test result immediately to file"""
        if not self.results_file:
            return
        
        config = self.optimizations[opt_name]
        
        with open(self.results_file, 'a') as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {opt_name}\n")
            f.write(f"  Original: {original}\n")
            f.write(f"  Tested: {test_value}\n")
            f.write(f"  Baseline avg: {baseline_avg:.1f}μs\n")
            f.write(f"  Test avg: {test_avg:.1f}μs\n")
            f.write(f"  Drift: {drift:.1f}%\n")
            f.write(f"  Improvement: {improvement:.1f}μs ({improvement_pct:.1f}%)\n")
            f.write(f"  Status: ✓ VALID (improvement > drift)\n")
            
            # Add the command to apply this setting
            if config['type'] == 'sysctl':
                f.write(f"  Command: sysctl -w {config['param']}={test_value}\n")
            elif config['type'] == 'ethtool_coalesce':
                f.write(f"  Command: ethtool -C {self.interface} {config['param']} {test_value}\n")
            elif config['type'] == 'ethtool_ring':
                f.write(f"  Command: ethtool -G {self.interface} {config['param']} {test_value}\n")
            
            f.write("\n")
            f.flush()  # Ensure it's written to disk immediately
    
    def save_current_settings(self):
        """Save all current system settings"""
        print("📁 Saving current system settings...")
        
        for name, config in self.optimizations.items():
            try:
                if config['type'] == 'sysctl':
                    result = subprocess.run(f"sysctl -n {config['param']}", 
                                          shell=True, capture_output=True, text=True)
                    value = result.stdout.strip()
                    if value:
                        self.original_settings[name] = value
                        priority = config.get('priority', 3)
                        pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                        print(f"  [{pri_label}] {name}: {value}")
                        
                elif config['type'] == 'ethtool_coalesce':
                    result = subprocess.run(f"ethtool -c {self.interface} 2>/dev/null | grep '{config['param']}:' | head -1",
                                          shell=True, capture_output=True, text=True)
                    if result.stdout:
                        value = result.stdout.split(':')[1].strip()
                        self.original_settings[name] = value
                        priority = config.get('priority', 3)
                        pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                        print(f"  [{pri_label}] {name}: {value}")
                        
                elif config['type'] == 'ethtool_ring':
                    result = subprocess.run(f"ethtool -g {self.interface} 2>/dev/null | grep '{config['param'].upper()}:' | tail -1",
                                          shell=True, capture_output=True, text=True)
                    if result.stdout:
                        value = result.stdout.split(':')[1].strip()
                        self.original_settings[name] = value
                        priority = config.get('priority', 3)
                        pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                        print(f"  [{pri_label}] {name}: {value}")
            except:
                pass
    
    def restore_original_settings(self):
        """Restore original system settings"""
        for name, value in self.original_settings.items():
            try:
                self.apply_setting(name, value, silent=True)
            except:
                pass
        time.sleep(0.5)
    
    def apply_setting(self, name, value, silent=False):
        """Apply a single setting"""
        config = self.optimizations[name]
        
        # Clear TCP state
        subprocess.run(f"ss -K dst {self.best_ip} 2>/dev/null", shell=True, capture_output=True)
        
        try:
            if config['type'] == 'sysctl':
                cmd = f"sysctl -w {config['param']}={value} 2>/dev/null"
            elif config['type'] == 'ethtool_coalesce':
                cmd = f"ethtool -C {self.interface} {config['param']} {value} 2>/dev/null"
            elif config['type'] == 'ethtool_ring':
                cmd = f"ethtool -G {self.interface} {config['param']} {value} 2>/dev/null"
            else:
                return False
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            # Wait for setting to take effect
            # Different settings need different stabilization times
            if config['type'] == 'ethtool_ring':
                time.sleep(1.5)  # Ring buffer changes may reset the interface
            elif config['type'] == 'ethtool_coalesce':
                time.sleep(0.8)  # Interrupt coalescing needs time to settle
            else:
                time.sleep(0.5)  # Sysctl changes are quick
            
            return result.returncode == 0
            
        except Exception as e:
            if not silent:
                print(f"  Error applying {name}={value}: {e}")
            return False
    
    def test_tcp_burst(self, duration_ms):
        """Test TCP with parallel connections"""
        if not self.best_ip:
            return []
        
        def single_connection():
            """Single connection test"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(CONNECTION_TIMEOUT)
            
            try:
                start = time.perf_counter_ns()
                sock.connect((self.best_ip, 443))
                end = time.perf_counter_ns()
                sock.close()
                
                latency_us = (end - start) / 1000
                if latency_us < 100000:  # < 100ms sanity check
                    return latency_us
                return None
            except:
                try:
                    sock.close()
                except:
                    pass
                return None
        
        latencies = []
        end_time = time.time() + (duration_ms / 1000.0)
        
        with ThreadPoolExecutor(max_workers=PARALLEL_CONNECTIONS) as executor:
            while time.time() < end_time and not self.abort_testing:
                futures = [executor.submit(single_connection) 
                          for _ in range(PARALLEL_CONNECTIONS)]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        latencies.append(result)
                
                time.sleep(0.01)
        
        return latencies
    
    def measure_latency(self, samples=SAMPLES_PER_TEST):
        """Get stable latency measurement"""
        all_latencies = []
        
        for _ in range(samples):
            latencies = self.test_tcp_burst(BURST_DURATION_MS)
            if latencies and len(latencies) > 20:
                all_latencies.extend(latencies)
            time.sleep(0.1)
        
        if len(all_latencies) < 50:
            return None
        
        # Remove outliers
        all_latencies = np.array(all_latencies)
        p5, p95 = np.percentile(all_latencies, [5, 95])
        clean = all_latencies[(all_latencies >= p5) & (all_latencies <= p95)]
        
        if len(clean) < 30:
            return None
        
        # Check for instability
        median_latency = np.percentile(clean, 50)
        if self.check_and_handle_instability(median_latency):
            return None  # Return None to trigger retry
        
        return {
            'p50': median_latency,
            'p25': np.percentile(clean, 25),
            'p75': np.percentile(clean, 75),
            'mean': np.mean(clean),
            'std': np.std(clean),
            'cv': np.std(clean) / np.mean(clean),
            'samples': len(clean)
        }
    
    def wait_for_stability(self, expected_baseline=None):
        """Wait for network to stabilize - with recovery detection and reset"""
        print("    ⏳ Waiting for stability...", end='', flush=True)
        
        stable_readings = []
        high_latency_count = 0
        wait_attempts = 0
        max_wait_attempts = 20  # Increased from 10
        
        while wait_attempts < max_wait_attempts:
            wait_attempts += 1
            result = self.measure_latency(samples=2)
            if not result:
                time.sleep(2)
                continue
            
            current_latency = result['p50']
            
            # Check for severe instability
            if self.good_baseline and current_latency > self.good_baseline * INSTABILITY_THRESHOLD:
                high_latency_count += 1
                print(f"\n      Unstable: {current_latency:.0f}μs vs expected ~{expected_baseline or self.good_baseline:.0f}μs", end='')
                
                # If we see 3+ high readings, trigger reset
                if high_latency_count >= 3:
                    print("\n      Too many unstable readings, triggering reset...")
                    self.perform_network_reset()
                    return self.good_baseline
                
                time.sleep(self.stability_wait_time)
                continue
            else:
                high_latency_count = 0  # Reset counter on good reading
            
            # RECOVERY DETECTION: If current is MUCH better than expected, network recovered!
            if expected_baseline and current_latency < expected_baseline * 0.3:
                print(f"\n      ✅ Network recovered: {current_latency:.0f}μs (was expecting ~{expected_baseline:.0f}μs)")
                self.baseline_cache['baseline'] = current_latency
                self.good_baseline = current_latency  # Remember the good baseline
                self.instability_count = 0  # Reset instability counter
                return current_latency
            
            # If we have a good baseline stored and current matches it, we're stable
            if self.good_baseline and abs(current_latency - self.good_baseline) / self.good_baseline < 0.2:
                print(f" Stable at good baseline {current_latency:.0f}μs")
                self.baseline_cache['baseline'] = current_latency
                self.instability_count = 0  # Reset instability counter
                return current_latency
            
            # If we have an expected baseline, check if we're close
            if expected_baseline:
                deviation = abs(current_latency - expected_baseline) / expected_baseline
                if deviation > 0.5:  # More than 50% off
                    # Check if this might be a new good baseline
                    if current_latency < 500 and result['cv'] < 0.20:
                        print(f"\n      Found new good baseline: {current_latency:.0f}μs")
                        self.baseline_cache['baseline'] = current_latency
                        self.good_baseline = current_latency
                        self.instability_count = 0
                        return current_latency
                    else:
                        print(f"\n      Unstable: {current_latency:.0f}μs vs expected ~{expected_baseline:.0f}μs", end='')
                        time.sleep(self.stability_wait_time)
                        continue
            
            # Check CV for stability
            if result['cv'] < 0.20:  # Less than 20% variation
                stable_readings.append(current_latency)
                if len(stable_readings) >= 2:
                    print(f" Stable at {current_latency:.0f}μs")
                    # Update baseline if this is better
                    if not self.good_baseline or current_latency < self.good_baseline * 1.5:
                        self.baseline_cache['baseline'] = current_latency
                        if current_latency < 500:  # Likely a good baseline
                            self.good_baseline = current_latency
                            self.instability_count = 0
                    return current_latency
            else:
                stable_readings = []
            
            time.sleep(2)
        
        # After max attempts, perform a network reset and try again
        print(" ⚠️ Could not stabilize after many attempts, performing reset")
        self.perform_network_reset()
        return self.good_baseline if self.good_baseline else None
    
    def test_with_aba_pattern_stable(self, opt_name, test_value, original):
        """Single A/B/A/B/A test with infinite retries until successful"""
        retry = 0
        consecutive_failures = 0
        no_improvement_count = 0  # Track tests with no significant improvement
        max_retries_before_reset = 10  # Reset network after 10 retries
        apply_failures = 0  # Track failures to apply settings
        max_apply_failures = 3  # Skip setting after 3 failed attempts to apply
        
        while True:  # Keep retrying indefinitely
            if self.abort_testing:
                return None, None
            
            if retry > 0:
                print(f"    Retry {retry} (will keep trying until successful)...")
                
                # Check if we've hit the retry limit and should reset
                if retry >= max_retries_before_reset:
                    print(f"    ⚠️ Hit {max_retries_before_reset} retries, triggering network reset...")
                    self.perform_network_reset()
                    retry = 0  # Reset retry counter after network reset
                    consecutive_failures = 0
                    no_improvement_count = 0
                    continue
                
                # Use good baseline if we have it, otherwise current baseline
                expected = self.good_baseline if self.good_baseline else self.baseline_cache.get('baseline', 500)
                stable_latency = self.wait_for_stability(expected)
                if not stable_latency:
                    consecutive_failures += 1
                    # If we can't stabilize after many retries, might need reset
                    if consecutive_failures > 5:
                        print("    Too many failed stabilization attempts, triggering reset")
                        self.perform_network_reset()
                        consecutive_failures = 0  # Reset counter after network reset
                    continue
                else:
                    consecutive_failures = 0  # Reset counter on success
            
            # A1: First baseline
            if not self.apply_setting(opt_name, original):
                print(f"    Failed to apply original setting: {original}")
                apply_failures += 1
                if apply_failures >= max_apply_failures:
                    print(f"    ⚠️ Skipping {opt_name}: Unable to apply settings (incompatible or requires different permissions)")
                    self.skipped_optimizations.append((opt_name, "Cannot apply original setting"))
                    return None, None  # Skip this optimization entirely
                retry += 1
                continue
                
            print(f"    A1 (baseline)...", end='', flush=True)
            baseline_a1 = self.measure_latency()
            if not baseline_a1:
                print(" Failed to measure")
                retry += 1
                continue
            print(f" {baseline_a1['p50']:.1f}μs")
            apply_failures = 0  # Reset counter after successful apply and measure
            
            # Check if baseline is in bad state
            if self.good_baseline and baseline_a1['p50'] > self.good_baseline * INSTABILITY_THRESHOLD:
                print(f"    ⚠️ Network degraded, triggering reset...")
                consecutive_failures += 1
                if consecutive_failures > 2:  # Reset after fewer failures in degraded state
                    self.perform_network_reset()
                    consecutive_failures = 0
                else:
                    time.sleep(5)  # Wait a bit before retrying
                retry += 1
                continue
            
            # B1: First test value measurement
            if not self.apply_setting(opt_name, test_value):
                print(f"    Failed to apply test setting: {test_value}")
                apply_failures += 1
                if apply_failures >= max_apply_failures:
                    print(f"    ⚠️ Skipping {opt_name}: Unable to apply test value {test_value}")
                    self.skipped_optimizations.append((opt_name, f"Cannot apply test value: {test_value}"))
                    return None, None  # Skip this optimization entirely
                retry += 1
                continue
                
            print(f"    B1 ({test_value})...", end='', flush=True)
            test_b1 = self.measure_latency()
            if not test_b1:
                print(" Failed to measure")
                retry += 1
                continue
            print(f" {test_b1['p50']:.1f}μs")
            
            # A2: Second baseline
            if not self.apply_setting(opt_name, original):
                print(f"    Failed to apply original setting (A2): {original}")
                retry += 1
                continue
                
            print(f"    A2 (baseline)...", end='', flush=True)
            baseline_a2 = self.measure_latency()
            if not baseline_a2:
                print(" Failed to measure")
                retry += 1
                continue
            print(f" {baseline_a2['p50']:.1f}μs")
            
            # B2: Second test value measurement
            if not self.apply_setting(opt_name, test_value):
                print(f"    Failed to apply test setting (B2): {test_value}")
                retry += 1
                continue
                
            print(f"    B2 ({test_value})...", end='', flush=True)
            test_b2 = self.measure_latency()
            if not test_b2:
                print(" Failed to measure")
                retry += 1
                continue
            print(f" {test_b2['p50']:.1f}μs")
            
            # A3: Third baseline
            if not self.apply_setting(opt_name, original):
                print(f"    Failed to apply original setting (A3): {original}")
                retry += 1
                continue
                
            print(f"    A3 (baseline)...", end='', flush=True)
            baseline_a3 = self.measure_latency()
            if not baseline_a3:
                print(" Failed to measure")
                retry += 1
                continue
            print(f" {baseline_a3['p50']:.1f}μs")
            
            # Check consistency between B measurements
            b_consistency = abs(test_b1['p50'] - test_b2['p50']) / min(test_b1['p50'], test_b2['p50']) * 100
            print(f"    B consistency: {b_consistency:.1f}% difference")
            
            # Calculate drift across A measurements
            a_values = [baseline_a1['p50'], baseline_a2['p50'], baseline_a3['p50']]
            a_mean = np.mean(a_values)
            a_std = np.std(a_values)
            a_cv = a_std / a_mean * 100
            drift = (baseline_a3['p50'] - baseline_a1['p50']) / baseline_a1['p50'] * 100
            
            print(f"    A drift: {drift:.1f}% (CV: {a_cv:.1f}%)")
            
            # Check if all measurements are in bad state
            if all(v > 1000 for v in [baseline_a1['p50'], baseline_a2['p50'], baseline_a3['p50'], 
                                      test_b1['p50'], test_b2['p50']]):
                if self.good_baseline and self.good_baseline < 500:
                    print(f"    ⚠️ All measurements in degraded state, triggering reset...")
                    self.perform_network_reset()
                    consecutive_failures = 0
                    retry += 1
                    continue
            
            # Check if measurements are stable enough
            if abs(drift) <= MAX_DRIFT_PERCENT and b_consistency <= 20 and a_cv <= 15:
                # Good measurement, calculate improvement
                baseline_avg = a_mean
                test_avg = (test_b1['p50'] + test_b2['p50']) / 2
                improvement = baseline_avg - test_avg
                improvement_pct = improvement / baseline_avg * 100
                
                print(f"    Baseline avg: {baseline_avg:.1f}μs")
                print(f"    Test avg: {test_avg:.1f}μs")
                print(f"    Improvement: {improvement:.1f}μs ({improvement_pct:.1f}%)")
                
                # Update baseline cache
                self.baseline_cache['baseline'] = baseline_avg
                
                # Sanity check
                if improvement > baseline_avg * 0.5:
                    print(f"    ⚠️ Unrealistic improvement, retrying...")
                    retry += 1
                    continue
                
                # Check if improvement is significant (must exceed drift)
                if improvement_pct > abs(drift):
                    print(f"    ✓ Improvement ({improvement_pct:.1f}%) exceeds drift ({abs(drift):.1f}%) - VALID")
                    no_improvement_count = 0  # Reset counter
                    
                    # Save to real-time results file immediately
                    self.save_test_result(opt_name, test_value, original, 
                                        improvement, improvement_pct, drift, 
                                        baseline_avg, test_avg)
                    
                    return improvement, improvement_pct
                else:
                    print(f"    ℹ️ Improvement ({improvement_pct:.1f}%) within drift margin ({abs(drift):.1f}%)")
                    no_improvement_count += 1
                    
                    # If we've seen no significant improvement 3 times with stable measurements, accept no improvement
                    if no_improvement_count >= 3:
                        print(f"    → No significant improvement after {no_improvement_count} stable tests")
                        return 0, 0  # Return no improvement
                    else:
                        print(f"    → Retrying... ({no_improvement_count}/3 attempts with no improvement)")
                        retry += 1
                        continue
            else:
                reasons = []
                if abs(drift) > MAX_DRIFT_PERCENT:
                    reasons.append(f"drift {drift:.1f}%")
                if b_consistency > 20:
                    reasons.append(f"B inconsistent {b_consistency:.1f}%")
                if a_cv > 15:
                    reasons.append(f"A variable CV={a_cv:.1f}%")
                
                print(f"    ⚠️ Network unstable ({', '.join(reasons)}), retrying...")
                consecutive_failures += 1
                
                # Trigger reset if we've had too many failures
                if consecutive_failures > 8:
                    print(f"    Excessive instability, triggering network reset")
                    self.perform_network_reset()
                    consecutive_failures = 0
                time.sleep(self.stability_wait_time)
            
            retry += 1  # Increment retry counter
    
    def test_with_aba_pattern(self, opt_name):
        """Test using A/B/A/B/A pattern with stability retries"""
        config = self.optimizations[opt_name]
        original = self.original_settings.get(opt_name)
        
        if not original:
            return None, 0
        
        # Get values to test (excluding original)
        test_values = [v for v in config['values'] if v != original]
        
        if not test_values:
            return original, 0
        
        priority = config.get('priority', 3)
        pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
        
        print(f"\n{'='*70}")
        print(f"🔬 Testing {opt_name} [{pri_label} PRIORITY]")
        print(f"  Original: {original}")
        print(f"  Testing: {test_values}")
        print(f"  Current test IP: {self.best_ip}")
        
        # Establish baseline if not cached or if we have a good baseline to use
        if 'baseline' not in self.baseline_cache or self.good_baseline:
            self.apply_setting(opt_name, original)
            baseline = self.wait_for_stability(self.good_baseline)
            if baseline:
                self.baseline_cache['baseline'] = baseline
        
        best_value = original
        best_improvement = 0
        
        for test_value in test_values:
            if self.abort_testing:
                break
            
            print(f"\n  Testing A/B/A/B/A pattern: {original} → {test_value} → {original} → {test_value} → {original}")
            
            improvement, improvement_pct = self.test_with_aba_pattern_stable(opt_name, test_value, original)
            
            if improvement is not None and improvement_pct is not None:
                # Check if this is better
                if improvement > best_improvement and improvement_pct > (MIN_IMPROVEMENT_THRESHOLD * 100):
                    best_value = test_value
                    best_improvement = improvement
                    print(f"    ✅ New best!")
        
        if best_value != original:
            print(f"\n  Best: {best_value} (improvement: {best_improvement:.1f}μs)")
            return best_value, best_improvement
        else:
            print(f"  No significant improvement - keeping: {original}")
            return original, 0
    
    def find_best_ip(self):
        """Find best working IP"""
        print("\n🎯 Finding best endpoint...")
        
        best_latency = float('inf')
        best_ip = None
        
        for ip in TEST_IPS:
            self.best_ip = ip
            print(f"  Testing {ip}...", end='', flush=True)
            
            result = self.measure_latency(samples=5)
            if result:
                print(f" {result['p50']:.1f}μs (CV: {result['cv']:.1%})")
                if result['p50'] < best_latency:
                    best_latency = result['p50']
                    best_ip = ip
            else:
                print(" Failed")
        
        if best_ip:
            self.best_ip = best_ip
            self.baseline_cache['baseline'] = best_latency
            # Set good baseline if this looks like a good latency
            if best_latency < 500:
                self.good_baseline = best_latency
                print(f"  ✓ Using {self.best_ip} ({best_latency:.1f}μs) - Good baseline established")
            else:
                print(f"  ✓ Using {self.best_ip} ({best_latency:.1f}μs)")
            return True
        
        return False
    
    def final_comparison_test(self, optimal_settings):
        """Final comparison using interleaved A/B testing with stability checks"""
        print("\n" + "="*70)
        print("🔬 FINAL VERIFICATION: Interleaved A/B Testing")
        print("="*70)
        
        if not optimal_settings:
            print("No optimizations to test")
            return
        
        print("Testing pattern: Original → Optimized → Original → Optimized...")
        print("This ensures we measure actual improvement, not network drift\n")
        
        # Function to apply all optimal settings
        def apply_optimal():
            for name, (value, _) in optimal_settings.items():
                self.apply_setting(name, value, silent=True)
            time.sleep(0.5)
        
        # Function to apply original settings
        def apply_original():
            self.restore_original_settings()
            time.sleep(0.5)
        
        # Collect interleaved samples
        original_results = []
        optimal_results = []
        
        for round_num in range(5):
            print(f"Round {round_num + 1}/5:")
            
            # Check for stability before testing
            if round_num > 0:
                expected = self.good_baseline if self.good_baseline else np.median(original_results) if original_results else 500
                stable = self.wait_for_stability(expected)
                if not stable:
                    print("  ⚠️ Network unstable, waiting...")
                    time.sleep(10)
            
            # Test Original
            print(f"  Testing ORIGINAL...", end='', flush=True)
            apply_original()
            result = self.measure_latency(samples=2)
            if result:
                # Skip if in degraded state
                if self.good_baseline and result['p50'] > self.good_baseline * 3:
                    print(f" {result['p50']:.1f}μs (degraded, skipping)")
                else:
                    original_results.append(result['p50'])
                    print(f" {result['p50']:.1f}μs")
            else:
                print(" Failed")
            
            # Test Optimized
            print(f"  Testing OPTIMIZED...", end='', flush=True)
            apply_optimal()
            result = self.measure_latency(samples=2)
            if result:
                # Skip if in degraded state
                if self.good_baseline and result['p50'] > self.good_baseline * 3:
                    print(f" {result['p50']:.1f}μs (degraded, skipping)")
                else:
                    optimal_results.append(result['p50'])
                    print(f" {result['p50']:.1f}μs")
            else:
                print(" Failed")
            
            # Check for drift
            if len(original_results) >= 2:
                drift = abs(original_results[-1] - original_results[-2])
                drift_pct = drift / original_results[-2] * 100
                if drift_pct > 30:
                    print(f"  ⚠️ High drift detected ({drift_pct:.1f}%), results may be unreliable")
        
        # Analyze results
        if len(original_results) >= 3 and len(optimal_results) >= 3:
            print("\n" + "="*70)
            print("📊 FINAL RESULTS")
            print("="*70)
            
            # Filter out any remaining outliers
            orig_median = np.median(original_results)
            opt_median = np.median(optimal_results)
            orig_std = np.std(original_results)
            opt_std = np.std(optimal_results)
            
            improvement = orig_median - opt_median
            improvement_pct = improvement / orig_median * 100
            
            print(f"\n🔵 ORIGINAL:  {orig_median:.1f} ± {orig_std:.1f}μs")
            print(f"🟢 OPTIMIZED: {opt_median:.1f} ± {opt_std:.1f}μs")
            
            # Statistical significance test
            from scipy import stats
            t_stat, p_value = stats.ttest_ind(original_results, optimal_results)
            
            if improvement > 0 and p_value < 0.05:
                print(f"\n✅ VERIFIED IMPROVEMENT: {improvement:.1f}μs ({improvement_pct:.1f}%)")
                print(f"   Statistical significance: p={p_value:.4f}")
            elif improvement > 0:
                print(f"\n⚠️ Improvement of {improvement:.1f}μs but not statistically significant (p={p_value:.2f})")
            else:
                print(f"\n❌ No improvement detected")
            
            # Check if improvement matches expectations
            expected_total = sum(imp for _, imp in optimal_settings.values())
            if improvement > 0:
                efficiency = (improvement / expected_total * 100) if expected_total > 0 else 0
                print(f"\n📈 Expected total: {expected_total:.1f}μs")
                print(f"   Actual: {improvement:.1f}μs ({efficiency:.0f}% of expected)")
                
                if efficiency < 50:
                    print("   ⚠️ Actual improvement less than expected - some optimizations may not stack")
        else:
            print("\n❌ Insufficient data for comparison")
        
        # Restore original
        print("\n🔄 Restoring original settings...")
        apply_original()
        print("✓ Done")
    
    def save_results_to_file(self, optimal_settings, test_start_time):
        """Save results to timestamped file"""
        # Create results directory if it doesn't exist
        results_dir = "optimization_results"
        os.makedirs(results_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{results_dir}/optimization_{timestamp}.txt"
        
        # Calculate test duration
        test_duration = time.time() - test_start_time
        
        with open(filename, 'w') as f:
            f.write("="*80 + "\n")
            f.write("NETWORK OPTIMIZATION RESULTS\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Test IPs: {', '.join(TEST_IPS)}\n")
            f.write(f"Best IP used: {self.best_ip}\n")
            f.write(f"Test duration: {test_duration/60:.1f} minutes\n")
            f.write(f"Network resets performed: {self.ip_rotation_index}\n")
            f.write(f"Mode: {'Quick (HIGH priority only)' if QUICK_MODE else 'Full (all priorities)'}\n")
            f.write("\n")
            
            if optimal_settings:
                f.write("IMPROVEMENTS FOUND:\n")
                f.write("-"*60 + "\n\n")
                
                # Group by priority
                by_priority = defaultdict(list)
                for name, (value, improvement) in optimal_settings.items():
                    priority = self.optimizations[name].get('priority', 3)
                    by_priority[priority].append((name, value, improvement))
                
                total_improvement = 0
                for priority in sorted(by_priority.keys()):
                    pri_label = ['HIGH', 'MEDIUM', 'LOW'][priority-1]
                    f.write(f"[{pri_label} PRIORITY]\n")
                    
                    for name, value, improvement in by_priority[priority]:
                        original = self.original_settings.get(name, 'unknown')
                        config = self.optimizations[name]
                        f.write(f"  {name}:\n")
                        f.write(f"    Original: {original}\n")
                        f.write(f"    Optimal: {value}\n")
                        f.write(f"    Improvement: {improvement:.1f}μs\n")
                        f.write(f"    Parameter: {config['param']}\n")
                        total_improvement += improvement
                    f.write("\n")
                
                f.write(f"Expected Total Improvement: {total_improvement:.1f}μs\n")
                f.write("Note: Improvements may not stack linearly\n\n")
                
                f.write("COMMANDS TO APPLY:\n")
                f.write("-"*60 + "\n\n")
                
                f.write("# Sysctl settings (add to /etc/sysctl.conf):\n")
                for name, (value, _) in optimal_settings.items():
                    config = self.optimizations[name]
                    if config['type'] == 'sysctl':
                        f.write(f"{config['param']}={value}\n")
                
                f.write("\n# Ethtool settings (add to network startup script):\n")
                for name, (value, _) in optimal_settings.items():
                    config = self.optimizations[name]
                    if config['type'] == 'ethtool_coalesce':
                        f.write(f"ethtool -C {self.interface} {config['param']} {value}\n")
                    elif config['type'] == 'ethtool_ring':
                        f.write(f"ethtool -G {self.interface} {config['param']} {value}\n")
            else:
                f.write("No significant improvements found.\n")
                f.write("System may already be optimally configured,\n")
                f.write("or network conditions prevented accurate testing.\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write(f"Results saved to: {filename}\n")
        
        print(f"\n📁 Results saved to: {filename}")
        return filename
    
    def generate_report(self, optimal_settings):
        """Generate optimization report"""
        print("\n" + "="*80)
        print("📈 OPTIMIZATION REPORT")
        print("="*80)
        
        # Report skipped optimizations first
        if self.skipped_optimizations:
            print("\n⚠️ SKIPPED OPTIMIZATIONS:")
            print("-"*60)
            for opt_name, reason in self.skipped_optimizations:
                config = self.optimizations[opt_name]
                priority = config.get('priority', 3)
                pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                print(f"  [{pri_label}] {opt_name}: {reason}")
            print()
        
        if optimal_settings:
            print("\n✅ IMPROVEMENTS FOUND:")
            print("-"*60)
            
            # Group by priority
            by_priority = defaultdict(list)
            for name, (value, improvement) in optimal_settings.items():
                priority = self.optimizations[name].get('priority', 3)
                by_priority[priority].append((name, value, improvement))
            
            for priority in sorted(by_priority.keys()):
                pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                print(f"\n  [{pri_label} PRIORITY]")
                
                for name, value, improvement in by_priority[priority]:
                    original = self.original_settings.get(name, 'unknown')
                    print(f"    {name:20}: {original} → {value}")
                    print(f"      Improvement: {improvement:.1f}μs")
            
            total = sum(imp for _, imp in optimal_settings.values())
            print(f"\n  Expected Total: {total:.1f}μs")
            print("  Note: Improvements may not stack linearly")
            print(f"\n  Network resets performed: {self.ip_rotation_index}")
            
            print("\n📝 COMMANDS TO APPLY:")
            print("-"*60)
            
            print("\n# Add to /etc/sysctl.conf:")
            for name, (value, _) in optimal_settings.items():
                config = self.optimizations[name]
                if config['type'] == 'sysctl':
                    print(f"{config['param']}={value}")
            
            print("\n# Add to network startup:")
            for name, (value, _) in optimal_settings.items():
                config = self.optimizations[name]
                if config['type'] == 'ethtool_coalesce':
                    print(f"ethtool -C {self.interface} {config['param']} {value}")
                elif config['type'] == 'ethtool_ring':
                    print(f"ethtool -G {self.interface} {config['param']} {value}")
        else:
            print("\n✅ System already optimally configured")
            print("   (or network too unstable to detect improvements)")
            if self.ip_rotation_index > 0:
                print(f"\n   Network resets performed: {self.ip_rotation_index}")
        
        print("\n" + "="*80)

def main():
    print("="*70)
    print("⚡ NETWORK OPTIMIZER - With Auto Reset on Instability")
    print("="*70)
    print(f"Interface: {INTERFACE}")
    print(f"Method: A/B/A/B/A pattern with infinite retries until success")
    print(f"Max acceptable drift: {MAX_DRIFT_PERCENT}%")
    print(f"Instability threshold: {INSTABILITY_THRESHOLD}x baseline")
    print(f"Auto-reset: Enabled (after 3 consecutive unstable readings)")
    
    # Parse command line arguments
    global QUICK_MODE, TEST_ITERATIONS
    
    for i, arg in enumerate(sys.argv[1:]):
        if arg == '--quick':
            QUICK_MODE = True
            print("⚡ Quick mode enabled - testing only HIGH priority settings")
        elif arg == '--iterations' and i + 2 < len(sys.argv):
            try:
                TEST_ITERATIONS = int(sys.argv[i + 2])
                print(f"🔁 Will run {TEST_ITERATIONS} test iterations")
            except ValueError:
                print(f"⚠️ Invalid iterations value, using default (1)")
    
    if not QUICK_MODE and TEST_ITERATIONS == 1:
        print("Full mode - testing ALL settings (use --quick for faster run, --iterations N for multiple runs)")
    
    print("")
    
    if os.geteuid() != 0:
        print("❌ Must run as root")
        sys.exit(1)
    
    optimizer = DriftCompensatingOptimizer()
    
    def signal_handler(signum, frame):
        print("\n\n⚠️ Interrupted! Restoring...")
        optimizer.abort_testing = True
        optimizer.restore_original_settings()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Track test start time
        test_start_time = time.time()
        
        # Initialize real-time results file
        optimizer.init_results_file()
        
        optimizer.save_current_settings()
        
        if not optimizer.find_best_ip():
            print("❌ Network connectivity issues")
            sys.exit(1)
        
        # Run multiple iterations if requested
        all_iteration_results = []
        
        for iteration in range(TEST_ITERATIONS):
            if TEST_ITERATIONS > 1:
                print(f"\n{'='*70}")
                print(f"🔁 ITERATION {iteration + 1} of {TEST_ITERATIONS}")
                print(f"{'='*70}")
                
                # Reset baseline cache for new iteration
                optimizer.baseline_cache = {}
                optimizer.good_baseline = None
            
            optimal_settings = {}
            
            # Sort optimizations by priority
            sorted_opts = sorted(optimizer.optimizations.items(), 
                               key=lambda x: x[1].get('priority', 3))
            
            print(f"\n📋 Testing {len(sorted_opts)} optimizations")
            print(f"   Order: HIGH priority → MED priority → LOW priority")
            print(f"   Will retry indefinitely until each test succeeds")
            print(f"   Auto-reset if instability persists")
            
            for i, (opt_name, config) in enumerate(sorted_opts, 1):
                if optimizer.abort_testing:
                    break
                
                priority = config.get('priority', 3)
                pri_label = ['HIGH', 'MED', 'LOW'][priority-1]
                print(f"\n[{i}/{len(sorted_opts)}] {opt_name} [{pri_label}]")
                
                best_value, improvement = optimizer.test_with_aba_pattern(opt_name)
                
                if best_value and improvement > 10:  # Only keep if > 10μs improvement
                    optimal_settings[opt_name] = (best_value, improvement)
                    
                    # If in quick mode and found good improvements, can stop
                    if QUICK_MODE and len(optimal_settings) >= 3 and priority > 1:
                        print("\n⚡ Quick mode: Found enough improvements, stopping early")
                        break
            
            # Store this iteration's results
            all_iteration_results.append(optimal_settings.copy())
            
            # If multiple iterations, add separator to results file
            if TEST_ITERATIONS > 1 and iteration < TEST_ITERATIONS - 1:
                with open(optimizer.results_file, 'a') as f:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"End of iteration {iteration + 1}\n")
                    f.write(f"{'='*60}\n\n")
        
        # If multiple iterations, use the best results
        if TEST_ITERATIONS > 1:
            # Find the iteration with the most improvements
            best_iteration = max(range(len(all_iteration_results)), 
                               key=lambda i: sum(imp for _, imp in all_iteration_results[i].values()))
            optimal_settings = all_iteration_results[best_iteration]
            print(f"\n✓ Using results from iteration {best_iteration + 1} (best total improvement)")
        
        # Final verification with interleaved testing
        optimizer.final_comparison_test(optimal_settings)
        
        # Generate report
        optimizer.generate_report(optimal_settings)
        
        # Save results to file
        optimizer.save_results_to_file(optimal_settings, test_start_time)
        
        if optimal_settings:
            print("\n" + "="*70)
            response = input("Apply optimal settings? (y/n): ")
            
            if response.lower() == 'y':
                for name, (value, _) in optimal_settings.items():
                    optimizer.apply_setting(name, value)
                print("✅ Applied")
            else:
                optimizer.restore_original_settings()
                print("✅ Restored original settings")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        optimizer.restore_original_settings()

if __name__ == "__main__":
    main()