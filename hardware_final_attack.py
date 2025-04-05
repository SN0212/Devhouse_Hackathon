#!/usr/bin/env python3
"""
IoT Security Scanner v4.0 with Dataset Generation
Advanced Physical/Wired Attack Toolkit with ESP32 Bypass Techniques
"""

import serial
import serial.tools.list_ports
import os
import sys
import time
import ctypes
from datetime import datetime
import json
import hashlib
import binascii
import struct
import random
import csv

class AttackLogger:
    def __init__(self, reports_dir):
        self.csv_file = os.path.join(reports_dir, "attack_dataset.csv")
        self.headers = [
            "timestamp", "attack_type", "payload", "response", 
            "success", "severity", "device_info", "description"
        ]
        self._init_csv()

    def _init_csv(self):
        with open(self.csv_file, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            if f.tell() == 0:  # Write headers only if file is empty
                writer.writeheader()

    def log_attack(self, attack_type, payload, response, success, severity, device_info="", description=""):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "payload": str(payload),
            "response": str(response),
            "success": success,
            "severity": severity,
            "device_info": str(device_info),
            "description": description
        }
        
        with open(self.csv_file, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.headers)
            writer.writerow(entry)

class IoTScanner:
    def __init__(self):  # ✅ Correct - double underscores
        """Initialize scanner with advanced attack capabilities"""
        self.script_dir = os.path.dirname(os.path.abspath(__file__))  # Fixed __file__
        self.reports_dir = os.path.join(self.script_dir, "scan_reports")
        self.dataset_dir = os.path.join(self.script_dir, "attack_datasets")
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.dataset_dir, exist_ok=True)
        
        # Initialize attack logger
        self.logger = AttackLogger(self.reports_dir)
        
        # Initialize report structure
        self.report = {
            "metadata": {
                "scanner_version": "4.0",
                "scan_start": datetime.now().isoformat(),
                "environment": {
                    "os": os.name,
                    "python": sys.version
                }
            },
            "device": {
                "port": "Unknown",
                "vendor": "Unknown",
                "type": "Unknown",
                "firmware": "Unknown",
                "hardware_details": {},
                "security_features": {
                    "secure_boot": "Unknown",
                    "flash_encryption": "Unknown",
                    "efuse_protection": "Unknown"
                }
            },
            "findings": {
                "vulnerabilities": [],
                "stats": {
                    "total_tests": 0,
                    "tests_passed": 0,
                    "tests_failed": 0
                }
            }
        }
        
        # Initialize dataset file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dataset_file = os.path.join(self.dataset_dir, f"attack_dataset_{timestamp}.csv")
        self.init_dataset_file()
        
        self.max_retries = 5
        self.retry_delay = 1
        self.uart = None
        self.ensure_admin()
        self.test_cases = self.load_test_cases()
        self.esp32_specific_attacks = self.load_esp32_attacks()

    def init_dataset_file(self):
        """Initialize the CSV dataset file with headers"""
        headers = [
            "timestamp", "attack_type", "payload", "response", "success", "severity",
            "payload_length", "contains_default_creds", "contains_null_bytes",
            "contains_repeats", "contains_format_string", "contains_at_command",
            "response_has_timing", "device_secure_boot", "device_flash_encryption",
            "description"
        ]
    
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
    
        with open(self.dataset_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    def log_attack_to_dataset(self, attack_data):
        """Log attack data to the CSV dataset"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.dataset_file), exist_ok=True)
        
            with open(self.dataset_file, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    attack_data["timestamp"],
                    attack_data["attack_type"],
                    attack_data["payload"],
                    attack_data["response"],
                    attack_data["success"],
                    attack_data["severity"],
                    attack_data["payload_length"],
                    attack_data["contains_default_creds"],
                    attack_data["contains_null_bytes"],
                    attack_data["contains_repeats"],
                    attack_data["contains_format_string"],
                    attack_data["contains_at_command"],
                    attack_data["response_has_timing"],
                    attack_data["device_secure_boot"],
                    attack_data["device_flash_encryption"],
                    attack_data["description"]
                ])
        except Exception as e:
            print(f"Error writing to dataset file: {e}")

    def analyze_payload(self, payload):
        """Analyze payload characteristics for dataset features"""
        payload_str = payload.decode(errors='ignore')
        
        return {
            "length": len(payload),
            "contains_default_creds": any(
                cred in payload_str.lower() 
                for cred in ["admin:admin", "root:root", "admin:password"]
            ),
            "contains_null_bytes": b'\x00' in payload,
            "contains_repeats": self.check_for_repeats(payload),
            "contains_format_string": any(
                fmt in payload_str 
                for fmt in ["%n", "%s", "%x", "%p"]
            ),
            "contains_at_command": payload_str.strip().startswith("AT+"),
        }

    def check_for_repeats(self, payload):
        """Check if payload contains repeated patterns"""
        if len(payload) < 16:
            return False
            
        # Check for repeating single byte
        first_byte = payload[0]
        if all(b == first_byte for b in payload[:16]):
            return True
            
        # Check for repeating 4-byte pattern (common in buffer overflows)
        if len(payload) >= 8:
            pattern = payload[:4]
            return pattern == payload[4:8]
            
        return False

    def analyze_response(self, response):
        """Analyze response characteristics for dataset features"""
        response_str = response.decode(errors='ignore')
        
        return {
            "has_timing": any(
                term in response_str.lower()
                for term in ["timing", "delay", "measurement", "ns", "seconds"]
            )
        }

    def ensure_admin(self):
        """Ensure the script is running with administrative privileges"""
        try:
            if os.name == 'nt':
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("⚠ Error: This tool requires administrative privileges on Windows")
                    sys.exit(1)
            else:
                if os.geteuid() != 0:
                    print("⚠ Error: This tool requires root privileges on Unix-like systems")
                    sys.exit(1)
        except Exception as e:
            print(f"⚠ Privilege check failed: {str(e)}")
            sys.exit(1)
            
    def load_test_cases(self):
        """Load comprehensive security test cases"""
        return {
            "authentication": [
                {"payload": b'admin:admin\r\n', "description": "Default admin credentials"},
                {"payload": b'root:root\r\n', "description": "Root user attempt"},
                {"payload": b'admin:\x00\r\n', "description": "Null byte injection"},
                {"payload": b'admin:password123\r\n', "description": "Common password attempt"},
                {"payload": b'AT+CMNG=0,0,"0000"\r\n', "description": "Bluetooth pairing attempt"}
            ],
            "command_injection": [
                {"payload": b';ls;\r\n', "description": "Basic command injection"},
                {"payload": b'$(reboot)\r\n', "description": "Subshell injection"},
                {"payload": b'cat /etc/passwd\r\n', "description": "Backtick command execution"},
                {"payload": b'| cat /etc/shadow\r\n', "description": "Pipe command execution"},
                {"payload": b'\x1b[1;1H\x1b[2Jsh\r\n', "description": "Terminal escape sequence injection"},
                {"payload": b'\nreboot\n', "description": "Newline injection"}
            ],
            "info_disclosure": [
                {"payload": b'AT+VERSION\r\n', "description": "Firmware version request"},
                {"payload": b'get config\r\n', "description": "Configuration dump"},
                {"payload": b'AT+DEVCONFIG\r\n', "description": "Device configuration request"},
                {"payload": b'AT+GMR\r\n', "description": "Module version request"},
                {"payload": b'AT+SYSINFO\r\n', "description": "System information request"},
                {"payload": b'AT+FSLS\r\n', "description": "Filesystem listing"}
            ],
            "buffer_overflow": [
                {"payload": b'A'*500 + b'\r\n', "description": "Basic buffer overflow"},
                {"payload": b'\x00'*256 + b'\r\n', "description": "Null byte overflow"},
                {"payload": b'%n%n%n%n%n\r\n', "description": "Format string attack"},
                {"payload": struct.pack('<I', 0x41414141)*64, "description": "Structured overflow"},
                {"payload": b'\xFF'*1024, "description": "Large binary payload"}
            ],
            "firmware_manipulation": [
                {"payload": b'AT+CIUPDATE\r\n', "description": "Firmware update trigger"},
                {"payload": b'AT+UREBOOT=1\r\n', "description": "Unattended reboot command"},
                {"payload": b'AT+FWUPD=1\r\n', "description": "Forced firmware update"},
                {"payload": b'AT+BOOTLOADER\r\n', "description": "Bootloader access"}
            ],
            "memory_attacks": [
                {"payload": b'AT+CRASH\r\n', "description": "Crash command attempt"},
                {"payload": b'AT+MEMDUMP\r\n', "description": "Memory dump request"},
                {"payload": b'AT+MEMREAD=0x40000000,100\r\n', "description": "Memory read attempt"},
                {"payload": b'AT+MEMWRITE=0x40000000,41414141\r\n', "description": "Memory write attempt"}
            ],
            "hardware_probing": [
                {"payload": b'AT+POWER=9\r\n', "description": "Over-voltage attempt"},
                {"payload": b'AT+FRFREQ=900000000\r\n', "description": "RF frequency manipulation"},
                {"payload": b'AT+CPUFREQ=240\r\n', "description": "CPU overclock attempt"},
                {"payload": b'AT+TEMP\r\n', "description": "Temperature sensor access"}
            ],
            "serial_protocol": [
                {"payload": b'\x7E\x00\x02\x01\x02\x7E', "description": "Malformed HDLC frame"},
                {"payload": b'\x55\x55\x55\x55', "description": "Sync flood"},
                {"payload": b'\x00\xFF\x00\xFF', "description": "Bit flipping attack"},
                {"payload": b'\xAA\x55\xAA\x55', "description": "Alternating bit pattern"},
                {"payload": b'\xFF\xFF\xFF\xFF', "description": "Maximum bit pattern"}
            ],
            "physical_tampering": [
                {"payload": b'AT+JTAGEN=1\r\n', "description": "JTAG enable attempt"},
                {"payload": b'AT+BOOTMODE=1\r\n', "description": "Boot mode change"},
                {"payload": b'AT+SECURE=0\r\n', "description": "Security disable attempt"},
                {"payload": b'AT+RESETCFG\r\n', "description": "Configuration reset"}
            ],
            "side_channel": [
                {"payload": b'AT+DELAY=10000\r\n', "description": "Timing attack probe"},
                {"payload": b'AT+POWERMEASURE\r\n', "description": "Power analysis trigger"},
                {"payload": b'AT+EMAN\r\n', "description": "EM emission trigger"},
                {"payload": b'AT+CLOCK\r\n', "description": "Clock glitch attempt"}
            ],
            "battery_attacks": [
                {"payload": b'AT+BATTOFF\r\n', "description": "Battery cutoff attempt"},
                {"payload": b'AT+CHGCONTROL=0\r\n', "description": "Charge control disable"},
                {"payload": b'AT+BATOVP=5.0\r\n', "description": "Over-voltage protection disable"},
                {"payload": b'AT+BATOCP=2.0\r\n', "description": "Over-current protection disable"}
            ],
            "wire_probing": [
                {"payload": b'AT+GPIO=1,1\r\n', "description": "GPIO manipulation"},
                {"payload": b'AT+I2CSCAN\r\n', "description": "I2C bus scan"},
                {"payload": b'AT+SPIREAD=0,1,10\r\n', "description": "SPI read attempt"},
                {"payload": b'AT+ADCREAD=0\r\n', "description": "ADC read attempt"},
                {"payload": b'AT+PWM=1,1000,50\r\n', "description": "PWM control attempt"}
            ],
            "radio_attacks": [
                {"payload": b'AT+RFBAUD=115200\r\n', "description": "RF baud rate change"},
                {"payload": b'AT+RFPOWER=20\r\n', "description": "Max RF power setting"},
                {"payload": b'AT+RXSTOP\r\n', "description": "Radio receive disable"},
                {"payload": b'AT+TXCW\r\n', "description": "Continuous wave transmit"}
            ],
            "bluetooth_attacks": [
                {"payload": b'AT+BTINIT=0\r\n', "description": "Bluetooth disable attempt"},
                {"payload": b'AT+BTSCAN=1\r\n', "description": "Bluetooth forced scan"},
                {"payload": b'AT+BTPAIR=0,"0000"\r\n', "description": "Bluetooth forced pairing"}
            ]
        }

    def load_esp32_attacks(self):
        """Load specialized ESP32 attack vectors"""
        return {
            "secure_boot_bypass": [
                {"payload": b'\x00'*16 + b'\x12\x34\x56\x78', "description": "Secure Boot signature padding attack"},
                {"payload": b'\x00'*16 + b'\xDE\xAD\xBE\xEF', "description": "Secure Boot null signature attack"},
                {"payload": b'\xFF'*16 + b'\x12\x34\x56\x78', "description": "Secure Boot flash dump trigger"},
                {"payload": b'AT+SECBOOT=0\r\n', "description": "Secure Boot disable attempt"}
            ],
            "flash_encryption": [
                {"payload": b'AT+FLASH_READ=0,1024\r\n', "description": "Direct flash read attempt"},
                {"payload": b'AT+FLASH_DUMP\r\n', "description": "Full flash dump request"},
                {"payload": b'AT+FLASH_KEY\r\n', "description": "Encryption key extraction attempt"},
                {"payload": b'AT+FLASH_ENC=0\r\n', "description": "Flash encryption disable attempt"}
            ],
            "efuse_attacks": [
                {"payload": b'AT+EFUSE_READ=0\r\n', "description": "eFuse read attempt"},
                {"payload": b'AT+EFUSE_WRITE=0,0\r\n', "description": "eFuse write attempt"},
                {"payload": b'AT+EFUSE_RESET\r\n', "description": "eFuse protection disable"},
                {"payload": b'AT+EFUSE_DIS=1\r\n', "description": "eFuse disable attempt"}
            ],
            "voltage_glitching": [
                {"payload": b'AT+VGLITCH=1\r\n', "description": "Voltage glitch trigger"},
                {"payload": b'AT+POWER=0\r\n', "description": "Brownout attack"},
                {"payload": b'AT+VCC=1.0\r\n', "description": "Undervoltage attack"},
                {"payload": b'AT+VCC=3.6\r\n', "description": "Overvoltage attack"}
            ],
            "timing_attacks": [
                {"payload": b'\x00'*128, "description": "AES timing probe"},
                {"payload": b'\xFF'*128, "description": "RSA timing probe"},
                {"payload": b'AT+DELAY=1000\r\n', "description": "Secure boot delay attack"},
                {"payload": b'AT+TIMING=1\r\n', "description": "Timing measurement trigger"}
            ],
            "jtag_attacks": [
                {"payload": b'AT+JTAG=1\r\n', "description": "JTAG enable attempt"},
                {"payload": b'AT+DEBUG=1\r\n', "description": "Debug port activation"},
                {"payload": b'AT+OCD=1\r\n', "description": "On-chip debugger enable"},
                {"payload": b'AT+JTAGRST=1\r\n', "description": "JTAG reset attempt"}
            ],
            "memory_corruption": [
                {"payload": b'A'*1024 + b'\xDE\xAD\xBE\xEF', "description": "Heap overflow attack"},
                {"payload": b'%08x.'*50, "description": "Stack canary bypass"},
                {"payload": b'\x00'*256 + struct.pack('<I', 0x400D0000), "description": "Code execution attempt"},
                {"payload": b'AT+MEMCORRUPT=1\r\n', "description": "Memory corruption trigger"}
            ],
            "wifi_attacks": [
                {"payload": b'AT+CWQAP\r\n', "description": "WiFi disconnect attack"},
                {"payload": b'AT+CWMODE=0\r\n', "description": "WiFi mode change attack"},
                {"payload": b'AT+CWSAP="hacked","password",1,0\r\n', "description": "Rogue AP creation"},
                {"payload": b'AT+CWWPS=1\r\n', "description": "WPS push button attack"}
            ],
            "rtos_attacks": [
                {"payload": b'AT+TASK_DELETE=1\r\n', "description": "RTOS task kill"},
                {"payload": b'AT+SEMAPHORE=0\r\n', "description": "RTOS semaphore attack"},
                {"payload": b'AT+QUEUE_FLOOD\r\n', "description": "RTOS queue overflow"},
                {"payload": b'AT+RTOSCRASH=1\r\n', "description": "RTOS crash trigger"}
            ],
            "partition_attacks": [
                {"payload": b'AT+PARTREAD=0,100\r\n', "description": "Partition table read"},
                {"payload": b'AT+PARTWRITE=0,41414141\r\n', "description": "Partition table write"},
                {"payload": b'AT+PARTDEL=0\r\n', "description": "Partition delete attempt"},
                {"payload": b'AT+PARTFORMAT=1\r\n', "description": "Partition format attempt"}
            ]
        }

    def scan_devices(self):
        """Scan for available serial devices"""
        print("\n🔍 Scanning for connected devices...")
        ports = serial.tools.list_ports.comports()
        
        if not ports:
            print("❌ No serial devices found")
            return False
            
        print("\nAvailable devices:")
        for i, port in enumerate(ports, 1):
            print(f"{i}. {port.device} - {port.description}")
            
        try:
            selection = int(input("\nSelect device (number): ")) - 1
            if 0 <= selection < len(ports):
                self.connect_device(ports[selection].device)
                return True
            else:
                print("❌ Invalid selection")
                return False
        except ValueError:
            print("❌ Please enter a valid number")
            return False

    def connect_device(self, port):
        """Connect to the selected serial device"""
        self.report['device']['port'] = port
        
        for attempt in range(self.max_retries):
            try:
                print(f"\n⚡ Connecting to {port} (attempt {attempt + 1}/{self.max_retries})...")
                self.uart = serial.Serial(
                    port=port,
                    baudrate=115200,
                    timeout=1,
                    write_timeout=1
                )
                print(f"✅ Connected to {port}")
                self.detect_device_info()
                return True
            except Exception as e:
                print(f"⚠ Connection failed: {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
        
        print(f"❌ Failed to connect to {port} after {self.max_retries} attempts")
        return False

    def detect_device_info(self):
        """Attempt to detect device information"""
        print("\n🛠 Detecting device information...")
        
        # Try common AT commands to get device info
        info_commands = {
            'vendor': b'AT+GMI\r\n',
            'model': b'AT+GMM\r\n',
            'firmware': b'AT+GMR\r\n',
            'imei': b'AT+GSN\r\n',
            'chip_id': b'AT+CIPSN\r\n',
            'mac': b'AT+GETMAC\r\n'
        }
        
        for field, cmd in info_commands.items():
            try:
                self.uart.write(cmd)
                time.sleep(0.5)
                response = self.uart.read_all().decode('ascii', errors='ignore').strip()
                if response:
                    self.report['device'][field] = response
                    print(f"{field.capitalize()}: {response}")
            except Exception as e:
                print(f"⚠ Failed to get {field}: {str(e)}")

    def detect_esp32_security(self):
        """Attempt to detect ESP32 security features"""
        print("\n🛡 Probing ESP32 Security Features...")
        
        security_checks = {
            "secure_boot": [
                (b'AT+SECURE_BOOT?\r\n', lambda r: b'enabled' in r.lower()),
                (b'AT+SB_VER?\r\n', lambda r: len(r) > 0)
            ],
            "flash_encryption": [
                (b'AT+FLASH_ENC?\r\n', lambda r: b'enabled' in r.lower()),
                (b'AT+ENC_KEY?\r\n', lambda r: b'error' not in r.lower())
            ],
            "efuse_protection": [
                (b'AT+EFUSE_PROT?\r\n', lambda r: b'enabled' in r.lower()),
                (b'AT+EFUSE_READ=0\r\n', lambda r: b'error' in r.lower())
            ]
        }
        
        for feature, tests in security_checks.items():
            for cmd, validator in tests:
                try:
                    self.uart.write(cmd)
                    time.sleep(0.5)
                    response = self.uart.read_all()
                    if validator(response):
                        self.report['device']['security_features'][feature] = "Enabled"
                        break
                except Exception as e:
                    print(f"⚠ {feature} check failed: {str(e)}")
            else:
                self.report['device']['security_features'][feature] = "Disabled/Unknown"

    def run_security_tests(self):
        """Execute comprehensive security test suite"""
        if not hasattr(self, 'uart') or not self.uart:
            return

        print("\n🔧 Running Comprehensive Security Test Suite...")
        total_tests = 0
        
        # Standard security tests
        for category, tests in self.test_cases.items():
            print(f"\n⚔ Running {category.replace('_', ' ').title()} Tests...")
            for test in tests:
                getattr(self, f'test_{category}')(test['payload'], test['description'])
                total_tests += 1
        
        # ESP32-specific security tests
        self.detect_esp32_security()
        print("\n💀 Running Advanced ESP32-Specific Attacks...")
        for category, tests in self.esp32_specific_attacks.items():
            print(f"\n☠ Running {category.replace('_', ' ').title()}...")
            for test in tests:
                getattr(self, f'test_{category}')(test['payload'], test['description'])
                total_tests += 1
        
        # Update test statistics
        self.report['findings']['stats']['total_tests'] = total_tests
        self.report['findings']['stats']['tests_failed'] = len(self.report['findings']['vulnerabilities'])
        self.report['findings']['stats']['tests_passed'] = total_tests - len(self.report['findings']['vulnerabilities'])

    def test_authentication(self, payload, description):
        """Test authentication bypass vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'login' not in response.lower() and b'fail' not in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Authentication Bypass",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Authentication Bypass",
                    f"{description}: Possible authentication bypass",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Authentication test failed: {str(e)}")
            
    def test_command_injection(self, payload, description):
        """Test command injection vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'error' not in response.lower() and len(response) > 0
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Command Injection",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Command Injection",
                    f"{description}: Possible command injection",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Command injection test failed: {str(e)}")

    def test_info_disclosure(self, payload, description):
        """Test information disclosure vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = len(response) > 10  # Arbitrary threshold for "interesting" response
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Information Disclosure",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Medium",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Information Disclosure",
                    f"{description}: Possible information disclosure",
                    "Medium",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Information disclosure test failed: {str(e)}")

    def test_buffer_overflow(self, payload, description):
        """Test buffer overflow vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = not response or b'crash' in response.lower() or b'reboot' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Buffer Overflow",
                "payload": binascii.hexlify(payload).decode(),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Buffer Overflow",
                    f"{description}: Possible memory corruption",
                    "Critical",
                    binascii.hexlify(payload).decode(),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Buffer overflow test failed: {str(e)}")
            
    def test_firmware_manipulation(self, payload, description):
        """Test firmware manipulation vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'update' in response.lower() or b'flash' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Firmware Manipulation",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Firmware Manipulation",
                    f"{description}: Possible firmware update triggered",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Firmware manipulation test failed: {str(e)}")

    def test_memory_attacks(self, payload, description):
        """Test memory access vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'dump' in response.lower() or b'memory' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Memory Access",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Memory Access",
                    f"{description}: Possible memory access granted",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Memory attack test failed: {str(e)}")

    def test_hardware_probing(self, payload, description):
        """Test hardware configuration vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'power' in response.lower() or b'voltage' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Hardware Probing",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Hardware Probing",
                    f"{description}: Possible hardware control granted",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Hardware probing test failed: {str(e)}")

    def test_serial_protocol(self, payload, description):
        """Test serial protocol vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = len(response) > 0 and not b'error' in response
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Protocol Vulnerability",
                "payload": binascii.hexlify(payload).decode(),
                "response": binascii.hexlify(response).decode(),
                "success": is_vulnerable,
                "severity": "Medium",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Protocol Vulnerability",
                    f"{description}: Unexpected response to malformed frame",
                    "Medium",
                    binascii.hexlify(payload).decode(),
                    binascii.hexlify(response).decode()
                )
        except Exception as e:
            print(f"⚠ Serial protocol test failed: {str(e)}")

    def test_physical_tampering(self, payload, description):
        """Test physical tampering vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'jtag' in response.lower() or b'boot' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Physical Tampering",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Physical Tampering",
                    f"{description}: Possible debug interface enabled",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Physical tampering test failed: {str(e)}")

    def test_side_channel(self, payload, description):
        """Test side channel vulnerabilities"""
        try:
            start_time = time.time()
            self.uart.write(payload)
            response = self.uart.read_all()
            elapsed = time.time() - start_time
            
            is_vulnerable = elapsed > 1.0  # Significant delay
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Side Channel",
                "payload": payload.decode(errors='ignore'),
                "response": f"Response time: {elapsed:.2f} seconds",
                "success": is_vulnerable,
                "severity": "Medium",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": True,
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Side Channel",
                    f"{description}: Timing variation detected ({elapsed:.2f}s)",
                    "Medium",
                    payload.decode(errors='ignore'),
                    f"Response time: {elapsed:.2f} seconds"
                )
        except Exception as e:
            print(f"⚠ Side channel test failed: {str(e)}")

    def test_battery_attacks(self, payload, description):
        """Test battery management vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'batt' in response.lower() or b'charge' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Battery Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Battery Vulnerability",
                    f"{description}: Possible power control granted",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Battery attack test failed: {str(e)}")

    def test_wire_probing(self, payload, description):
        """Test bus probing vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'i2c' in response.lower() or b'spi' in response.lower() or b'gpio' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Bus Probing",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Bus Probing",
                    f"{description}: Possible bus access granted",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Wire probing test failed: {str(e)}")

    def test_radio_attacks(self, payload, description):
        """Test radio configuration vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'rf' in response.lower() or b'radio' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Radio Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Radio Vulnerability",
                    f"{description}: Possible RF control granted",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Radio attack test failed: {str(e)}")

    def test_bluetooth_attacks(self, payload, description):
        """Test Bluetooth subsystem vulnerabilities"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'bluetooth' in response.lower() or b'bt' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Bluetooth Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Bluetooth Vulnerability",
                    f"{description}: Possible Bluetooth control",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Bluetooth attack test failed: {str(e)}")

    def test_secure_boot_bypass(self, payload, description):
        """Test Secure Boot bypass techniques"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'verified' in response.lower() or b'signature' not in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Secure Boot Bypass",
                "payload": binascii.hexlify(payload).decode(),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Secure Boot Bypass",
                    f"{description}: Possible Secure Boot bypass",
                    "Critical",
                    binascii.hexlify(payload).decode(),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Secure Boot bypass test failed: {str(e)}")
            
    def test_flash_encryption(self, payload, description):
        """Test Flash Encryption bypass techniques"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'encrypt' not in response.lower() and len(response) > 0
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Flash Encryption Bypass",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Flash Encryption Bypass",
                    f"{description}: Possible flash content leakage",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Flash encryption test failed: {str(e)}")

    def test_efuse_attacks(self, payload, description):
        """Test eFuse protection bypass techniques"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'efuse' in response.lower() and b'error' not in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "eFuse Protection Bypass",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "eFuse Protection Bypass",
                    f"{description}: Possible eFuse access",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ eFuse attack test failed: {str(e)}")

    def test_voltage_glitching(self, payload, description):
        """Test voltage glitching attack vectors"""
        try:
            # Simulate voltage glitch by rapid baud rate changes
            original_baud = self.uart.baudrate
            for baud in [74880, 115200, 230400, 460800, 921600]:
                self.uart.baudrate = baud
                self.uart.write(payload)
                time.sleep(0.01)
            self.uart.baudrate = original_baud
            
            response = self.uart.read_all()
            is_vulnerable = b'glitch' in response.lower() or b'reset' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Voltage Glitching",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Voltage Glitching",
                    f"{description}: Possible glitch response",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Voltage glitching test failed: {str(e)}")
            self.uart.baudrate = original_baud

    def test_timing_attacks(self, payload, description):
        """Test timing-based side channel attacks"""
        try:
            measurements = []
            for _ in range(5):  # Multiple measurements for consistency
                start = time.perf_counter_ns()
                self.uart.write(payload)
                self.uart.read_all()  # Clear buffer
                end = time.perf_counter_ns()
                measurements.append(end - start)
                time.sleep(0.1)
            
            avg_time = sum(measurements) / len(measurements)
            std_dev = (max(measurements) - min(measurements)) / avg_time
            
            is_vulnerable = std_dev > 0.2  # Significant timing variation
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Timing Attack",
                "payload": binascii.hexlify(payload).decode(),
                "response": f"Timing measurements: {measurements}",
                "success": is_vulnerable,
                "severity": "Medium",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": True,
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Timing Attack",
                    f"{description}: Timing variation detected (σ={std_dev:.2f})",
                    "Medium",
                    binascii.hexlify(payload).decode(),
                    f"Timing measurements: {measurements} ns"
                )
        except Exception as e:
            print(f"⚠ Timing attack test failed: {str(e)}")
            
    def test_jtag_attacks(self, payload, description):
        """Test JTAG and debug interface attacks"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'debug' in response.lower() or b'jtag' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Debug Interface",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Debug Interface",
                    f"{description}: Possible debug interface access",
                    "Critical",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ JTAG attack test failed: {str(e)}")

    def test_memory_corruption(self, payload, description):
        """Test advanced memory corruption techniques"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'corrupt' in response.lower() or b'panic' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Memory Corruption",
                "payload": binascii.hexlify(payload).decode(),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "Memory Corruption",
                    f"{description}: Possible memory corruption",
                    "Critical",
                    binascii.hexlify(payload).decode(),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ Memory corruption test failed: {str(e)}")

    def test_wifi_attacks(self, payload, description):
        """Test WiFi subsystem attacks"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'wifi' in response.lower() and b'error' not in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "WiFi Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "WiFi Vulnerability",
                    f"{description}: Possible WiFi control",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ WiFi attack test failed: {str(e)}")

    def test_rtos_attacks(self, payload, description):
        """Test FreeRTOS specific attacks"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'task' in response.lower() or b'rtos' in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "RTOS Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "High",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "RTOS Vulnerability",
                    f"{description}: Possible RTOS control",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ RTOS attack test failed: {str(e)}")
            
    def test_partition_attacks(self, payload, description):
        """Test partition table manipulation"""
        try:
            self.uart.write(payload)
            response = self.uart.read_all()
            
            is_vulnerable = b'partition' in response.lower() and b'error' not in response.lower()
            
            # Log to dataset
            payload_analysis = self.analyze_payload(payload)
            response_analysis = self.analyze_response(response)
            
            attack_data = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Partition Vulnerability",
                "payload": payload.decode(errors='ignore'),
                "response": response.decode(errors='ignore'),
                "success": is_vulnerable,
                "severity": "Critical",
                "payload_length": payload_analysis["length"],
                "contains_default_creds": payload_analysis["contains_default_creds"],
                "contains_null_bytes": payload_analysis["contains_null_bytes"],
                "contains_repeats": payload_analysis["contains_repeats"],
                "contains_format_string": payload_analysis["contains_format_string"],
                "contains_at_command": payload_analysis["contains_at_command"],
                "response_has_timing": response_analysis["has_timing"],
                "device_secure_boot": self.report['device']['security_features']['secure_boot'],
                "device_flash_encryption": self.report['device']['security_features']['flash_encryption'],
                "description": description
            }
            
            self.log_attack_to_dataset(attack_data)
            
            if is_vulnerable:
                self.log_vulnerability(
                    "RTOS Vulnerability",
                    f"{description}: Possible RTOS control",
                    "High",
                    payload.decode(errors='ignore'),
                    response.decode(errors='ignore')
                )
        except Exception as e:
            print(f"⚠ RTOS attack test failed: {str(e)}")
            
    def log_vulnerability(self, title, details, severity, request="", response=""):
        """Record vulnerability findings with context"""
        self.report['findings']['vulnerabilities'].append({
            "title": title,
            "details": details,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "request": request,
            "response": response,
            "mitigation": self.get_mitigation_suggestion(title)
        })
        print(f"‼ {severity.upper()} - {title}: {details}")

    def get_mitigation_suggestion(self, vulnerability_type):
        """Provide remediation suggestions for found vulnerabilities"""
        suggestions = {
            "Authentication Bypass": "Implement strong password policies and multi-factor authentication",
            "Command Injection": "Sanitize all user inputs and use parameterized commands",
            "Information Disclosure": "Remove sensitive data from debug outputs and implement proper access controls",
            "Buffer Overflow": "Implement proper bounds checking and use memory-safe languages",
            "Firmware Manipulation": "Require cryptographic signatures for firmware updates",
            "Memory Access": "Implement proper memory protection and address space layout randomization",
            "Hardware Probing": "Disable debug interfaces in production and implement hardware locks",
            "Protocol Vulnerability": "Implement proper protocol validation and framing checks",
            "Physical Tampering": "Use tamper-evident packaging and active tamper detection",
            "Side Channel": "Implement constant-time algorithms and power analysis countermeasures",
            "Battery Vulnerability": "Implement hardware protection circuits and software limits",
            "Bus Probing": "Disable debug interfaces and implement bus encryption where possible",
            "Radio Vulnerability": "Implement RF power limits and require authentication for configuration changes"
        }
        return suggestions.get(vulnerability_type, "Review and harden the affected component")

    def generate_report(self):
        """Generate a comprehensive JSON report"""
        self.report['metadata']['scan_end'] = datetime.now().isoformat()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"iot_scan_report_{timestamp}.json"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        with open(report_path, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        return report_path

    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'uart') and self.uart:
            try:
                self.uart.close()
                print("\n🔌 Disconnected from device")
            except Exception as e:
                print(f"\n⚠ Error disconnecting: {str(e)}")

def main():
    print("""
    █▀▀ █▀▀█ █▀▀▄ █▀▀ █▀▀ ▀▀█▀▀ 
    █░░ █▄▄█ █▀▀▄ █▀▀ ▀▀█ ░░█░░ 
    ▀▀▀ ▀░░▀ ▀▀▀░ ▀▀▀ ▀▀▀ ░░▀░░
    IoT Security Scanner v4.0 with Dataset Generation
    Physical/Wired Attack Enhanced Edition
    """)

    scanner = IoTScanner()
    
    try:
        if scanner.scan_devices():
            scanner.run_security_tests()
        report_file = scanner.generate_report()
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    main()