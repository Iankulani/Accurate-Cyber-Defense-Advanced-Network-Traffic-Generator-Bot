import os
import sys
import time
import socket
import subprocess
import threading
import json
import platform
from datetime import datetime
import requests
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP
import psutil
import logging
from typing import Dict, List, Optional, Tuple
import select
import argparse
import readline  # For better input handling

# Constants
VERSION = "18.0.0"
AUTHOR = "Ian Carter Kulani"
RED_THEME = "\033[91m"
GREEN_THEME = "\033[92m"
BLUE_THEME = "\033[94m"
YELLOW_THEME = "\033[93m"
RESET_THEME = "\033[0m"
BANNER = f"""
{RED_THEME}
                    
{RESET_THEME}
"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('accuratecyber_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("accuatecyberdefenseBot")

class NetworkUtils:
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate an IPv4 address."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def get_local_ip() -> str:
        """Get the local IP address of the machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return "127.0.0.1"

    @staticmethod
    def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open on a given IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                return result == 0
        except Exception as e:
            logger.error(f"Error checking port {port} on {ip}: {e}")
            return False

    @staticmethod
    def get_hostname(ip: str) -> str:
        """Get hostname from IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ip

class TrafficGenerator:
    def __init__(self):
        self.is_generating = False
        self.thread = None

    def generate_icmp_traffic(self, target_ip: str, count: int = 100):
        """Generate ICMP traffic to a target IP."""
        try:
            for _ in range(count):
                if not self.is_generating:
                    break
                packet = IP(dst=target_ip)/ICMP()
                scapy.send(packet, verbose=False)
                time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error generating ICMP traffic: {e}")

    def generate_tcp_traffic(self, target_ip: str, port: int = 80, count: int = 100):
        """Generate TCP traffic to a target IP and port."""
        try:
            for _ in range(count):
                if not self.is_generating:
                    break
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
                scapy.send(packet, verbose=False)
                time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error generating TCP traffic: {e}")

    def start_traffic_generation(self, target_ip: str, traffic_type: str = "icmp"):
        """Start traffic generation in a separate thread."""
        if self.is_generating:
            return False, "Traffic generation already running"

        self.is_generating = True
        
        if traffic_type == "icmp":
            self.thread = threading.Thread(
                target=self.generate_icmp_traffic,
                args=(target_ip,),
                daemon=True
            )
        elif traffic_type == "tcp":
            self.thread = threading.Thread(
                target=self.generate_tcp_traffic,
                args=(target_ip,),
                daemon=True
            )
        else:
            self.is_generating = False
            return False, "Invalid traffic type"

        self.thread.start()
        return True, f"Started {traffic_type} traffic generation to {target_ip}"

    def stop_traffic_generation(self):
        """Stop traffic generation."""
        if not self.is_generating:
            return False, "No traffic generation running"

        self.is_generating = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        return True, "Stopped traffic generation"

class NetworkMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread = None
        self.captured_packets = []
        self.packet_count = 0
        self.target_ip = None

    def packet_callback(self, packet):
        """Callback function for packet capture."""
        if not self.is_monitoring:
            return
        
        if IP in packet:
            if self.target_ip and packet[IP].src != self.target_ip and packet[IP].dst != self.target_ip:
                return
            
            self.packet_count += 1
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "source": packet[IP].src,
                "destination": packet[IP].dst,
                "protocol": packet[IP].proto,
                "length": len(packet),
                "summary": packet.summary()
            }
            self.captured_packets.append(packet_info)
            
            if len(self.captured_packets) > 1000:  # Limit stored packets
                self.captured_packets.pop(0)

    def start_monitoring(self, target_ip: str = None, interface: str = None):
        """Start network monitoring."""
        if self.is_monitoring:
            return False, "Monitoring already running"

        self.target_ip = target_ip
        self.is_monitoring = True
        self.captured_packets = []
        self.packet_count = 0

        if not interface:
            interface = scapy.conf.iface

        self.monitor_thread = threading.Thread(
            target=scapy.sniff,
            kwargs={
                "prn": self.packet_callback,
                "store": False,
                "iface": interface,
                "filter": f"host {target_ip}" if target_ip else None
            },
            daemon=True
        )
        self.monitor_thread.start()
        return True, f"Started monitoring {'all traffic' if not target_ip else 'traffic for ' + target_ip}"

    def stop_monitoring(self):
        """Stop network monitoring."""
        if not self.is_monitoring:
            return False, "No monitoring running"

        self.is_monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            scapy.send(scapy.IP()/scapy.ICMP(), verbose=0)  # Send dummy packet to stop sniff
            self.monitor_thread.join(timeout=2)
        return True, "Stopped monitoring"

    def get_captured_packets(self, count: int = 10) -> List[Dict]:
        """Get captured packets."""
        return self.captured_packets[-count:] if self.captured_packets else []

    def get_stats(self) -> Dict:
        """Get monitoring statistics."""
        return {
            "is_monitoring": self.is_monitoring,
            "packet_count": self.packet_count,
            "target_ip": self.target_ip,
            "captured_packets": len(self.captured_packets)
        }

class TelegramBot:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}/"
        self.last_update_id = 0
        self.running = False
        self.command_handlers = {}

    def send_message(self, text: str) -> bool:
        """Send a message to the Telegram chat."""
        try:
            url = f"{self.base_url}sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error sending Telegram message: {e}")
            return False

    def get_updates(self) -> List[Dict]:
        """Get updates from Telegram."""
        try:
            url = f"{self.base_url}getUpdates"
            params = {
                "offset": self.last_update_id + 1,
                "timeout": 30
            }
            response = requests.get(url, params=params, timeout=35)
            if response.status_code == 200:
                updates = response.json().get("result", [])
                if updates:
                    self.last_update_id = updates[-1]["update_id"]
                return updates
            return []
        except Exception as e:
            logger.error(f"Error getting Telegram updates: {e}")
            return []

    def register_command(self, command: str, handler):
        """Register a command handler."""
        self.command_handlers[command] = handler

    def process_updates(self, updates: List[Dict]):
        """Process Telegram updates."""
        for update in updates:
            if "message" in update and "text" in update["message"]:
                message = update["message"]
                text = message["text"]
                if text.startswith("/"):
                    command = text.split()[0][1:].lower()
                    if command in self.command_handlers:
                        args = text.split()[1:]
                        self.command_handlers[command](args)

    def start(self):
        """Start the Telegram bot."""
        self.running = True
        logger.info("Telegram bot started")
        while self.running:
            updates = self.get_updates()
            if updates:
                self.process_updates(updates)
            time.sleep(1)

    def stop(self):
        """Stop the Telegram bot."""
        self.running = False
        logger.info("Telegram bot stopped")

class CyberSecBot:
    def __init__(self):
        self.running = True
        self.traffic_generator = TrafficGenerator()
        self.network_monitor = NetworkMonitor()
        self.telegram_bot = None
        self.command_history = []
        self.history_file = "command_history.json"
        self.config_file = "bot_config.json"
        self.load_config()
        self.load_history()
        
        # Initialize Telegram bot if configured
        if hasattr(self, 'telegram_token') and hasattr(self, 'telegram_chat_id'):
            self.telegram_bot = TelegramBot(self.telegram_token, self.telegram_chat_id)
            self.setup_telegram_handlers()
            telegram_thread = threading.Thread(target=self.telegram_bot.start, daemon=True)
            telegram_thread.start()

    def load_config(self):
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    for key, value in config.items():
                        setattr(self, key, value)
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def save_config(self):
        """Save configuration to file."""
        try:
            config = {
                "telegram_token": getattr(self, 'telegram_token', ''),
                "telegram_chat_id": getattr(self, 'telegram_chat_id', '')
            }
            with open(self.config_file, "w") as f:
                json.dump(config, f)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def load_history(self):
        """Load command history from file."""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r") as f:
                    self.command_history = json.load(f)
        except Exception as e:
            logger.error(f"Error loading history: {e}")

    def save_history(self):
        """Save command history to file."""
        try:
            with open(self.history_file, "w") as f:
                json.dump(self.command_history, f)
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def setup_telegram_handlers(self):
        """Setup Telegram command handlers."""
        if not self.telegram_bot:
            return

        def telegram_help(args):
            help_text = self.get_help_text()
            self.telegram_bot.send_message(f"<pre>{help_text}</pre>")

        def telegram_ping(args):
            if len(args) < 1:
                self.telegram_bot.send_message("Usage: /ping &lt;ip&gt;")
                return
            ip = args[0]
            if not NetworkUtils.validate_ip(ip):
                self.telegram_bot.send_message(f"Invalid IP address: {ip}")
                return
            result = self.ping_ip(ip)
            self.telegram_bot.send_message(f"Ping results for {ip}:\n<pre>{result}</pre>")

        # Register Telegram commands
        self.telegram_bot.register_command("help", telegram_help)
        self.telegram_bot.register_command("ping", telegram_ping)
        # Add more commands as needed...

    def get_help_text(self) -> str:
        """Get help text for all commands."""
        help_text = f"""{BANNER}
Accurate Cyber Defense Bot v{VERSION} - Help Menu

Basic Commands:
  help               - Show this help message
  clear              - Clear the screen
  exit               - Exit the program

Network Commands:
  ping <ip>          - Ping an IP address
  tracert <ip>       - Trace route to an IP address
  scan <ip>          - Scan common ports on an IP address
  startmon <ip>      - Start monitoring network traffic for an IP
  stopmon            - Stop monitoring network traffic
  gentraffic <ip>    - Generate network traffic to an IP
  stopgentraffic     - Stop generating network traffic
  view [count]       - View captured packets (default: 10)
  status             - Show current bot status

Telegram Commands:
  settoken <token>   - Set Telegram bot token
  setchat <chat_id>  - Set Telegram chat ID
  testtelegram       - Test Telegram integration

System Commands:
  export <filename>  - Export captured data to file
  history            - Show command history
"""
        return help_text

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)

    def ping_ip(self, ip: str) -> str:
        """Ping an IP address and return results."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'
            command = ['ping', param, count, ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            logger.error(f"Error pinging {ip}: {e}")
            return f"Error pinging {ip}: {str(e)}"

    def trace_route(self, ip: str) -> str:
        """Trace route to an IP address."""
        try:
            param = '-d' if platform.system().lower() == 'windows' else ''
            command = ['tracert', param, ip] if param else ['traceroute', ip]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            logger.error(f"Error tracing route to {ip}: {e}")
            return f"Error tracing route to {ip}: {str(e)}"

    def scan_ip(self, ip: str) -> str:
        """Scan common ports on an IP address."""
        if not NetworkUtils.validate_ip(ip):
            return f"Invalid IP address: {ip}"

        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        results = []
        
        def scan_port(port):
            if NetworkUtils.is_port_open(ip, port):
                results.append(f"Port {port} is open")

        threads = []
        for port in common_ports:
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=1)

        if not results:
            return f"No common ports open on {ip}"
        return f"Scan results for {ip}:\n" + "\n".join(results)

    def export_data(self, filename: str) -> str:
        """Export captured data to a file."""
        try:
            if not self.network_monitor.captured_packets:
                return "No captured data to export"

            with open(filename, 'w') as f:
                json.dump(self.network_monitor.captured_packets, f, indent=2)
            return f"Data exported to {filename}"
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            return f"Error exporting data: {str(e)}"

    def handle_command(self, command: str):
        """Handle user commands."""
        self.command_history.append(command)
        parts = command.split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            print(self.get_help_text())

        elif cmd == "clear":
            self.clear_screen()

        elif cmd == "exit":
            self.running = False
            print("Exiting CyberSecBot...")
            if self.network_monitor.is_monitoring:
                self.network_monitor.stop_monitoring()
            if self.traffic_generator.is_generating:
                self.traffic_generator.stop_traffic_generation()
            if self.telegram_bot:
                self.telegram_bot.stop()
            self.save_history()
            self.save_config()

        elif cmd == "ping" and len(args) >= 1:
            ip = args[0]
            if NetworkUtils.validate_ip(ip):
                print(f"Pinging {ip}...")
                result = self.ping_ip(ip)
                print(result)
                if self.telegram_bot:
                    self.telegram_bot.send_message(f"Ping results for {ip}:\n<pre>{result}</pre>")
            else:
                print(f"Invalid IP address: {ip}")

        elif cmd == "tracert" and len(args) >= 1:
            ip = args[0]
            if NetworkUtils.validate_ip(ip):
                print(f"Tracing route to {ip}...")
                result = self.trace_route(ip)
                print(result)
                if self.telegram_bot:
                    self.telegram_bot.send_message(f"Traceroute to {ip}:\n<pre>{result}</pre>")
            else:
                print(f"Invalid IP address: {ip}")

        elif cmd == "scan" and len(args) >= 1:
            ip = args[0]
            if NetworkUtils.validate_ip(ip):
                print(f"Scanning {ip}...")
                result = self.scan_ip(ip)
                print(result)
                if self.telegram_bot:
                    self.telegram_bot.send_message(f"Scan results for {ip}:\n<pre>{result}</pre>")
            else:
                print(f"Invalid IP address: {ip}")

        elif cmd == "startmon" and len(args) >= 1:
            ip = args[0]
            if NetworkUtils.validate_ip(ip):
                success, message = self.network_monitor.start_monitoring(ip)
                print(message)
                if self.telegram_bot:
                    self.telegram_bot.send_message(message)
            else:
                print(f"Invalid IP address: {ip}")

        elif cmd == "stopmon":
            success, message = self.network_monitor.stop_monitoring()
            print(message)
            if self.telegram_bot:
                self.telegram_bot.send_message(message)

        elif cmd == "gentraffic" and len(args) >= 1:
            ip = args[0]
            traffic_type = args[1] if len(args) > 1 else "icmp"
            if NetworkUtils.validate_ip(ip):
                success, message = self.traffic_generator.start_traffic_generation(ip, traffic_type)
                print(message)
                if self.telegram_bot:
                    self.telegram_bot.send_message(message)
            else:
                print(f"Invalid IP address: {ip}")

        elif cmd == "stopgentraffic":
            success, message = self.traffic_generator.stop_traffic_generation()
            print(message)
            if self.telegram_bot:
                self.telegram_bot.send_message(message)

        elif cmd == "view":
            count = 10
            if len(args) >= 1 and args[0].isdigit():
                count = int(args[0])
            packets = self.network_monitor.get_captured_packets(count)
            if not packets:
                print("No captured packets to display")
                return
            for packet in packets:
                print(f"{packet['timestamp']} - {packet['source']} -> {packet['destination']} "
                      f"({packet['protocol']}) - {packet['length']} bytes\n"
                      f"Summary: {packet['summary']}\n")

        elif cmd == "status":
            monitor_stats = self.network_monitor.get_stats()
            traffic_stats = {
                "is_generating": self.traffic_generator.is_generating,
            }
            telegram_status = "Connected" if self.telegram_bot and self.telegram_bot.running else "Disabled"
            
            print(f"{RED_THEME}AccurateBot Status{RESET_THEME}")
            print(f"Network Monitoring: {'Active' if monitor_stats['is_monitoring'] else 'Inactive'}")
            if monitor_stats['is_monitoring']:
                print(f"  Target IP: {monitor_stats['target_ip'] or 'All'}")
                print(f"  Packets Captured: {monitor_stats['packet_count']}")
            print(f"Traffic Generation: {'Active' if traffic_stats['is_generating'] else 'Inactive'}")
            print(f"Telegram Integration: {telegram_status}")

        elif cmd == "export" and len(args) >= 1:
            filename = args[0]
            result = self.export_data(filename)
            print(result)
            if self.telegram_bot:
                self.telegram_bot.send_message(result)

        elif cmd == "settoken" and len(args) >= 1:
            self.telegram_token = args[0]
            self.save_config()
            print("Telegram token set")
            if hasattr(self, 'telegram_chat_id'):
                self.telegram_bot = TelegramBot(self.telegram_token, self.telegram_chat_id)
                self.setup_telegram_handlers()
                telegram_thread = threading.Thread(target=self.telegram_bot.start, daemon=True)
                telegram_thread.start()

        elif cmd == "setchat" and len(args) >= 1:
            self.telegram_chat_id = args[0]
            self.save_config()
            print("Telegram chat ID set")
            if hasattr(self, 'telegram_token'):
                self.telegram_bot = TelegramBot(self.telegram_token, self.telegram_chat_id)
                self.setup_telegram_handlers()
                telegram_thread = threading.Thread(target=self.telegram_bot.start, daemon=True)
                telegram_thread.start()

        elif cmd == "testtelegram":
            if self.telegram_bot:
                success = self.telegram_bot.send_message("Test message from Accurate Cyber Defense network traffic Bot")
                print("Telegram test message sent successfully" if success else "Failed to send Telegram message")
            else:
                print("Telegram not configured. Use settoken and setchat commands first")

        elif cmd == "history":
            print("Command History:")
            for i, cmd in enumerate(self.command_history[-10:], 1):
                print(f"{i}. {cmd}")

        else:
            print(f"Unknown command: {cmd}. Type 'help' for available commands.")

    def run(self):
        """Main run loop for the bot."""
        self.clear_screen()
        print(f"{BANNER}")
        print(f"Accurate Cyber Defense Bot v{VERSION} - Type 'help' for commands\n")

        while self.running:
            try:
                command = input(f"{RED_THEME}accuratebot> {RESET_THEME}").strip()
                if command:
                    self.handle_command(command)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the accurate cyber defense bot")
            except Exception as e:
                logger.error(f"Error in command handling: {e}")
                print(f"Error: {str(e)}")

def main():
    # Check for root/admin privileges
    if os.name != 'nt' and os.geteuid() != 0:
        print("This tool requires root privileges for network operations.")
        sys.exit(1)

    bot = CyberSecBot()
    bot.run()

if __name__ == "__main__":
    main()