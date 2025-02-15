# CamFlooder

This Python script performs a denial of service (DoS) attack by combining UDP, TCP, and ICMP packets to overload a target. It is a stress-testing tool, and its use should be restricted to controlled and authorized environments, such as penetration testing on networks you are responsible for.

## Features

- Generation of UDP, TCP, and ICMP packets with spoofed IPs.
- Simultaneous packet sending through multiple threads.
- Control over packet rate and payload size.
- Control over attack duration.
- Limitation of sent packets.
- Interruption of the attack via an interrupt signal (Ctrl+C).

## Requirements

- Python 3.x
- Python libraries: `scapy`, `argparse`

You can install the necessary dependencies with the following command:

```bash
pip install scapy argparse
```

## Usage

Run the script with the following command:

```bash
python3 main.py
```

## Examples:

1. To perform a 60-second attack with 1000 packets per second, a payload of 10000 bytes, 1000 threads, and no packet limit:

```bash
python3 main.py --target_ip 192.168.1.1 --rate 1000 --payload 10000 --threads 1000 --duration 60
```

2. To perform a 60-second attack with 1000 packets per second, a payload of 10000 bytes, 1000 threads, with a packet limit of 1000000:

```bash
python3 main.py --target_ip 192.168.1.1 --rate 1000 --payload 10000 --threads 1000 --duration 60 --max_packets 1000000
```

## Parameters

- `target_ip`: The IP address of the target of the attack.
- `--rate`: The number of packets per second (default: 1000).
- `--payload`: The size of the payload in bytes (default: 10000).
- `--threads`: The number of threads to use for sending packets (default: 1000).
- `--duration`: The duration of the attack in seconds (default: 60).
- `--max_packets`: The maximum number of packets to send (optional).

## How It Works

- The script generates spoofed packets for UDP, TCP, and ICMP protocols and sends them in large quantities to the target.
- It uses multiple threads to ensure the attack is distributed efficiently.
- The target receives packets at a high rate, causing overload and potential service disruption.

## Security and Responsibility

**WARNING: This script is intended exclusively for security testing in authorized environments.** Using this code on unauthorized networks may be illegal and violate usage policies. **You are responsible for the use of this script and should only use it in controlled environments with explicit permission.**

## License

This repository is licensed under the [MIT License](LICENSE).
