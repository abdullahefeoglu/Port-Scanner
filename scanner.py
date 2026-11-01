from scapy.all import IP , TCP , sr1, send
import random
import argparse

def syn_scan(target_ip, port):
    src_port = random.randint(1024,65535)
    syn_packet =IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")

    response = sr1(syn_packet, timeout=5, verbose= False)

    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                print(f"[+] Port {port} is OPEN")
                rst_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R",seq=response[TCP].ack)
                send(rst_packet, verbose=False)
            elif response[TCP].flags == 0x14:
                print(f"[-] Port {port} is CLOSED")
        else:
            print(f"[?] Port {port} - Unexpected response")
    else:
        print(f"[?] Port {port} is FILTERED (no response)")

def syn_scan_range(target_ip,ports):
    for port in ports:
        syn_scan(target_ip, port)



def parse_args():
    parser = argparse.ArgumentParser(description="TCP SYN Scan")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan", required=True)
    args = parser.parse_args()

    ports = [int(port) for port in args.ports.split(",")]
    return args.target_ip, ports

if __name__ == "__main__":
    target_ip, ports_to_scan = parse_args()
    syn_scan_range(target_ip, ports_to_scan)