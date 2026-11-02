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
    parser.add_argument("-p", "--ports", help="Ports or port ranges (e.g. 80,443,1-1000)", required=True)
    args = parser.parse_args()

    ports = []
    port_groups = args.ports.split(",")

    for group in port_groups:
        if "-" in group:
            start, end = group.split("-")

            start = int(start)
            end = int(end)

            if start > end:
                parser.error("Start port cannot be greater than end port")

            ports.extend(range(start,end + 1))
        else:
            ports.append(int(group))

    if any(port < 1 or port > 65535 for port in ports):
        parser.error("Ports must be between 1 and 65535")

    return args.target_ip, ports

if __name__ == "__main__":
    target_ip, ports_to_scan = parse_args()
    syn_scan_range(target_ip, ports_to_scan)