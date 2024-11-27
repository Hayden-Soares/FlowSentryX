from scapy.all import *
import random

def random_ip():
    """Generate a random IP address in the form of A.B.C.D."""
    return ".".join(map(str, (random.randint(1, 254) for _ in range(4))))

def random_port():
    """Generate a random source port between 1024 and 65535."""
    return random.randint(1024, 65535)

def send_syn_packet(target_ip, target_port):
    """Send a TCP SYN packet with random IP and port to the specified target."""
    src = random_ip()

    #src = '10.0.0.1'
    print("Source IP:", src)

    list_ip = list(map(int,src.split('.')))
    num_ip = list_ip[0]*2**24 + list_ip[1]*2**16 + list_ip[2]*2**8 + list_ip[3]

    print("IP integer:", num_ip)

    # Construct the Ethernet, IP, and TCP layers
    ether = Ether()
    ip = IP(src=src, dst=target_ip)
    tcp = TCP(sport=random_port(), dport=target_port, flags="R")
    payload = b"GET HEY"
    packet = ether / ip / tcp / payload
    print(type(packet))

    # Send the packet on the specified interface
    sendp(packet, iface="lo", verbose=False)  # Replace 'eth0' with your actual interface

# Example usage:
target_ip = "127.0.0.1"  # Replace with the target IP
target_port = 80         # Replace with the target port

while True:
    send_syn_packet(target_ip, target_port)
