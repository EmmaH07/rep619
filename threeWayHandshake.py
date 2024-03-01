"""
Author: Emma Harel
DATE 1.3.24
Description: checking which ports are open using a 3 way handshake.
"""

from scapy.all import *
from scapy.layers.inet import TCP, IP

TIMEOUT = 0.5
START_PORT = 20
END_PORT = 1024


def check3way_handshake(ip_addr, port):
    """

    :param ip_addr: the computer's IP address
    :param port: the port to check if open
    :return: true if the port is open and false otherwise.
    """
    is_open = False
    syn_segment = TCP(dport=port, flags='S')
    try:
        syn_packet = IP(dst=ip_addr) / syn_segment
        syn_ack_packet = sr1(syn_packet, timeout=TIMEOUT)
        if syn_ack_packet is not None:
            f = syn_ack_packet.sprintf('%TCP.flags%')
            if f == 'SA':
                is_open = True

    except OSError as e:
        print(e)
    except Scapy_Exception as e:
        print(e)
    except Exception as e:
        print(e)

    finally:
        return is_open


def main():
    open_ports = 'Open ports: \r\n'
    comp_ip = input("please enter the computer's IP: ")
    current_port = START_PORT
    while current_port <= END_PORT:
        if check3way_handshake(comp_ip, current_port):
            open_ports += str(current_port) + "\r\n"
        current_port += 1

    if open_ports == 'Open ports: \r\n':
        open_ports = "there are no open ports"
    print(open_ports)


if __name__ == "__main__":
    main()
