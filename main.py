import socket
import requests
import struct
import ipaddress
import datetime
import argparse

packets_received = 0

def main():
    global packets_received

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--protocol', choices=['all', 'tcp', 'udp', 'icmp'], default='all')
    parser.add_argument('-i', '--interface',default='all')
    # parser.add_argument('-X', '--hex-dump', action='store_true')
    parser.add_argument('-a', '--abuse-check', action='store_true', help='Enable AbuseIPDB lookup for destination IP abuse score, don\'t forget to add your api key')
    args = parser.parse_args()

    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    if args.interface == 'all':
        pass
    else:
        try:
            connection.bind((args.interface, 0))
        except OSError as e:
            print(f'Error: {e}')
            return

    while True:

        data = connection.recv(65535)
        dest_mac, src_mac, data = unpack_frame(data)
        protc, src_ip, dest_ip, data = unpack_packet(data)


        if protc == 'TCP' and args.protocol.upper() == 'TCP' or args.protocol == 'all':
            packets_received += 1
            src_port, dest_port, seq_num, ack_num, window_size, flags, data = unpack_tcp(data)
            if args.abuse_check == True:
                print(get_score(dest_ip))
            print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} Flags[{flags}], ack {ack_num}, win {window_size}, length {len(data)} ')



        elif protc == 'UDP' and args.protocol.upper() == 'UDP' or args.protocol == 'all':
            packets_received += 1
            src_port, dest_port, header_length, packet_length = unpack_udp(data)
            if args.abuse_check == True:
                print(get_score(dest_ip))
            print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} UDP, length {len(packet_length)}')


        elif protc == 'ICMP' and args.protocol.upper() == 'ICMP' or args.protocol == 'all':
            packets_received += 1
            icmp_type, icmp_code, icmp_length = unpack_icmp(data)
            if args.abuse_check == True:
                print(get_score(dest_ip))
            print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip} -> {dest_ip} ICMP {icmp_type}, length {len(icmp_length)}')


def unpack_frame(data):
    dest_mac, src_mac, = struct.unpack('!6s6s', data[:12])
    return f"{':'.join(f"{byte:02x}" for byte in dest_mac)}", f"{':'.join(f"{byte:02x}" for byte in src_mac)}", data[14:]


def unpack_packet(data):
    vers_headlen = data[0]
    version = vers_headlen >> 4
    header_length = (vers_headlen & 15) * 4
    protc, src_ip, dest_ip = struct.unpack('! 9x B 2x 4s 4s', data[:20])

    if protc == 6:
        protc = 'TCP'
    elif protc == 17:
        protc = 'UDP'
    elif protc == 1:
        protc = 'ICMP'
    else:
        protc = f'Unkown: {protc}'
    return protc, socket.inet_ntoa(src_ip), socket.inet_ntoa(dest_ip), data[header_length:]

def unpack_tcp(data):
    src_port, dest_port, seq_num, ack_num, head_flags, window_size = struct.unpack('!HHLLHH', data[:16])
    header_length = (head_flags >> 12) * 4
    flags = {}
    flags["URG"] = (head_flags & 32) >> 5
    flags["ACK"] = (head_flags & 16) >> 4
    flags["PSH"] = (head_flags & 8) >> 3
    flags["RST"] = (head_flags & 4) >> 2
    flags["SYN"] = (head_flags & 2) >> 1
    flags["FIN"] = head_flags & 1
    flags_str = ', '.join(i for i in flags if flags[i] == 1)
    return src_port, dest_port, seq_num, ack_num, window_size, flags_str, data[header_length:]

def unpack_udp(data):
    src_port, dest_port, header_len = struct.unpack('!HHH', data[:6])
    return src_port, dest_port, header_len, data[8:]


def unpack_icmp(data):
    icmp_type, icmp_code = struct.unpack('!BB', data[:2])
    icmp_type_3_codes = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
    6: "Destination Network Unknown",
    7: "Destination Host Unknown",
    8: "Source Host Isolated (Obsolete)",
    9: "Destination Network Prohibited",
    10: "Destination Host Prohibited",
    11: "Network Unreachable for TOS",
    12: "Host Unreachable for TOS",
    13: "Communication Prohibited"
    }

    if icmp_type == 0:
        icmp_type = 'Echo Reply'
    elif icmp_type == 3:
        for i in icmp_type_3_codes:
            if i == icmp_code:
                icmp_type = icmp_type_3_codes[i]
    elif icmp_type == 8:
        icmp_type = 'Echo Request'
    elif icmp_tyye == 11:
        icmp_type = 'TTL Exceeded'
    else:
        icmp_type = f'Unknown (icmp_type = {icmp_type}, icmp_code: {icmp_code})'

    return icmp_type, icmp_code, data[4:]



def get_score(ip):
    if ipaddress.ip_address(ip).is_private:
        return 'Private IP'
    api_key = 'API KEY'
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            score = data["data"]["abuseConfidenceScore"]
            country = data["data"]["countryCode"]
            domain = data["data"]['domain']
            return f"Malicious: {score}/100  Domain: {domain}  Country: {country}"
        elif r.status_code == 429:
            return "Rate Limit Exceeded"
        else:
            return f"Error: HTTP {r.status_code}"
    except requests.RequestException:
        return "Request Failed"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f'\npackets received: {packets_received}')
