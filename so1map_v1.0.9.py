import socket
import requests
import struct
import ipaddress
import datetime
import argparse
import json
import csv
import hexdump

packets_received = 0
main_row = 0

def main():
    global packets_received
    global main_row

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--protocol', choices=['all', 'tcp', 'udp', 'icmp'], default='all')
    parser.add_argument('-i', '--interface',default='all')
    parser.add_argument('-f', '--file', choices=['csv', 'json', 'txt'], default='no')
    parser.add_argument('-n', '--name', help='you can also add paths example( -n /folder/tcp_01.json)')
    parser.add_argument('-X', '--hex-dump', action='store_true', help='Display raw packets')
    parser.add_argument('--quiet', action='store_true', help='Supress terminal output, use only if your writing to a file ofc')
    parser.add_argument('-a', '--abuse-check', action='store_true', help='Enable AbuseIPDB lookup for destination IP abuse score')
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
                if not args.quiet:
                    print(get_score(dest_ip))
            if not args.quiet:
                print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} TCP Flags[{flags}], ack {ack_num}, win {window_size}, length {len(data)} ')
            if len(data) > 0 and args.hex_dump == True:
                print()
                hex = hexdump.hexdump(data[:len(data)], result='return')
                if not args.quiet:
                    print(hex)
                    print()

            if args.file == 'no':
                pass
            elif args.file == 'json':
                if args.hex_dump == True and len(data) > 1:
                    data = {
                        'time':datetime.datetime.now().strftime("%H:%M:%S.%f"),
                        'src_ip':src_ip,
                        'src_port':src_port,
                        'dest_ip':dest_ip,
                        'dest_port':dest_port,
                        'flags':flags,
                        'ack_number':ack_num,
                        'window_size':window_size,
                        'length':len(data),
                        'hex':hex
                        }
                else:
                    data = {
                        'time':datetime.datetime.now().strftime("%H:%M:%S.%f"),
                        'src_ip':src_ip,
                        'src_port':src_port,
                        'dest_ip':dest_ip,
                        'dest_port':dest_port,
                        'flags':flags,
                        'ack_number':ack_num,
                        'window_size':window_size,
                        'length':len(data)
                        }


                write_file(data, args.file, args.name)

            elif args.file == 'csv':
                main_row += 1
                if args.hex_dump == True and len(data) > 1:
                    data = [['time', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'flags', 'ack_num', 'win_size', 'length', 'hex'], [datetime.datetime.now().strftime("%H:%M:%S.%f"), src_ip, src_port, dest_ip, dest_port, flags, ack_num, window_size, len(data), hex]]
                else:
                    data = [['time', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'flags', 'ack_num', 'win_size', 'length'], [datetime.datetime.now().strftime("%H:%M:%S.%f"), src_ip, src_port, dest_ip, dest_port, flags, ack_num, window_size, len(data)]]

                write_file(data, args.file, args.name, main_row)
            else:
                if args.hex_dump == True and len(data) > 1:
                    data = f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} TCP Flags[{flags}], ack {ack_num}, win {window_size}, length {len(data)}\n{hex}\n'
                else:
                    data = f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} TCP Flags[{flags}], ack {ack_num}, win {window_size}, length {len(data)}'
                write_file(data, args.file, args.name)


        elif protc == 'UDP' and args.protocol.upper() == 'UDP' or args.protocol == 'all':
            packets_received += 1
            src_port, dest_port, header_length, packet_length = unpack_udp(data)
            if args.abuse_check == True:
                if not args.quiet:
                    print(get_score(dest_ip))
            if not args.quiet:
                print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} UDP, length {len(packet_length)}')

            if len(packet_length) > 0 and args.hex_dump == True:
                print()
                hex = hexdump.hexdump(data[:len(packet_length)], result='return')
                if not args.quiet:
                    print(hex)
                    print()

            if args.file == 'no':
                pass
            elif args.file == 'json':
                if args.hex_dump == True and len(data) > 1:
                    data = {
                        'time':datetime.datetime.now().strftime("%H:%M:%S.%f"),
                        'src_ip':src_ip,
                        'src_port':src_port,
                        'dest_ip':dest_ip,
                        'dest_port':dest_port,
                        'length':len(packet_length),
                        'hex':hex
                        }
                else:
                    data = {
                    'time':datetime.datetime.now().strftime("%H:%M:%S.%f"),
                    'src_ip':src_ip,
                    'src_port':src_port,
                    'dest_ip':dest_ip,
                    'dest_port':dest_port,
                    'length':len(packet_length)
                    }
                write_file(data, args.file, args.name)

            elif args.file == 'csv':
                main_row += 1
                if args.hex_dump == True and len(data) > 1:
                    data = [['time', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'length', 'hex'], [datetime.datetime.now().strftime("%H:%M:%S.%f"), src_ip, src_port, dest_ip, dest_port, len(packet_length), hex]]
                else:
                    data = [['time', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'length'], [datetime.datetime.now().strftime("%H:%M:%S.%f"), src_ip, src_port, dest_ip, dest_port, len(packet_length)]]
                write_file(data, args.file, args.name, main_row)
            else:
                if args.hex_dump == True and len(data) > 1:
                    data = f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} UDP, length {len(packet_length)}\n{hex}\n'
                else:
                    data = f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip}:{src_port} -> {dest_ip}:{dest_port} UDP, length {len(packet_length)}'
                write_file(data, args.file, args.name)


        elif protc == 'ICMP' and args.protocol.upper() == 'ICMP' or args.protocol == 'all':
            packets_received += 1
            icmp_type, icmp_code, icmp_length = unpack_icmp(data)
            if args.abuse_check == True:
                if not args.quiet:
                    print(get_score(dest_ip))
            if not args.quiet:
                print(f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip} -> {dest_ip} ICMP {icmp_type}, length {len(icmp_length)}')
            if args.file == 'no':
                pass
            elif args.file == 'json':
                data = {
                    'time':datetime.datetime.now().strftime("%H:%M:%S.%f"),
                    'src_ip':src_ip,
                    'dest_ip':dest_ip,
                    'icmp_type':icmp_type,
                    'length':len(icmp_length)
                    }
                write_file(data, args.file, args.name)
            elif args.file == 'csv':
                main_row += 1
                data = [['time', 'src_ip','dest_ip', 'icmp_type', 'length'], [datetime.datetime.now().strftime("%H:%M:%S.%f"), src_ip, dest_ip, icmp_type, len(icmp_length)]]
                write_file(data, args.file, args.name, main_row)
            else:
                data = f'{datetime.datetime.now().strftime("%H:%M:%S.%f")} IP {src_ip} -> {dest_ip} ICMP {icmp_type}, length {len(icmp_length)}'
                write_file(data, args.file, args.name)


# function that unpacks frames
def unpack_frame(data):
    dest_mac, src_mac, = struct.unpack('!6s6s', data[:12])
    return f"{':'.join(f"{byte:02x}" for byte in dest_mac)}", f"{':'.join(f"{byte:02x}" for byte in src_mac)}", data[14:]

# function that unpacks ip packets
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

# function that unpacks tcp packets
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

# function that unpacks udp packets
def unpack_udp(data):
    src_port, dest_port, header_len = struct.unpack('!HHH', data[:6])
    return src_port, dest_port, header_len, data[8:]

# function that unpacks icmp packets
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

# function that provides abuse rating for ip's
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


# function that writes to various file types
def write_file(data, file_type, output_file, check=None):
    if not output_file:
        return
    if file_type == 'json':
        with open(output_file, 'a') as file:
            json.dump(data, file, indent=2)
    elif file_type == 'csv':
        with open(output_file, 'a') as file:
            writer = csv.writer(file)
            if check < 2:
                for row in data:
                    writer.writerow(row)
            else:
                writer.writerow(data[1])
    else:
        with open(output_file, 'a') as file:
            file.write(data + '\n')



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f'\npackets received: {packets_received}')
