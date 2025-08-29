import socket
import struct
import requests
import ipaddress


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        data = conn.recv(65535)
        dest_mac, src_mac, data = unpack_frame(data)
        ver, protc, src_ip, dest_ip, data = unpack_ip(data)
        if protc == "ICMP":
            icmp_type, icmp_code, icmp_checksum = struct.unpack('!BBH', data[:4])
            if icmp_type == 0:
                icmp_type = 'Echo reply'
            elif icmp_type == 3:
                icmp_type = 'Destination unreachable'
            elif icmp_type == 8:
                icmp_type = 'Echo request'
            elif icmp_type == 11:
                icmp_type = 'Time exceeded'
            else:
                icmp_type = f'Unknown {icmp_type}'
            print(f'{src_ip} ---> {dest_ip}: {protc}, {icmp_type}')

        elif protc == 'TCP':

            src_port, dest_port, seq_num, ack_num, head_resv_bits, window, = struct.unpack('!HHLLHH', data[:16])
            offset = (head_resv_bits >> 12) * 4
            flags = {}
            flags["urg"] = (head_resv_bits & 32) >> 5
            flags["ack"] = (head_resv_bits & 16) >> 4
            flags["psh"] = (head_resv_bits & 8) >> 3
            flags["rst"] = (head_resv_bits & 4) >> 2
            flags["syn"] = (head_resv_bits & 2) >> 1
            flags["fin"] = head_resv_bits & 1


            print(f'{src_ip}:{src_port} ---> {dest_ip}:{dest_port}, seq {seq_num}, ack {ack_num}, flags [{f", ".join(i[0] for i in flags.items() if i[1]==1)}], window {window}, length {len(data[offset:])}')








def unpack_frame(data):
    dest_mac, src_mac, eth_type= struct.unpack('!6s6sH', data[:14])
    return f'{":".join(f'{byte:02x}'for byte in dest_mac)}', f'{":".join(f'{byte:02x}'for byte in src_mac)}', data[14:]

def unpack_ip(data):
    vers_head = data[0]
    version = vers_head >> 4
    header_len = (vers_head & 15) * 4
    protc, src_ip, dest_ip = struct.unpack('!9x B 2x 4s 4s', data[:20])

    if protc == 6:
        protc = 'TCP'
    elif protc == 1:
        protc = 'ICMP'
    elif protc == 17:
        protc = 'UDP'
    else:
        protc = f'Other:{protc}'

    return version, protc, socket.inet_ntoa(src_ip), socket.inet_ntoa(dest_ip), data[header_len:]


def get_score(ip):
    if ipaddress.ip_address(ip).is_private:
        return 'Private IP'
    api_key = 'YOUR API KEY' 
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
        print("\n[+] Exiting ...")
