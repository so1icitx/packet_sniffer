import socket
import struct
import requests
import ipaddress

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        data = connection.recv(65353)
        dest_mac, src_mac, data= unpack_frame(data)
        ver, protc, src_ip, dest_ip, data = unpack_ip(data)
        print('-'*30, 'PACKET', '-' * 30)
        print('\n')
        print(f'{get_score(dest_ip)}')
        print(f'{src_ip} ---> {dest_ip}')
        print(f'{src_mac} ---> {dest_mac}',f'{protc}')
        print('\n')
        print('-' * 66)


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
    api_key = '93f56cb498c0bbb52e4bcd7f4761b4a54975233c7b7c9f6c265d35941666032be94ce71f86c1940d'
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

