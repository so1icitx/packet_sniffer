import socket
import struct


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        data = connection.recv(65353)
        dest_mac, src_mac, data= unpack_frame(data)

        print('-'*30, 'PACKET', '-' * 30)
        print('\n')
        print(f'{src_mac} ---> {dest_mac}')
        print('\n')
        print('-' * 66)


def unpack_frame(data):
    dest_mac, src_mac, eth_type= struct.unpack('!6s6sH', data[:14])
    return f'{":".join(f'{byte:02x}'for byte in dest_mac)}', f'{":".join(f'{byte:02x}'for byte in src_mac)}', data[14:]

main()
