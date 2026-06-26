import socket
import struct

s = socket.socket()
s.connect(('mysterious-sea.picoctf.net', 53754))

buf = b''
def recv_until(marker):
    global buf
    while marker not in buf:
        buf += s.recv(4096)
    idx = buf.index(marker) + len(marker)
    result = buf[:idx]
    buf = buf[idx:]
    return result

for i in range(20):
    recv_until(b"Here's the next binary in bytes:\n")
    data = recv_until(b"What's the secret?:")
    hex_str = data.split(b"What's the secret?:")[0].strip().decode()
    hex_str = hex_str.replace('\n', '').replace(' ', '')
    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    binary = bytes.fromhex(hex_str)
    idx = binary.find(b'\xc7\x45\xfc')
    secret = struct.unpack('<I', binary[idx+3:idx+7])[0]
    s.sendall(str(secret).encode() + b'\n')
    print(f"Binary {i+1}: {secret}")

rest = s.recv(4096)
print(rest.decode())