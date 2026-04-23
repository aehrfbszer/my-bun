import socket
import struct
import threading
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
ECHO_SERVERS = [
    ("127.0.0.1", 54321),
    ("::1", 54322),
]
DNS_SERVERS = [
    ("dns.google", 53),
    ("2001:4860:4860::8888", 53),
]
DNS_DOMAIN = "example.com"
TEST_PAYLOAD = b"Hello SOCKS5 UDP proxy!"


def build_socks5_addr(host: str, port: int) -> bytes:
    try:
        parts = [int(x) for x in host.split('.')]
        if len(parts) == 4 and all(0 <= p < 256 for p in parts):
            return struct.pack("!BBBBBH", 0x01, *parts, port)
    except ValueError:
        pass

    try:
        addr = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + addr + struct.pack("!H", port)
    except OSError:
        pass

    host_bytes = host.encode("utf-8")
    return struct.pack("!BB", 0x03, len(host_bytes)) + host_bytes + struct.pack("!H", port)


def parse_socks5_udp_reply(data: bytes):
    if len(data) < 5:
        raise ValueError("SOCKS5 UDP reply too short")
    ver, rep, rsv, atyp = struct.unpack("!BBBB", data[:4])
    if ver != 0x05:
        raise ValueError(f"Unexpected SOCKS version: {ver}")
    if rep != 0x00:
        raise ValueError(f"SOCKS5 UDP associate failed, reply={rep}")

    offset = 4
    if atyp == 0x01:
        if len(data) < offset + 6:
            raise ValueError("Invalid IPv4 address in SOCKS5 reply")
        addr = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 0x03:
        length = data[offset]
        offset += 1
        addr = data[offset:offset + length].decode()
        offset += length
    elif atyp == 0x04:
        if len(data) < offset + 18:
            raise ValueError("Invalid IPv6 address in SOCKS5 reply")
        addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError(f"Unsupported ATYP {atyp}")

    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return addr, port


def parse_socks5_udp_packet(data: bytes):
    if len(data) < 4:
        raise ValueError("UDP packet too short")
    rsv, frag, atyp = struct.unpack("!HBB", data[:4])
    if rsv != 0:
        raise ValueError("Invalid RSV in SOCKS5 UDP packet")
    if frag != 0:
        raise ValueError("Fragmented UDP payload is not supported by this test")

    offset = 4
    if atyp == 0x01:
        addr = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 0x03:
        length = data[offset]
        offset += 1
        addr = data[offset:offset + length].decode()
        offset += length
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError(f"Unsupported ATYP {atyp}")

    port = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    return addr, port, data[offset:]


def test_bind():
    print("\n=== SOCKS5 BIND CMD 测试 ===")
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(5)
    tcp.connect((PROXY_HOST, PROXY_PORT))

    tcp.sendall(b"\x05\x01\x00")
    auth_reply = tcp.recv(2)
    print(f"握手响应: {auth_reply.hex()}")
    if auth_reply != b"\x05\x00":
        raise RuntimeError("SOCKS5 认证失败，代理不接受无认证")

    request = b"\x05\x02\x00" + build_socks5_addr("0.0.0.0", 0)
    tcp.sendall(request)
    first_reply = tcp.recv(262)
    print(f"BIND 第一个响应: {first_reply.hex()}")

    bound_host, bound_port = parse_socks5_udp_reply(first_reply)
    print(f"代理已绑定地址: {bound_host}:{bound_port}")

    if bound_host in ("0.0.0.0", "::"):
        connect_host = "127.0.0.1" if "." in PROXY_HOST else "::1"
    else:
        connect_host = bound_host

    remote = socket.socket(socket.AF_INET6 if ":" in connect_host else socket.AF_INET, socket.SOCK_STREAM)
    remote.settimeout(5)
    print(f"从远程客户端连接到代理绑定端口 {connect_host}:{bound_port}")
    remote.connect((connect_host, bound_port))

    second_reply = tcp.recv(262)
    print(f"BIND 第二个响应: {second_reply.hex()}")
    remote_host, remote_port = parse_socks5_udp_reply(second_reply)
    print(f"远程连接源地址: {remote_host}:{remote_port}")

    bind_test_payload = b"Hello BIND proxy!"
    tcp.sendall(bind_test_payload)
    received = remote.recv(4096)
    print(f"远程收到数据: {received!r}")

    if received != bind_test_payload:
        raise RuntimeError("BIND 数据转发失败: 远程接收数据不匹配")

    remote.sendall(b"BIND OK")
    acknowledgment = tcp.recv(4096)
    print(f"客户端收到回传: {acknowledgment!r}")

    if acknowledgment != b"BIND OK":
        raise RuntimeError("BIND 数据转发失败: 客户端未收到回传")

    remote.close()
    tcp.close()
    print("✅ BIND 命令测试通过")


def build_dns_query(domain: str) -> bytes:
    labels = domain.strip('.').split('.')
    qname = b''.join(len(label).to_bytes(1, 'big') + label.encode('ascii') for label in labels) + b'\x00'
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def read_dns_name(data: bytes, offset: int):
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("Invalid DNS name")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            name, _ = read_dns_name(data, pointer)
            return ".".join(labels + [name]), offset + 2
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length


def parse_dns_response(data: bytes):
    if len(data) < 12:
        raise ValueError("DNS response too short")
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = read_dns_name(data, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        name, offset = read_dns_name(data, offset)
        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if atype == 1 and rdlength == 4:
            answers.append(socket.inet_ntoa(rdata))
        elif atype == 28 and rdlength == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        else:
            answers.append((atype, rdata))
    return tid, ancount, answers


def start_udp_echo_server(host: str, port: int):
    stop_event = threading.Event()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port, 0, 0))
    else:
        sock.bind((host, port))

    def serve():
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            print(f"[Echo {host}] Received {len(data)} bytes from {addr}")
            sock.sendto(data, addr)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock, stop_event


def main():
    print("== SOCKS5 UDP 协议测试 ==")

    echo_servers = []
    for host, port in ECHO_SERVERS:
        print(f"启动本地 UDP 回显服务器：{host}:{port}")
        sock, stop_event = start_udp_echo_server(host, port)
        echo_servers.append((host, port, sock, stop_event))

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(5)
    tcp.connect((PROXY_HOST, PROXY_PORT))
    print(f"已连接 SOCKS5 代理 {PROXY_HOST}:{PROXY_PORT}")

    tcp.sendall(b"\x05\x01\x00")
    auth_reply = tcp.recv(2)
    print(f"握手响应: {auth_reply.hex()}")
    if auth_reply != b"\x05\x00":
        raise RuntimeError("SOCKS5 认证失败，代理不接受无认证")

    request = b"\x05\x03\x00" + build_socks5_addr("0.0.0.0", 0)
    tcp.sendall(request)
    data = tcp.recv(262)
    print(f"UDP ASSOCIATE 响应: {data.hex()}")

    relay_host, relay_port = parse_socks5_udp_reply(data)
    if relay_host == "0.0.0.0":
        relay_host = PROXY_HOST
    print(f"UDP relay 地址: {relay_host}:{relay_port}")

    for host, port, _, _ in echo_servers:
        print(f"\n--- 测试目标: {host}:{port} ---")
        udp_family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        udp = socket.socket(udp_family, socket.SOCK_DGRAM)
        udp.settimeout(5)
        if udp_family == socket.AF_INET6:
            udp.bind(("::", 0))
        else:
            udp.bind(("0.0.0.0", 0))

        socks5_udp_packet = b"\x00\x00\x00" + build_socks5_addr(host, port) + TEST_PAYLOAD
        print(f"发送 SOCKS5 UDP 数据包到回显服务器 ({host}:{port})")
        udp.sendto(socks5_udp_packet, (relay_host, relay_port))

        resp, addr = udp.recvfrom(4096)
        print(f"收到代理 UDP 响应 {len(resp)} bytes 来自 {addr}")

        dest_addr, dest_port, payload = parse_socks5_udp_packet(resp)
        print(f"解析到目标地址: {dest_addr}:{dest_port}")
        print(f"回显负载: {payload!r}")

        if payload == TEST_PAYLOAD:
            print("✅ SOCKS5 UDP 功能完整：回显 payload 与发送 payload 匹配")
        else:
            print("❌ SOCKS5 UDP 功能异常：回显 payload 与发送 payload 不匹配")

        udp.close()

    test_bind()

    print("\n=== DNS over UDP 测试 ===")
    dns_query = build_dns_query(DNS_DOMAIN)
    for dns_host, dns_port in DNS_SERVERS:
        print(f"\n--- DNS 目标: {dns_host}:{dns_port} ---")
        udp_family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        udp_dns = socket.socket(udp_family, socket.SOCK_DGRAM)
        udp_dns.settimeout(5)
        if udp_family == socket.AF_INET6:
            udp_dns.bind(("::", 0))
        else:
            udp_dns.bind(("0.0.0.0", 0))

        socks5_udp_packet = b"\x00\x00\x00" + build_socks5_addr(dns_host, dns_port) + dns_query
        print(f"发送 DNS 查询到 {dns_host}:{dns_port} (域名: {DNS_DOMAIN})")
        udp_dns.sendto(socks5_udp_packet, (relay_host, relay_port))

        resp, addr = udp_dns.recvfrom(4096)
        print(f"收到代理 DNS UDP 响应 {len(resp)} bytes 来自 {addr}")

        dest_addr, dest_port, payload = parse_socks5_udp_packet(resp)
        print(f"解析到目标地址: {dest_addr}:{dest_port}")

        tid, ancount, answers = parse_dns_response(payload)
        print(f"DNS 响应 ID={tid}, answer count={ancount}, answers={answers}")
        if ancount > 0 and answers:
            print("✅ DNS over UDP 功能完整：收到至少一个 DNS 应答")
        else:
            print("❌ DNS over UDP 功能异常：未收到 DNS 应答")

        udp_dns.close()

    tcp.close()
    for _, _, sock, stop_event in echo_servers:
        stop_event.set()
        sock.close()


if __name__ == "__main__":
    main()
