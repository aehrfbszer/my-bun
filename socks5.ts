// ========== 纯 Bun 原生 SOCKS5 代理 ==========
// 无任何 Node.js API，100% 使用 Bun 原生 TCPSocket / UDPSocket
const CONFIG = {
    host: "0.0.0.0",
    port: 1080,
    auth: {
        enabled: false,
        username: "user",
        password: "pass"
    }
};

// SOCKS5 常量
const VER = 0x05;
const AUTH_NONE = 0x00;
const AUTH_USER_PASS = 0x02;
const AUTH_FAIL = 0xFF;
const CONNECT = 0x01;
const UDP_ASSOCIATE = 0x03;
const IPV4 = 0x01;
const DOMAIN = 0x03;
const IPV6 = 0x04;
const SUCCESS = 0x00;
const ERR_GENERAL = 0x01;
const ERR_CONN_REFUSED = 0x05;



function buildAddr(host: string, port: number): Uint8Array {
    // 简单实现：假设 IPv4 或域名
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
        // IPv4
        const parts = host.split('.').map(Number);
        const buf = new Uint8Array(7);
        buf[0] = IPV4;
        buf[1] = parts[0];
        buf[2] = parts[1];
        buf[3] = parts[2];
        buf[4] = parts[3];
        buf[5] = (port >> 8) & 0xFF;
        buf[6] = port & 0xFF;
        return buf;
    } else {
        // 域名
        const hostBytes = new TextEncoder().encode(host);
        const buf = new Uint8Array(2 + hostBytes.length + 2);
        buf[0] = DOMAIN;
        buf[1] = hostBytes.length;
        buf.set(hostBytes, 2);
        buf[2 + hostBytes.length] = (port >> 8) & 0xFF;
        buf[2 + hostBytes.length + 1] = port & 0xFF;
        return buf;
    }
}


// 解析目标地址（纯 Bun Buffer）
function parseAddr(data: Uint8Array) {
    const atyp = data[3];
    let host: string, portOffset: number;

    const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);

    if (atyp === IPV4) {
        if (data.length < 10) {
            throw new Error("Invalid IPv4 address");
        }
        host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
        portOffset = 8;
    } else if (atyp === DOMAIN) {
        const len = data[4];
        if (!len || data.length < 5 + len + 2) {
            throw new Error("Invalid domain address");
        }
        host = new TextDecoder().decode(data.subarray(5, 5 + len));
        portOffset = 5 + len;
    } else if (atyp === IPV6) {
        if (data.length < 22) {
            throw new Error("Invalid IPv6 address");
        }
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(
            dataView.getUint16(4 + i).toString(16)
        );
        host = parts.join(":");
        portOffset = 20;
    } else return null;

    const port = dataView.getUint16(portOffset, false); // big-endian
    return { host, port, len: portOffset + 2 };
}

// 响应包
function reply(code: number, bndAddr?: string, bndPort?: number) {
    const buf = new Uint8Array(10);
    buf[0] = VER; buf[1] = code; buf[2] = 0; buf[3] = IPV4;
    if (bndAddr && bndPort !== undefined) {
        const parts = bndAddr.split('.').map(Number);
        buf[4] = parts[0] || 0;
        buf[5] = parts[1] || 0;
        buf[6] = parts[2] || 0;
        buf[7] = parts[3] || 0;
        buf[8] = (bndPort >> 8) & 0xFF;
        buf[9] = bndPort & 0xFF;
    }
    return buf;
}





// ============== SOCKS5 握手主逻辑 ==============

type SocketData = { stage: number; isHandshakeDone: boolean; tcpSocket?: Bun.TCPSocket; udpSocket?: Bun.udp.Socket<"uint8array">; socketType?: "tcp" | "udp" };

Bun.listen<SocketData>({
    hostname: CONFIG.host,
    port: CONFIG.port,
    socket: {
        data(client, data) {
            if (data[0] !== VER) {
                client.end();
                return
            }
            const stage = client.data.stage || 0;

            // 握手
            if (stage === 0) {
                if (!data[1]) {
                    client.end();
                    return;
                }
                const methods = data.subarray(2, 2 + data[1]);
                const needAuth = CONFIG.auth.enabled;
                const ok = needAuth ? methods.includes(AUTH_USER_PASS) : methods.includes(AUTH_NONE);

                client.write(new Uint8Array([VER, ok ? (needAuth ? AUTH_USER_PASS : AUTH_NONE) : AUTH_FAIL]));
                if (!ok) {
                    client.end()
                    return;
                }
                client.data.stage = needAuth ? 1 : 2;
                console.log(`[TCP] ${client.remoteAddress}:${client.remotePort} 连接成功，认证方式: ${needAuth ? "用户名密码" : "无"}`);
            }

            // 认证
            else if (stage === 1) {
                const ulen = data[1];
                if (!ulen || data.length < 2 + ulen + 1) {
                    client.write(new Uint8Array([1, AUTH_FAIL]));
                    client.end();
                    return;
                }
                const user = new TextDecoder().decode(data.subarray(2, 2 + ulen));
                const plen = data[2 + ulen];
                if (!plen || data.length < 3 + ulen + plen) {
                    client.write(new Uint8Array([1, AUTH_FAIL]));
                    client.end();
                    return;
                }
                const pass = new TextDecoder().decode(data.subarray(3 + ulen, 3 + ulen + plen));
                const success = user === CONFIG.auth.username && pass === CONFIG.auth.password;

                client.write(new Uint8Array([1, success ? 0 : 1]));
                if (!success) {
                    client.end()
                    return;
                }
                client.data.stage = 2;
            }

            // 请求
            else if (stage === 2) {

                if (!client.data.isHandshakeDone) {


                    const addr = parseAddr(data);
                    if (!addr) {
                        client.write(reply(ERR_GENERAL));
                        client.end();
                        return;
                    }
                    const cmd = data[1];

                    if (cmd === CONNECT) {
                        Bun.connect({
                            hostname: addr.host,
                            port: addr.port,
                            socket: {
                                open(remote) {
                                    console.log(`[TCP] ${addr.host}:${addr.port} 连接建立`);
                                },
                                data(remote, data) {
                                    console.log(`[TCP] 远程数据: ${data.length} bytes`);
                                    try {
                                        client.write(data);
                                    } catch (e) {
                                        console.error('Client write error:', e);
                                        remote.end();
                                    }
                                },
                                error(remote, err) {
                                    console.error('TCP connection error:', err);
                                    client.write(reply(ERR_CONN_REFUSED));
                                    client.end();
                                },
                                close(remote) {
                                    console.log('Remote closed');
                                    client.end();
                                }
                            }
                        }).then(remote => {
                            client.data.tcpSocket = remote;
                            client.data.isHandshakeDone = true;
                            client.data.socketType = "tcp";
                            client.write(reply(SUCCESS, "127.0.0.1", remote.localPort));
                            console.log(`[TCP] ${addr.host}:${addr.port} 连接成功,准备转发数据 BND: 127.0.0.1:${remote.localPort}`);
                        }).catch((err) => {
                            console.error('Connect failed:', err);
                            client.write(reply(ERR_CONN_REFUSED));
                            client.end();
                        });


                    }
                    else if (cmd === UDP_ASSOCIATE) {

                        Bun.udpSocket({
                            port: 0,
                            hostname: "0.0.0.0",
                            binaryType: "uint8array",
                            socket: {
                                data: async (socks5, data, port, host) => {
                                    if (data[0] || data[1] || data[2]) return;
                                    const addr = parseAddr(data);
                                    if (!addr) return;
                                    const payload = data.subarray(3 + addr.len);

                                    const udpClient = await Bun.udpSocket({
                                        socket: {
                                            data(out, res) {
                                                const addrBuf = buildAddr(addr.host, addr.port); // 需要实现 buildAddr 函数
                                                const packet = new Uint8Array(3 + addrBuf.length + res.length);
                                                packet[0] = 0; // RSV
                                                packet[1] = 0; // FRAG
                                                packet.set(addrBuf, 2); // ATYP + DST.ADDR + DST.PORT
                                                packet.set(res, 2 + addrBuf.length); // DATA'

                                                socks5.send(packet, port, host);
                                                out.close();
                                            }
                                        }
                                    });
                                    udpClient.send(payload, addr.port, addr.host);
                                },

                            }
                        }).then(udp => {
                            const res = new Uint8Array([VER, SUCCESS, 0, IPV4, 0, 0, 0, 0, (udp.port >> 8) & 0xFF, udp.port & 0xFF]);
                            client.write(res);
                            client.data.udpSocket = udp;
                            client.data.isHandshakeDone = true;
                            client.data.socketType = "udp";
                            console.log(`[UDP] ${addr.host}:${addr.port} 连接成功,准备转发数据`);

                        }).catch(() => {
                            client.write(reply(ERR_CONN_REFUSED));
                            client.end();
                        });

                    }
                    else {
                        console.error("Unsupported command:", cmd);
                        client.write(reply(ERR_GENERAL));
                        client.end();
                    }

                } else {

                    console.log(`[${client.data.socketType?.toUpperCase()}] ${client.remoteAddress}:${client.remotePort} => ${data.length} bytes`);

                    if (client.data.socketType === "udp") {
                        console.log(`[UDP] 转发数据到 ${client.remoteAddress}:${client.remotePort}`);
                        const udpSocket = client.data.udpSocket;
                        if (udpSocket) {
                            udpSocket.send(data, client.remotePort, client.remoteAddress);
                        } else {
                            console.error("No redirect udp socket for established connection");
                            client.end();
                        }
                        return;
                    }

                    console.log(`[TCP] 转发数据到 ${client.remoteAddress}:${client.remotePort}`);
                    const tcpSocket = client.data.tcpSocket;
                    if (tcpSocket) {
                        try {
                            tcpSocket.write(data);
                        } catch (e) {
                            console.error('TCP write error:', e);
                            client.end();
                        }
                    } else {
                        console.error("No redirect tcp socket for established connection");
                        client.end();
                    }
                }
            }
        },
        open: (socket) => {
            socket.data = { stage: 0, isHandshakeDone: false };
            console.log(`Client ${socket.remoteAddress}:${socket.remotePort} connected`);
        }, // 初始化阶段
        close(client) {
            console.log(`Client ${client.remoteAddress}:${client.remotePort} closed`);
            console.log(!!client.data.tcpSocket, !!client.data.udpSocket)
            if (client.data.tcpSocket) {
                client.data.tcpSocket.end();
            }
            if (client.data.udpSocket) {
                client.data.udpSocket.close();
            }
        },
        error(_, err) { console.error("[err]", err) },
        binaryType: "uint8array"
    }
});

console.log(`✅ 纯 Bun SOCKS5 启动 => ${CONFIG.host}:${CONFIG.port}`);
console.log(`🔐 认证：${CONFIG.auth.enabled ? "ON" : "OFF"}`);