// ========== 纯 Bun 原生 SOCKS5 代理 ==========
// 无任何 Node.js API，100% 使用 Bun 原生 TCPSocket / UDPSocket
const CONFIG = {
  host: "0.0.0.0",
  port: 1080,
  auth: {
    enabled: false,
    username: "user",
    password: "pass",
  },
};

// SOCKS5 常量
const VER = 0x05;
const AUTH_NONE = 0x00;
const AUTH_USER_PASS = 0x02;
const AUTH_FAIL = 0xff;
const CONNECT = 0x01;
const UDP_ASSOCIATE = 0x03;
const IPV4 = 0x01;
const DOMAIN = 0x03;
const IPV6 = 0x04;
const SUCCESS = 0x00;
const ERR_GENERAL = 0x01;
const ERR_CONN_REFUSED = 0x05;
const ERR_CMD_NOT_SUPPORTED = 0x07;

// 解析目标地址（纯 Bun Buffer）
function parseAddr(data: Uint8Array) {
  const atyp = data[3];
  let host: string;
  let portOffset = 4;

  const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);

  if (atyp === IPV4) {
    if (data.length < 10) {
      throw new Error("Invalid IPv4 address");
    }
    host = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
    portOffset += 4;
  } else if (atyp === DOMAIN) {
    const len = data[4];
    if (!len || data.length < 5 + len + 2) {
      throw new Error("Invalid domain address");
    }
    portOffset += 1;
    host = new TextDecoder().decode(data.subarray(5, 5 + len));
    portOffset += len;
  } else if (atyp === IPV6) {
    if (data.length < 22) {
      throw new Error("Invalid IPv6 address");
    }
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(dataView.getUint16(4 + i).toString(16));
    host = parts.join(":");
    portOffset += 16;
  } else {
    return null;
  }

  const port = dataView.getUint16(portOffset, false); // big-endian
  return { host, port, offset: portOffset + 2 };
}

// 响应包
function reply(code: number) {
  const buf = new Uint8Array(10);
  buf.set([VER, code, 0, IPV4], 0); // 默认回复 IPv4
  return buf;
}

function encodeIPv6(addr: string) {
  const parts = addr.split("::");
  if (parts.length > 2) {
    throw new Error("Invalid IPv6 address");
  }
  const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
  const right = parts[1] ? parts[1].split(":").filter(Boolean) : [];
  const zeros = new Array(8 - left.length - right.length).fill("0");
  const groups = [...left, ...zeros, ...right];
  const buf = new Uint8Array(16);
  const dataView = new DataView(buf.buffer);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i] || "0", 16);
    dataView.setUint16(i * 2, val, false); // big-endian
  }
  return buf;
}

// ============== SOCKS5 握手主逻辑 ==============

type SocketData = {
  stage: number;
  isHandshakeDone: boolean;
  tcpSocket?: Bun.TCPSocket;
  udpSocket?: Bun.udp.Socket<"uint8array">;
  socketType?: "tcp" | "udp";
};

Bun.listen<SocketData>({
  hostname: CONFIG.host,
  port: CONFIG.port,
  socket: {
    binaryType: "uint8array",
    async data(localSocket, clientData: Uint8Array) {
      const stage = localSocket.data.stage || 0;

      // 握手
      if (stage === 0) {
        if (clientData[0] !== VER) {
          console.error("Unsupported SOCKS version:", clientData[0]);
          localSocket.end();
          return;
        }
        if (!clientData[1]) {
          console.error("No authentication methods provided");
          localSocket.end();
          return;
        }
        const methods = clientData.subarray(2, 2 + clientData[1]);
        const needAuth = CONFIG.auth.enabled;
        const ok = needAuth ? methods.includes(AUTH_USER_PASS) : methods.includes(AUTH_NONE);

        localSocket.write(
          new Uint8Array([VER, ok ? (needAuth ? AUTH_USER_PASS : AUTH_NONE) : AUTH_FAIL]),
        );
        if (!ok) {
          console.error("No acceptable authentication method");
          localSocket.end();
          return;
        }
        localSocket.data.stage = needAuth ? 1 : 2;
        console.log(
          `[TCP] ${localSocket.remoteAddress}:${localSocket.remotePort} 连接成功，认证方式: ${needAuth ? "用户名密码" : "无"}`,
        );
      }

      // 认证
      else if (stage === 1) {
        const ulen = clientData[1];
        if (!ulen || clientData.length < 2 + ulen + 1) {
          localSocket.write(new Uint8Array([1, AUTH_FAIL]));
          localSocket.end();
          return;
        }
        const user = new TextDecoder().decode(clientData.subarray(2, 2 + ulen));
        const plen = clientData[2 + ulen];
        if (!plen || clientData.length < 3 + ulen + plen) {
          localSocket.write(new Uint8Array([1, AUTH_FAIL]));
          localSocket.end();
          return;
        }
        const pass = new TextDecoder().decode(clientData.subarray(3 + ulen, 3 + ulen + plen));
        const success = user === CONFIG.auth.username && pass === CONFIG.auth.password;

        localSocket.write(new Uint8Array([1, success ? 0 : 1]));
        if (!success) {
          localSocket.end();
          return;
        }
        localSocket.data.stage = 2;
      }

      // 请求
      else if (stage === 2) {
        if (!localSocket.data.isHandshakeDone) {
          const addr = parseAddr(clientData);
          if (!addr) {
            localSocket.write(reply(ERR_GENERAL));
            localSocket.end();
            return;
          }
          const cmd = clientData[1];

          if (cmd === CONNECT) {
            try {
              const tcpRedirect = await Bun.connect({
                hostname: addr.host,
                port: addr.port,
                socket: {
                  binaryType: "uint8array",
                  open(remote) {
                    console.log(`[TCP] ${addr.host}:${addr.port} 连接建立`);
                  },
                  data(remote, data: Uint8Array) {
                    // console.log(`[TCP] 远程数据: ${data.length} bytes`);
                    localSocket.write(data);
                  },
                  error(remote, err) {
                    console.error("TCP connection error:", err);
                    localSocket.write(reply(ERR_CONN_REFUSED));
                    localSocket.end();
                  },
                  close(remote) {
                    console.log("Remote closed");
                    localSocket.end();
                  },
                },
              });

              localSocket.write(reply(SUCCESS));

              console.log(
                `[TCP] ${addr.host}:${addr.port} 连接成功,准备转发数据 BND: port:${tcpRedirect.localPort}`,
              );
              localSocket.data.tcpSocket = tcpRedirect;
              localSocket.data.isHandshakeDone = true;
              localSocket.data.socketType = "tcp";
            } catch (e) {
              console.error("Failed to establish connection:", addr.host, addr.port, e);
              localSocket.write(reply(ERR_CONN_REFUSED));
              localSocket.end();
            }
          } else if (cmd === UDP_ASSOCIATE) {
            console.log(
              `[UDP+++++++] ${localSocket.remoteAddress}:${localSocket.remotePort} 请求 UDP 关联`,
            );

            try {
              const udpRedirect = await Bun.udpSocket({
                port: 0,
                hostname: "::",
                binaryType: "uint8array",
                socket: {
                  data: async (socks5, clientUdpData, port, host) => {
                    // console.log(`[UDP] 收到数据 ${data.length} bytes 来自 ${host}:${port}`);
                    if (clientUdpData[0] || clientUdpData[1] || clientUdpData[2]) {
                      // 不支持分片的 UDP 数据包，RSV 必须为 0，FRAG 必须为 0
                      console.error("Invalid UDP packet header");
                      socks5.close();
                      return;
                    }
                    const addr = parseAddr(clientUdpData);
                    if (!addr) {
                      console.error("Invalid UDP packet address");
                      socks5.close();
                      return;
                    }
                    const payload = clientUdpData.subarray(addr.offset);

                    const udpClient = await Bun.udpSocket({
                      port: 0,
                      hostname: "::",
                      binaryType: "uint8array",
                      socket: {
                        data(out, res) {
                          const addrBuf = clientUdpData.subarray(3, addr.offset); // ATYP + DST.ADDR + DST.PORT
                          const packet = new Uint8Array(3 + addrBuf.length + res.length);
                          const dataView = new DataView(packet.buffer);
                          dataView.setUint16(0, 0); // RSV
                          dataView.setUint8(2, 0); // FRAG
                          packet.set(addrBuf, 3); // ATYP + DST.ADDR + DST.PORT
                          packet.set(res, 3 + addrBuf.length); // DATA'

                          socks5.send(packet, port, host);
                          out.close();
                        },
                        error(out, err) {
                          console.error("[UDP Client] send error:", err);
                          out.close();
                        },
                      },
                    });
                    udpClient.send(payload, addr.port, addr.host);
                  },
                },
              });

              let IPFamily = IPV4;

              let addrBytes: Uint8Array;
              if (udpRedirect.address.family === "IPv6") {
                IPFamily = IPV6;

                addrBytes = encodeIPv6(udpRedirect.address.address);
              } else {
                IPFamily = IPV4;
                const parts = udpRedirect.address.address.split(".").map(Number);
                addrBytes = new Uint8Array(parts);
              }
              const res = new Uint8Array(4 + addrBytes.length + 2);
              const dataView = new DataView(res.buffer);
              res.set([VER, SUCCESS, 0, IPFamily], 0);
              res.set(addrBytes, 4);
              dataView.setUint16(4 + addrBytes.length, udpRedirect.port, false); // big-endian
              localSocket.write(res);
              localSocket.data.udpSocket = udpRedirect;
              localSocket.data.isHandshakeDone = true;
              localSocket.data.socketType = "udp";
              console.log(`[UDP] ${addr.host}:${addr.port} 连接成功,准备转发数据`);
            } catch (e) {
              console.error("UDP association error:", e);
              localSocket.write(reply(ERR_GENERAL));
              localSocket.end();
            }
          } else {
            console.error("Unsupported command:", cmd);
            localSocket.write(reply(ERR_CMD_NOT_SUPPORTED));
            localSocket.end();
          }
        } else {
          //   console.log(
          //     `[${client.data.socketType?.toUpperCase()}] ${client.remoteAddress}:${client.remotePort} => ${data.length} bytes`,
          //   );

          // 这是永远不会发生的情况，因为 UDP 数据包是通过独立的 UDP Socket 处理的，但为了代码健壮性，还是加个判断
          if (localSocket.data.socketType === "udp") {
            console.error("Received TCP data on a UDP socket, closing");
            localSocket.end();
            return;
          }

          //   console.log(`[TCP] 转发数据到 ${client.remoteAddress}:${client.remotePort}`);
          const tcpSocket = localSocket.data.tcpSocket;
          if (tcpSocket) {
            try {
              tcpSocket.write(clientData);
            } catch (e) {
              console.error("TCP write error:", e);
              localSocket.end();
            }
          } else {
            console.error("No redirect tcp socket for established connection");
            localSocket.end();
          }
        }
      }
    },
    open: (socket) => {
      socket.data = { stage: 0, isHandshakeDone: false };
      console.log(`Client ${socket.remoteAddress}:${socket.remotePort} connected`);
    }, // 初始化阶段
    close(socket) {
      console.log(`Client closed`);
      if (socket.data.tcpSocket) {
        socket.data.tcpSocket.end();
      }
      if (socket.data.udpSocket) {
        socket.data.udpSocket.close();
      }
    },
    error(socket, err) {
      console.error("[err]", err);
      if (socket.data.tcpSocket) {
        socket.data.tcpSocket.end();
      }
      if (socket.data.udpSocket) {
        socket.data.udpSocket.close();
      }
    },
  },
});

console.log(`✅ 纯 Bun SOCKS5 启动 => ${CONFIG.host}:${CONFIG.port}`);
console.log(`🔐 认证：${CONFIG.auth.enabled ? "ON" : "OFF"}`);
