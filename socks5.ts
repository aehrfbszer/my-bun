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
  return { host, port, len: portOffset + 2 };
}

// 响应包
function reply(code: number, bndAddr?: string, bndPort?: number) {
  const buf = new Uint8Array(10);
  buf[0] = VER;
  buf[1] = code;
  buf[2] = 0;
  buf[3] = IPV4;
  if (bndAddr && bndPort !== undefined) {
    const parts = bndAddr.split(".").map(Number);
    buf[4] = parts[0] || 0;
    buf[5] = parts[1] || 0;
    buf[6] = parts[2] || 0;
    buf[7] = parts[3] || 0;
    buf[8] = (bndPort >> 8) & 0xff;
    buf[9] = bndPort & 0xff;
  }
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
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i] || "0", 16);
    buf[i * 2] = (val >> 8) & 0xff;
    buf[i * 2 + 1] = val & 0xff;
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
    async data(client, data) {
      const stage = client.data.stage || 0;

      // 握手
      if (stage === 0) {
        if (data[0] !== VER) {
          console.error("Unsupported SOCKS version:", data[0]);
          client.end();
          return;
        }
        if (!data[1]) {
          console.error("No authentication methods provided");
          client.end();
          return;
        }
        const methods = data.subarray(2, 2 + data[1]);
        const needAuth = CONFIG.auth.enabled;
        const ok = needAuth ? methods.includes(AUTH_USER_PASS) : methods.includes(AUTH_NONE);

        client.write(
          new Uint8Array([VER, ok ? (needAuth ? AUTH_USER_PASS : AUTH_NONE) : AUTH_FAIL]),
        );
        if (!ok) {
          console.error("No acceptable authentication method");
          client.end();
          return;
        }
        client.data.stage = needAuth ? 1 : 2;
        console.log(
          `[TCP] ${client.remoteAddress}:${client.remotePort} 连接成功，认证方式: ${needAuth ? "用户名密码" : "无"}`,
        );
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
          client.end();
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
            try {
              const tcpRedirect = await Bun.connect({
                hostname: addr.host,
                port: addr.port,
                socket: {
                  open(remote) {
                    console.log(`[TCP] ${addr.host}:${addr.port} 连接建立`);
                  },
                  data(remote, data) {
                    // console.log(`[TCP] 远程数据: ${data.length} bytes`);
                    try {
                      client.write(data);
                    } catch (e) {
                      console.error("Client write error:", e);
                      remote.end();
                    }
                  },
                  error(remote, err) {
                    console.error("TCP connection error:", err);
                    client.write(reply(ERR_CONN_REFUSED));
                    client.end();
                  },
                  close(remote) {
                    console.log("Remote closed");
                    client.end();
                  },
                },
              });

              client.write(reply(SUCCESS));

              console.log(
                `[TCP] ${addr.host}:${addr.port} 连接成功,准备转发数据 BND: port:${tcpRedirect.localPort}`,
              );
              client.data.tcpSocket = tcpRedirect;
              client.data.isHandshakeDone = true;
              client.data.socketType = "tcp";
            } catch (e) {
              console.error("Failed to establish connection:", addr.host, addr.port, e);
              client.write(reply(ERR_CONN_REFUSED));
              client.end();
            }
          } else if (cmd === UDP_ASSOCIATE) {
            console.log(`[UDP+++++++] ${client.remoteAddress}:${client.remotePort} 请求 UDP 关联`);

            try {
              const udpRedirect = await Bun.udpSocket({
                port: 0,
                hostname: "::",
                binaryType: "uint8array",
                socket: {
                  data: async (socks5, data, port, host) => {
                    console.log(`[UDP] 收到数据 ${data.length} bytes 来自 ${host}:${port}`);
                    if (data[0] || data[1] || data[2]) {
                      console.error("Invalid UDP packet header");
                      socks5.close();
                      return;
                    }
                    const addr = parseAddr(data);
                    if (!addr) {
                      console.error("Invalid UDP packet address");
                      socks5.close();
                      return;
                    }
                    const payload = data.subarray(addr.len);

                    const udpClient = await Bun.udpSocket({
                      port: 0,
                      hostname: "::",
                      binaryType: "uint8array",
                      socket: {
                        data(out, res) {
                          const addrBuf = data.subarray(3, addr.len); // ATYP + DST.ADDR + DST.PORT
                          const packet = new Uint8Array(3 + addrBuf.length + res.length);
                          packet[0] = 0; // RSV
                          packet[1] = 0; // RSV
                          packet[2] = 0; // FRAG
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

              let ipArr: number[] = [];
              let IPFamily = IPV4;
              switch (udpRedirect.address.family) {
                case "IPv4":
                  ipArr = udpRedirect.address.address.split(".").map(Number);
                  IPFamily = IPV4;
                  console.log(`[UDP] 监听在 ${udpRedirect.hostname}:${udpRedirect.port} (IPv4)`);
                  break;
                case "IPv6":
                  ipArr = udpRedirect.address.address.split(":").map((x) => parseInt(x, 16));
                  IPFamily = IPV6;
                  console.log(`[UDP] 监听在 [${udpRedirect.hostname}]:${udpRedirect.port} (IPv6)`);
                  break;
                default:
                  console.log(
                    `[UDP] 监听在 ${udpRedirect.hostname}:${udpRedirect.port} (未知协议)`,
                  );
              }

              let addrBytes: Uint8Array;
              if (udpRedirect.address.family === "IPv6") {
                addrBytes = encodeIPv6(udpRedirect.address.address);
              } else {
                const parts = udpRedirect.address.address.split(".").map(Number);
                addrBytes = new Uint8Array(parts);
              }
              const res = new Uint8Array(4 + addrBytes.length + 2);
              res[0] = VER;
              res[1] = SUCCESS;
              res[2] = 0;
              res[3] = IPFamily;
              res.set(addrBytes, 4);
              res[4 + addrBytes.length] = (udpRedirect.port >> 8) & 0xff;
              res[5 + addrBytes.length] = udpRedirect.port & 0xff;
              client.write(res);
              client.data.udpSocket = udpRedirect;
              client.data.isHandshakeDone = true;
              client.data.socketType = "udp";
              console.log(`[UDP] ${addr.host}:${addr.port} 连接成功,准备转发数据`);
            } catch (e) {
              console.error("UDP association error:", e);
              client.write(reply(ERR_GENERAL));
              client.end();
            }
          } else {
            console.error("Unsupported command:", cmd);
            client.write(reply(ERR_CMD_NOT_SUPPORTED));
            client.end();
          }
        } else {
          //   console.log(
          //     `[${client.data.socketType?.toUpperCase()}] ${client.remoteAddress}:${client.remotePort} => ${data.length} bytes`,
          //   );

          // 这是永远不会发生的情况，因为 UDP 数据包是通过独立的 UDP Socket 处理的，但为了代码健壮性，还是加个判断
          if (client.data.socketType === "udp") {
            // console.log(`[UDP] 转发数据到 ${client.remoteAddress}:${client.remotePort}`);
            const udpSocket = client.data.udpSocket;
            if (udpSocket) {
              udpSocket.send(data, client.remotePort, client.remoteAddress);
            } else {
              console.error("No redirect udp socket for established connection");
              client.end();
            }
            return;
          }

          //   console.log(`[TCP] 转发数据到 ${client.remoteAddress}:${client.remotePort}`);
          const tcpSocket = client.data.tcpSocket;
          if (tcpSocket) {
            try {
              tcpSocket.write(data);
            } catch (e) {
              console.error("TCP write error:", e);
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
    close(socket) {
      console.log(`Client closed`);
      if (socket.data.tcpSocket) {
        socket.data.tcpSocket.end();
      }
      if (socket.data.udpSocket) {
        socket.data.udpSocket.close();
      }
    },
    error(_, err) {
      console.error("[err]", err);
    },
    binaryType: "uint8array",
  },
});

console.log(`✅ 纯 Bun SOCKS5 启动 => ${CONFIG.host}:${CONFIG.port}`);
console.log(`🔐 认证：${CONFIG.auth.enabled ? "ON" : "OFF"}`);
