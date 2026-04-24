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
const BIND = 0x02;
const UDP_ASSOCIATE = 0x03;
const IPV4 = 0x01;
const DOMAIN = 0x03;
const IPV6 = 0x04;
const SUCCESS = 0x00;
const ERR_GENERAL = 0x01;
const ERR_CONN_REFUSED = 0x05;
const ERR_CMD_NOT_SUPPORTED = 0x07;

function getStrType(str: string) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(str)) {
    return IPV4;
  } else if (str.includes(":")) {
    return IPV6;
  } else {
    return DOMAIN;
  }
}

function buildAddr(host: string, port: number): Uint8Array {
  const type = getStrType(host);

  if (type === IPV4) {
    const parts = host.split(".").map(Number);
    if (parts.length === 4 && parts.every((n) => Number.isFinite(n))) {
      const [a, b, c, d] = parts as [number, number, number, number];
      const buf = new Uint8Array(7);
      const view = new DataView(buf.buffer);
      buf.set([IPV4, a, b, c, d]);
      view.setUint16(5, port, false);
      return buf;
    }
  }

  if (type === IPV6) {
    const addr = encodeIPv6(host);
    const buf = new Uint8Array(19);
    const view = new DataView(buf.buffer);
    buf.set([IPV6]);
    buf.set(addr, 1);
    view.setUint16(17, port, false);
    return buf;
  }

  const hostBytes = new TextEncoder().encode(host);
  const buf = new Uint8Array(2 + hostBytes.length + 2);
  const view = new DataView(buf.buffer);
  buf.set([DOMAIN, hostBytes.length]);
  buf.set(hostBytes, 2);
  view.setUint16(2 + hostBytes.length, port, false);
  return buf;
}

function encodeIPv6(host: string): Uint8Array {
  const parts = host.split("::");
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
    dataView.setUint16(i * 2, val, false);
  }
  return buf;
}

function compressIPv6(ipv6: string): string {
  // 将连续的多个全零组压缩为 ::
  const parts = ipv6.split(":");
  let bestStart = -1;
  let bestLen = 0;

  // 找到最长的连续零序列（至少2个或更多）
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
    } else {
      if (currentLen >= 2 && currentLen > bestLen) {
        // 只压缩2个或更多连续的零
        bestStart = currentStart;
        bestLen = currentLen;
      }
      currentStart = -1;
      currentLen = 0;
    }
  }

  // 检查末尾的零序列
  if (currentLen >= 2 && currentLen > bestLen) {
    bestStart = currentStart;
    bestLen = currentLen;
  }

  if (bestLen >= 2) {
    const before = parts.slice(0, bestStart);
    const after = parts.slice(bestStart + bestLen);
    return before.join(":") + "::" + after.join(":");
  }

  return ipv6;
}

// 解析目标地址（纯 Bun Buffer）
function parseAddr(data: Uint8Array) {
  const subBuf = new Uint8Array(data.buffer, 3);

  const atyp = subBuf[0];
  let host: string;
  let portOffset = subBuf.byteOffset + 1; // ATYP 位置 + 1 字节

  const dataView = new DataView(data.buffer);

  if (atyp === IPV4) {
    // IPv4 地址需要 4 字节 + 2 字节端口
    if (data.length < portOffset + 4 + 2) {
      throw new Error("Invalid IPv4 address");
    }
    host = `${subBuf[1]}.${subBuf[2]}.${subBuf[3]}.${subBuf[4]}`;
    portOffset += 4;
  } else if (atyp === DOMAIN) {
    const len = subBuf[1];
    // 域名地址需要 1 字节长度 + 域名 + 2 字节端口
    console.warn(
      "Domain address length:",
      len,
      "bytes",
      data.length,
      "bytes total",
      portOffset,
      len,
    );
    if (!len || data.length < portOffset + 1 + len + 2) {
      throw new Error("Invalid domain address");
    }
    portOffset += 1;
    host = new TextDecoder().decode(subBuf.subarray(2, 2 + len));
    portOffset += len;
  } else if (atyp === IPV6) {
    // IPv6 地址需要 16 字节 + 2 字节端口
    if (data.length < portOffset + 16 + 2) {
      throw new Error("Invalid IPv6 address");
    }
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(dataView.getUint16(portOffset + i * 2, false).toString(16));
    }
    host = parts.join(":");
    console.warn("Parsed IPv6 address:", host);
    portOffset += 16;
  } else {
    return null;
  }

  const port = dataView.getUint16(portOffset, false); // big-endian
  return { host, port, offset: portOffset + 2 };
}

/**
 * 尝试解析地址，如果数据不完整返回 null（用于缓冲区）
 */
function tryParseAddr(data: Uint8Array) {
  try {
    return parseAddr(data);
  } catch (e) {
    console.error("Address parsing error (possibly incomplete data):", e);
    return null; // 数据不完整，等待更多数据
  }
}

// 响应包
function reply(code: number, bndAddr?: string, bndPort?: number) {
  let addr: Uint8Array<ArrayBufferLike> = new Uint8Array([IPV4, 0, 0, 0, 0, 0, 0]);
  if (bndAddr && bndPort !== undefined) {
    addr = buildAddr(bndAddr, bndPort);
  }
  const buf = new Uint8Array(4 + addr.length);
  buf.set([VER, code, 0, addr[0] ?? IPV4]);
  buf.set(addr.subarray(1), 4);
  return buf;
}

// ============== 缓冲区管理函数 ==============
/**
 * 向缓冲区追加数据
 */
function appendToBuffer(data: SocketData, newData: Uint8Array): void {
  if (data.bufferLen + newData.length > data.buffer.length) {
    // 缓冲区不够，扩容
    const newBuffer = new Uint8Array(
      Math.max(data.buffer.length * 2, data.bufferLen + newData.length),
    );
    newBuffer.set(data.buffer.subarray(0, data.bufferLen));
    data.buffer = newBuffer;
  }
  data.buffer.set(newData, data.bufferLen);
  data.bufferLen += newData.length;
}

/**
 * 从缓冲区消费数据
 */
function consumeBuffer(data: SocketData, len: number): void {
  if (len >= data.bufferLen) {
    data.bufferLen = 0;
  } else {
    data.buffer.copyWithin(0, len, data.bufferLen);
    data.bufferLen -= len;
  }
}

/**
 * 获取缓冲区中的有效数据
 */
function getBufferData(data: SocketData): Uint8Array {
  return data.buffer.subarray(0, data.bufferLen);
}

class DNSCache {
  #cache: Map<string, { ip: string; expires: number }>;
  #ttl: number;

  constructor(ttl: number = 5 * 60 * 1000) {
    this.#cache = new Map();
    this.#ttl = ttl;
  }

  get(hostname: string): string | null {
    const entry = this.#cache.get(hostname);
    if (entry && entry.expires > Date.now()) {
      return entry.ip;
    }
    this.#cache.delete(hostname);
    return null;
  }

  set(hostname: string, ip: string): void {
    this.#cache.set(hostname, { ip, expires: Date.now() + this.#ttl });
  }
}

// ============== SOCKS5 握手主逻辑 ==============

type SocketData = {
  stage: number;
  isHandshakeDone: boolean;
  tcpSocket?: Bun.TCPSocket;
  udpSocket?: Bun.udp.Socket<"uint8array">;
  socketType?: "tcp" | "udp" | "bind";
  bindServer?: Bun.TCPSocketListener;
  buffer: Uint8Array; // 缓冲区，处理TCP分包
  bufferLen: number; // 当前缓冲区的有效数据长度
  count: number; // 计数器
  dnsCache: DNSCache; // 可选的 DNS 缓存
  udpCache: Map<string, Bun.udp.ConnectedSocket<"uint8array">>; // UDP 关联的客户端地址缓存
};

const consoleLogRed = (msg: string) => {
  console.log(`%c${msg}`, "color: red; font-weight: bold;");
};

Bun.listen<SocketData>({
  hostname: CONFIG.host,
  port: CONFIG.port,
  socket: {
    binaryType: "uint8array",
    async data(localSocket, clientData: Uint8Array) {
      const sockData = localSocket.data;

      let bufferData = clientData;

      if (!sockData.isHandshakeDone) {
        // 追加数据到缓冲区
        appendToBuffer(sockData, clientData);
        bufferData = getBufferData(sockData);
      } else {
        if (sockData.bufferLen > 0) {
          throw new Error("Unexpected buffered data after handshake completion");
        }
        sockData.buffer = clientData;
        sockData.bufferLen = clientData.length;
      }

      // 握手
      if (sockData.stage === 0) {
        // 最少需要 2 字节：[VER, NMETHODS]
        if (bufferData.length < 2) {
          return; // 等待更多数据
        }

        if (bufferData[0] !== VER) {
          console.error("Unsupported SOCKS version:", bufferData[0]);
          localSocket.end();
          return;
        }

        const nmethods = bufferData[1];
        if (!nmethods) {
          console.error("No authentication methods provided");
          localSocket.end();
          return;
        }

        // 需要 2 + nmethods 字节
        if (bufferData.length < 2 + nmethods) {
          return; // 等待更多数据
        }

        const methods = bufferData.subarray(2, 2 + nmethods);
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

        // 消费缓冲区中的数据
        consumeBuffer(sockData, 2 + nmethods);
        sockData.stage = needAuth ? 1 : 2;
        console.log(
          `[TCP] ${localSocket.remoteAddress}:${localSocket.remotePort} 连接成功，认证方式: ${needAuth ? "用户名密码" : "无"}`,
        );
        console.warn(sockData.bufferLen, "bytes remaining in buffer after handshake");
      }

      // 认证
      else if (sockData.stage === 1) {
        // 最少需要 3 字节：[VER, ULEN, ...]
        if (bufferData.length < 2) {
          return;
        }

        const ulen = bufferData[1]!;
        if (!ulen || bufferData.length < 2 + ulen + 1) {
          return; // 等待更多数据（需要用户名长度）
        }

        const plenIndex = 2 + ulen;
        if (plenIndex >= bufferData.length) {
          return; // 等待更多数据
        }

        const plen = bufferData[plenIndex]!;
        // 需要 3 + ulen + plen 字节
        if (bufferData.length < 3 + ulen + plen) {
          return; // 等待更多数据（需要密码）
        }

        const user = new TextDecoder().decode(bufferData.subarray(2, 2 + ulen));
        const pass = new TextDecoder().decode(bufferData.subarray(3 + ulen, 3 + ulen + plen));
        const success = user === CONFIG.auth.username && pass === CONFIG.auth.password;

        localSocket.write(new Uint8Array([1, success ? 0 : 1]));

        if (!success) {
          localSocket.end();
          return;
        }

        consumeBuffer(sockData, 3 + ulen + plen);
        sockData.stage = 2;
      }

      // 请求
      else if (sockData.stage === 2) {
        console.log(`[TCP] 请求数据 ${bufferData.length} bytes`);
        if (!sockData.isHandshakeDone) {
          if (sockData.count === 0) {
            console.warn(bufferData);
          } else {
            console.warn(
              "客户端没有等我这里处理完上一个请求就又发了新数据过来，这个时候我只能先把数据放在缓冲区里，等我处理完上一个请求再来处理这个数据",
            );
            return; // 等待上一个请求处理完
          }

          sockData.count++;

          // 最少需要 4 字节：[VER, CMD, RSV, ATYP]
          if (bufferData.length < 4) {
            console.warn("Not enough data for request header, waiting for more...");
            return; // 等待更多数据
          }

          // 尝试解析地址，如果不完整则返回 null
          const parsed = tryParseAddr(bufferData);
          console.log("Parsed request address:", parsed);
          if (!parsed) {
            console.warn("Failed to parse request address, waiting for more data...");
            return; // 等待更多数据
          }

          const { host, port, offset: addrOffset } = parsed;
          const cmd = bufferData[1];
          console.log("Processing SOCKS5 request...", { cmd });

          if (cmd === CONNECT) {
            consoleLogRed(`[TCP] ${host}:${port} 请求 CONNECT`);
            try {
              const tcpRedirect = await Bun.connect({
                hostname: host,
                port: port,
                socket: {
                  binaryType: "uint8array",
                  open(remote) {
                    console.log(`[TCP] ${host}:${port} 连接建立`);
                  },
                  data(remote, data: Uint8Array) {
                    console.log(`[TCP] 响应数据 ${data.length} bytes`);
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

              console.log(
                `[TCP] ${host}:${port} 连接成功,准备转发数据 BND: port:${tcpRedirect.localPort}`,
              );
              sockData.tcpSocket = tcpRedirect;
              sockData.isHandshakeDone = true;
              sockData.socketType = "tcp";

              // 消费缓冲区中已处理的请求数据
              consumeBuffer(sockData, addrOffset);

              localSocket.write(reply(SUCCESS));

              console.warn(sockData.bufferLen, "bytes remaining in buffer after request");
            } catch (e) {
              console.error("Failed to establish connection:", host, port, e);
              localSocket.write(reply(ERR_CONN_REFUSED));
              localSocket.end();
            }
          } else if (cmd === BIND) {
            consoleLogRed(`[BIND] ${host}:${port} 请求 BIND`);
            try {
              const bindServer = Bun.listen({
                hostname: "::",
                port: 0,
                socket: {
                  binaryType: "uint8array",
                  open(boundSocket) {
                    // 发送第二个回复：连接已建立
                    localSocket.write(
                      reply(SUCCESS, boundSocket.remoteAddress, boundSocket.remotePort),
                    );
                    sockData.tcpSocket = boundSocket;
                    consoleLogRed(`[BIND] 远程连接建立，准备转发数据`);
                  },
                  data(boundSocket, data: Uint8Array) {
                    consoleLogRed(`[BIND] 转发数据 ${data.length} bytes`);
                    console.log("BIND数据：", new TextDecoder().decode(data));
                    localSocket.write(data);
                  },
                  close(boundSocket) {
                    consoleLogRed("BIND remote closed");
                    localSocket.end();
                  },
                  error(boundSocket, err) {
                    console.error("BIND socket error:", err);
                    localSocket.write(reply(ERR_GENERAL));
                    localSocket.end();
                  },
                },
              });

              sockData.bindServer = bindServer;
              sockData.isHandshakeDone = true;
              sockData.socketType = "bind";

              consumeBuffer(sockData, addrOffset);

              // 发送第一个回复：BND.ADDR 和 BND.PORT
              localSocket.write(reply(SUCCESS, bindServer.hostname, bindServer.port));

              console.log(`[BIND] 绑定端口 ${bindServer.hostname}:${bindServer.port} 成功`);
            } catch (e) {
              console.error("BIND error:", e);
              localSocket.write(reply(ERR_GENERAL));
              localSocket.end();
            }
          } else if (cmd === UDP_ASSOCIATE) {
            consoleLogRed(
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

                    const clientKey = `${host}:${port}`;

                    const cachedSocket = sockData.udpCache.get(clientKey);
                    if (cachedSocket) {
                      try {
                        cachedSocket.send(payload);
                        return;
                      } catch (e) {
                        console.error("UDP send error with cached socket:", e);
                        sockData.udpCache.delete(clientKey);
                      }
                    }

                    let finalIp = addr.host;

                    if (getStrType(addr.host) === DOMAIN) {
                      const cachedIp = sockData.dnsCache.get(addr.host);
                      if (cachedIp) {
                        finalIp = cachedIp;
                      } else {
                        // 这里应该实现 DNS 查询逻辑
                        const arr = await Bun.dns.lookup(addr.host);
                        const arr6 = arr.filter((item) => item.family === 6);
                        const arr4 = arr.filter((item) => item.family === 4);

                        const tempUdpClient = await Bun.udpSocket({
                          port: 0,
                          hostname: "::",
                          binaryType: "uint8array",
                          socket: {
                            data(out, res) {
                              console.log(
                                `[UDP Temp Client] 收到数据 ${res.length} bytes 来自 ${addr.host}:${addr.port}`,
                              );
                              out.close();
                            },
                            error(out, err) {
                              console.error("[UDP Temp Client] error:", err);
                              // out.close();
                            },
                          },
                        });

                        let sent = false;

                        for (const { address } of arr6) {
                          try {
                            tempUdpClient.send(payload, addr.port, address);
                            sockData.dnsCache.set(addr.host, address);
                            sent = true;
                            break; // 优先使用 IPv6 地址
                          } catch (e) {
                            console.error("UDP send error for IPv6 address:", address, e);
                          }
                        }
                        if (!sent) {
                          for (const { address } of arr4) {
                            try {
                              tempUdpClient.send(payload, addr.port, address);
                              sockData.dnsCache.set(addr.host, address);
                              sent = true;
                              break;
                            } catch (e) {
                              console.error("UDP send error for IPv4 address:", address, e);
                            }
                          }
                        }
                        tempUdpClient.close();
                        if (!sent) {
                          console.error(
                            `Failed to send UDP packet: no valid IP addresses found for ${addr.host}`,
                          );
                          return;
                        } else {
                          finalIp = sockData.dnsCache.get(addr.host) || addr.host;
                        }
                      }
                    }

                    try {
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

                            try {
                              console.log(
                                `[UDP] 转发响应数据 ${res.length} bytes 到 ${host}:${port}`,
                              );
                              socks5.send(packet, port, host);
                            } catch (e) {
                              console.error("UDP send error to client:", e);
                            }

                            out.close();
                          },
                          error(out, err) {
                            console.error("[UDP Client] send error:", err);
                            out.close();
                          },
                        },
                        connect: {
                          hostname: finalIp,
                          port: addr.port,
                        },
                      });
                      console.log(
                        `[UDP] 转发数据 ${payload.length} bytes 到 ${addr.host}:${addr.port}`,
                      );
                      udpClient.send(payload);
                      sockData.udpCache.set(clientKey, udpClient);
                      console.log(`[UDP] 已缓存 UDP 关联 ${clientKey} => ${finalIp}:${addr.port}`);
                    } catch (e) {
                      console.error(`UDP send to ${finalIp}:${addr.port} error:`, e);
                    }
                  },
                },
              });

              const addrBuf = buildAddr(udpRedirect.address.address, udpRedirect.port);
              const res = new Uint8Array(3 + addrBuf.length);
              res.set([VER, SUCCESS, 0], 0);
              res.set(addrBuf, 3);
              sockData.udpSocket = udpRedirect;
              sockData.isHandshakeDone = true;
              sockData.socketType = "udp";

              consumeBuffer(sockData, addrOffset);
              localSocket.write(res);

              console.log(`[UDP] ${host}:${port} 连接成功,准备转发数据`);
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
          // 握手完成后的数据转发

          if (sockData.socketType === "udp") {
            console.error("Received TCP data on a UDP socket, closing");
            localSocket.end();
            return;
          }

          if (sockData.socketType === "bind" && !sockData.tcpSocket) {
            console.error("Received data on a BIND socket before remote connection, closing");
            localSocket.end();
            return;
          }

          const tcpSocket = sockData.tcpSocket;
          if (tcpSocket) {
            try {
              // 转发缓冲区中的所有数据
              tcpSocket.write(bufferData);
              // 清空缓冲区
              sockData.bufferLen = 0;
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
      socket.data = {
        stage: 0,
        isHandshakeDone: false,
        buffer: new Uint8Array(4096), // 初始缓冲区 4KB
        bufferLen: 0,
        count: 0,
        dnsCache: new DNSCache(), // 初始化 DNS 缓存
        udpCache: new Map(), // 初始化 UDP 关联的客户端地址缓存
      };
      console.log(`Client ${socket.remoteAddress}:${socket.remotePort} connected`);
    },
    close(socket) {
      console.log(`Client closed`);
      if (socket.data.tcpSocket) {
        socket.data.tcpSocket.end();
      }
      if (socket.data.udpSocket) {
        socket.data.udpCache.forEach((udpClient) => udpClient.close());
        socket.data.udpCache.clear();
        socket.data.udpSocket.close();
      }
      if (socket.data.bindServer) {
        socket.data.bindServer.stop();
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
      if (socket.data.bindServer) {
        socket.data.bindServer.stop();
      }
    },
  },
});

console.log(`✅ 纯 Bun SOCKS5 启动 => ${CONFIG.host}:${CONFIG.port}`);
console.log(`🔐 认证：${CONFIG.auth.enabled ? "ON" : "OFF"}`);
