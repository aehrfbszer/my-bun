const textdecoder = new TextDecoder();
Bun.listen({
  hostname: "localhost",
  port: 8080,
  socket: {
    data(socket, data) {
      console.log("Received data from client:", textdecoder.decode(data));
    }, // message received from client
    open(socket) {}, // socket opened
    close(socket, error) {}, // socket closed
    drain(socket) {}, // socket ready for more data
    error(socket, error) {}, // error handler
    binaryType: "arraybuffer",
  },
});

// Create an ArrayBuffer with a size in bytes
const buffer = new ArrayBuffer(16);

// Highest possible BigInt value that fits in an unsigned 64-bit integer
const max = 2n ** 64n - 1n;

const view = new DataView(buffer);
view.setBigUint64(1, max, true);

console.log(view.getBigUint64(1, true), view.getBigUint64(0, true));
