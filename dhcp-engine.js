'use strict';

const dgram = require('dgram');

const DHCP_MAGIC_COOKIE = Buffer.from([99, 130, 83, 99]);

function ipFromBuffer(buf, offset) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

function macFromBuffer(buf, offset, length) {
  return Array.from(buf.subarray(offset, offset + length))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}

function parseOptions(packet) {
  const options = {};
  let offset = 240;

  if (packet.length < offset || !packet.subarray(236, 240).equals(DHCP_MAGIC_COOKIE)) return options;

  while (offset < packet.length) {
    const code = packet[offset++];
    if (code === 0) continue;
    if (code === 255) break;
    if (offset >= packet.length) break;

    const length = packet[offset++];
    if (offset + length > packet.length) break;

    const value = packet.subarray(offset, offset + length);
    offset += length;
    options[code] = value;
  }

  return options;
}

function parseDhcpPacket(packet) {
  if (!Buffer.isBuffer(packet) || packet.length < 240) {
    throw new Error('Invalid DHCP packet: packet is too short');
  }

  const options = parseOptions(packet);
  const messageType = options[53]?.[0] ?? null;
  const requestedIp = options[50] && options[50].length === 4
    ? ipFromBuffer(options[50], 0)
    : null;

  return {
    op: packet[0],
    htype: packet[1],
    hlen: packet[2],
    xid: packet.readUInt32BE(4),
    secs: packet.readUInt16BE(8),
    flags: packet.readUInt16BE(10),
    ciaddr: ipFromBuffer(packet, 12),
    yiaddr: ipFromBuffer(packet, 16),
    giaddr: ipFromBuffer(packet, 24),
    mac: macFromBuffer(packet, 28, Math.min(packet[2], 16)),
    messageType,
    requestedIp,
    options
  };
}

function createDhcpEngine({ port = 6767, host = '0.0.0.0', onPacket } = {}) {
  const socket = dgram.createSocket('udp4');

  socket.on('message', (packet, rinfo) => {
    try {
      const parsed = parseDhcpPacket(packet);
      if (typeof onPacket === 'function') onPacket(parsed, packet, rinfo);
    } catch (error) {
      console.error('[DHCPd-Guard] DHCP packet parse error:', error.message);
    }
  });

  socket.on('error', error => {
    console.error('[DHCPd-Guard] DHCP engine error:', error.message);
  });

  return {
    start() {
      return new Promise((resolve, reject) => {
        const onError = error => {
          socket.off('listening', onListening);
          reject(error);
        };
        const onListening = () => {
          socket.off('error', onError);
          console.log(`[DHCPd-Guard] DHCP engine listening on UDP ${host}:${port}`);
          resolve();
        };
        socket.once('error', onError);
        socket.once('listening', onListening);
        socket.bind(port, host);
      });
    },
    stop() {
      return new Promise(resolve => {
        try { socket.close(resolve); } catch { resolve(); }
      });
    },
    socket
  };
}

module.exports = { DHCP_MAGIC_COOKIE, parseDhcpPacket, createDhcpEngine };
