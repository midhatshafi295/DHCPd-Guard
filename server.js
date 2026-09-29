const { createDhcpEngine } = require("./dhcp-engine");
const { ClientStateTracker, STATES } = require("./client-state");
const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3000;
const DHCP_PORT = 6767;
const SUBNET = "192.168.1";

app.use(cors());
app.use(express.json());

// Simple project authentication (local demo credentials).
const AUTH_USER = "admin";
const AUTH_PASS = "admin123";
const sessions = new Set();

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return Object.fromEntries(header.split(";").filter(Boolean).map(part => {
    const i = part.indexOf("=");
    return [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())];
  }));
}

function authRequired(req, res, next) {
  const token = parseCookies(req).dhcpd_session;
  if (token && sessions.has(token)) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Authentication required" });
  return res.redirect("/");
}

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== AUTH_USER || password !== AUTH_PASS) {
    return res.status(401).json({ success: false, error: "Invalid username or password" });
  }
  const token = require("crypto").randomBytes(24).toString("hex");
  sessions.add(token);
  res.setHeader("Set-Cookie", `dhcpd_session=${token}; HttpOnly; SameSite=Lax; Path=/`);
  res.json({ success: true, user: AUTH_USER });
});

app.post("/api/auth/logout", (req, res) => {
  const token = parseCookies(req).dhcpd_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "dhcpd_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ success: true });
});

app.get("/api/auth/me", (req, res) => {
  const token = parseCookies(req).dhcpd_session;
  if (!token || !sessions.has(token)) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: AUTH_USER });
});

app.use("/api", (req, res, next) => {
  if (req.path.startsWith("/auth/")) return next();
  return authRequired(req, res, next);
});

// Dashboard files are kept in the project root.
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/index.html", authRequired, (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.use(express.static(__dirname, { index: false }));

const clientStateTracker = new ClientStateTracker();

let poolRange = { start: 101, end: 150, total: 50 };

let leases = [];

const pendingLeases = new Map();
let nextLeaseId = 1;

let attackStats = { starvation: 0, rogue: 0, other: 0, total: 0 };

let events = [];

const activityData = {
  labels: ["00:00","02:00","04:00","06:00","08:00","10:00","12:00","14:00","16:00","18:00","20:00","22:00","24:00"],
  datasets: [{ label: "DHCP Requests", data: [0,0,0,0,0,0,0,0,0,0,0,0,0] }]
};

let securityRules = [
  { id: 1, name: "Rate Limiting", description: "Limit excessive DHCP DISCOVER requests", status: "Active", icon: "shield" },
  { id: 2, name: "MAC Address Tracking", description: "Track client behaviour using MAC addresses", status: "Active", icon: "search" },
  { id: 3, name: "Starvation Attack Detection", description: "Protect the IP pool from abnormal exhaustion", status: "Active", icon: "alert" },
  { id: 4, name: "Rogue DHCP Detection", description: "Detect unauthorized DHCP responses", status: "Active", icon: "lock" },
  { id: 5, name: "Transaction State Tracking", description: "Track DHCP client transaction behaviour", status: "Active", icon: "check" }
];

let sseClients = [];
let decisionHistory = [];
let decisionId = 1;
const alertedSuspiciousClients = new Set();

function sendSSE(data) {
  sseClients.forEach(client => {
    try { client.res.write(`data: ${JSON.stringify(data)}\n\n`); } catch (_) {}
  });
}

function createEvent(type, title, detail, status) {
  const now = new Date();
  const time = `${String(now.getHours()).padStart(2,"0")}:${String(now.getMinutes()).padStart(2,"0")}`;
  const event = { id: events.length + 1, time, type, title, detail, status };
  events.unshift(event);
  events = events.slice(0, 200);
  return event;
}

function getActiveLeases() {
  return leases.filter(l => l.status === "Active");
}

function getPoolPressure() {
  const usage = poolRange.total ? getActiveLeases().length / poolRange.total : 1;
  return {
    usage,
    percent: Math.round(usage * 100),
    level: usage < 0.60 ? "LOW" : usage < 0.85 ? "MEDIUM" : "HIGH"
  };
}

function getStats() {
  const activeCount = getActiveLeases().length;
  const total = poolRange.total;
  const available = Math.max(0, total - activeCount);
  const pressure = getPoolPressure();
  return {
    totalIpPool: total,
    poolRangeStr: `${poolRange.start} - ${poolRange.end}`,
    activeLeasesCount: activeCount,
    activeLeasesPercent: total ? Math.round((activeCount / total) * 100) : 100,
    availableIpsCount: available,
    availableIpsPercent: total ? Math.round((available / total) * 100) : 0,
    blockedAttacksCount: attackStats.total,
    attacksBreakdown: { ...attackStats },
    poolPressure: pressure.level,
    poolPressurePercent: pressure.percent,
    pendingLeasesCount: pendingLeases.size
  };
}

function allocateAvailableIp() {
  const used = new Set([
    ...getActiveLeases().map(l => l.ip),
    ...Array.from(pendingLeases.values()).map(l => l.ip)
  ]);
  for (let i = poolRange.start; i <= poolRange.end; i++) {
    const ip = `${SUBNET}.${i}`;
    if (!used.has(ip)) return ip;
  }
  return null;
}

function getExistingActive(mac) {
  return leases.find(l => l.status === "Active" && l.mac.toLowerCase() === mac.toLowerCase());
}

function normalizeMac(mac) {
  return String(mac || "").trim().toUpperCase();
}

function validMac(mac) {
  return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac);
}

function decide(mac) {
  const client = clientStateTracker.getClient(mac);
  const pressure = getPoolPressure();
  let decision = "ALLOW";
  if (client.state === STATES.SUSPICIOUS || client.state === STATES.QUARANTINED) decision = "DENY";
  else if (pressure.level === "HIGH" && client.state !== STATES.STABLE) decision = "RESTRICT";
  return { client, pressure, decision };
}

function recordDecision(mac, decision, pressure, source) {
  const client = clientStateTracker.getClient(mac);
  const record = {
    id: decisionId++,
    time: new Date().toISOString(),
    mac,
    state: client.state,
    decision,
    pressure: pressure.level,
    usagePercent: pressure.percent,
    requests: client.requests,
    completedTransactions: client.completedTransactions,
    incompleteTransactions: client.incompleteTransactions,
    source
  };
  decisionHistory.unshift(record);
  decisionHistory = decisionHistory.slice(0, 100);
  return record;
}

function processDiscover(mac, source = "DHCP") {
  const client = clientStateTracker.recordDiscover(mac);

  // First transition to SUSPICIOUS is treated as a starvation/anomaly event.
  if (client.state === STATES.SUSPICIOUS && !alertedSuspiciousClients.has(mac)) {
    alertedSuspiciousClients.add(mac);
    attackStats.starvation += 1;
    attackStats.total += 1;
    createEvent(
      "attack",
      "Possible Starvation Attack Detected",
      `${mac} generated repeated incomplete DHCP transactions and was restricted`,
      "blocked"
    );
  }
  const { pressure, decision } = decide(mac);
  const record = recordDecision(mac, decision, pressure, source);
  let lease = getExistingActive(mac) || null;

  if (decision === "ALLOW") {
    if (!lease) {
      const pending = pendingLeases.get(mac);
      const ip = pending?.ip || allocateAvailableIp();
      if (ip) {
        pendingLeases.set(mac, {
          ip,
          mac,
          deviceType: "Device",
          createdAt: Date.now()
        });
        lease = { ip, mac, pending: true };
      }
    }
  }

  const title = decision === "ALLOW" ? "DHCP Request Allowed" : "DHCP Request Restricted";
  const status = decision === "ALLOW" ? "allowed" : "blocked";
  const detail = decision === "ALLOW"
    ? `State ${client.state} | ${pressure.level} pressure${lease?.ip ? ` | IP ${lease.ip}` : " | Pool exhausted"}`
    : `State ${client.state} | ${pressure.level} pressure | ${decision}`;
  const event = createEvent("request", title, detail, status);

  sendSSE({
    type: "DHCP_DECISION",
    decision: record,
    lease,
    event,
    stats: getStats()
  });

  return { client, pressure, decision, record, lease, event };
}

function processAck(mac, deviceType = "Device") {
  const client = clientStateTracker.recordCompletedTransaction(mac);
  let pending = pendingLeases.get(mac);
  let lease = getExistingActive(mac);
  let event = null;

  if (!lease && pending) {
    lease = {
      id: nextLeaseId++,
      ip: pending.ip,
      mac,
      deviceType,
      leaseTimeLeft: "2h 00m",
      status: "Active"
    };
    leases.unshift(lease);
    pendingLeases.delete(mac);
    event = createEvent("request", "Lease Activated", `DHCP transaction completed - ${lease.ip} assigned to ${mac}`, "allowed");
    sendSSE({ type: "NEW_LEASE", lease, event, stats: getStats() });
  } else if (lease) {
    lease.leaseTimeLeft = "2h 00m";
    event = createEvent("request", "Lease Renewed", `${lease.ip} lease renewed for ${mac}`, "allowed");
    sendSSE({ type: "LEASE_RENEWED", lease, event, stats: getStats() });
  }

  const stateEvent = createEvent("request", "DHCP Transaction Completed", `${mac} -> ${client.state}`, "allowed");
  sendSSE({ type: "CLIENT_STATE_UPDATE", client, event: stateEvent, stats: getStats() });
  return { client, lease, event: event || stateEvent };
}

// ---------------- API ----------------
app.get("/api/stats", (req,res) => res.json(getStats()));
app.get("/api/leases", (req,res) => res.json({ total: leases.length, leases }));
app.get("/api/clients", (req,res) => res.json({ clients: clientStateTracker.getAllClients() }));
app.get("/api/decisions", (req,res) => res.json(decisionHistory));
app.get("/api/events", (req,res) => res.json(events));
app.get("/api/activity", (req,res) => res.json(activityData));
app.get("/api/attacks", (req,res) => res.json(attackStats));
app.get("/api/rules", (req,res) => res.json(securityRules));

app.post("/api/leases", (req,res) => {
  const mac = normalizeMac(req.body.mac);
  if (!validMac(mac)) return res.status(400).json({ error: "Valid MAC address is required" });
  if (getExistingActive(mac)) return res.status(409).json({ error: "MAC already has an active lease" });

  const ip = req.body.ip || allocateAvailableIp();
  if (!ip) return res.status(503).json({ error: "No available IP addresses" });
  const last = Number(ip.split(".").pop());
  if (last < poolRange.start || last > poolRange.end) return res.status(400).json({ error: `IP must be within ${poolRange.start}-${poolRange.end}` });
  if (getActiveLeases().some(l => l.ip === ip) || Array.from(pendingLeases.values()).some(l => l.ip === ip)) return res.status(409).json({ error: "IP address is already allocated" });

  const lease = { id: nextLeaseId++, ip, mac, deviceType: req.body.deviceType || "Device", leaseTimeLeft: req.body.leaseTimeLeft || "2h 00m", status: "Active" };
  leases.unshift(lease);
  const event = createEvent("request", "Manual Lease Allocation", `Allowed - IP ${ip} assigned to ${mac}`, "allowed");
  sendSSE({ type: "NEW_LEASE", lease, event, stats: getStats() });
  res.status(201).json({ success: true, lease, stats: getStats() });
});

app.delete("/api/leases/:id", (req,res) => {
  const id = Number(req.params.id);
  const index = leases.findIndex(l => l.id === id);
  if (index === -1) return res.status(404).json({ error: "Lease not found" });
  const revoked = leases[index];
  leases.splice(index,1);
  const event = createEvent("expired", "Lease Revoked", `IP ${revoked.ip} manually released`, "expired");
  sendSSE({ type: "REVOKE_LEASE", revokedId: id, event, stats: getStats() });
  res.json({ success: true, message: "Lease revoked", stats: getStats() });
});

app.post("/api/leases/:id/renew", (req,res) => {
  const lease = leases.find(l => l.id === Number(req.params.id) && l.status === "Active");
  if (!lease) return res.status(404).json({ error: "Active lease not found" });
  lease.leaseTimeLeft = req.body.duration || "2h 00m";
  const event = createEvent("request", "Lease Renewed", `${lease.ip} renewed for ${lease.mac}`, "allowed");
  sendSSE({ type: "LEASE_RENEWED", lease, event, stats: getStats() });
  res.json({ success: true, lease, stats: getStats() });
});

app.post("/api/actions/pool-range", (req,res) => {
  const start = Number(req.body.start);
  const end = Number(req.body.end);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 2 || end > 254 || start >= end) return res.status(400).json({ error: "Invalid IP range" });

  poolRange = { start, end, total: end - start + 1 };
  const expired = [];
  leases.forEach(l => {
    const last = Number(l.ip.split(".").pop());
    if (l.status === "Active" && (last < start || last > end)) { l.status = "Expired"; expired.push(l); }
  });
  expired.forEach(l => createEvent("expired", "Lease Expired", `${l.ip} removed because it is outside the active pool`, "expired"));
  const stats = getStats();
  sendSSE({ type: "STATS_UPDATE", stats });
  res.json({ success: true, poolRange, stats });
});

app.post("/api/actions/simulate-attack", (req,res) => {
  const type = req.body.attackType || "starvation";
  let event;
  if (type === "starvation") {
    attackStats.starvation++; attackStats.total++;
    event = createEvent("attack", "Possible Starvation Attack Detected", "Abnormal DHCP request behaviour blocked", "blocked");
  } else if (type === "rogue") {
    attackStats.rogue++; attackStats.total++;
    event = createEvent("attack", "Rogue DHCP Server Detected", "Unauthorized DHCP response blocked", "blocked");
  } else {
    attackStats.other++; attackStats.total++;
    event = createEvent("attack", "Anomalous DHCP Packet Sequence", "Malformed packet sequence dropped", "blocked");
  }
  sendSSE({ type: "ATTACK_BLOCKED", event, stats: getStats(), attacks: attackStats });
  res.json({ success: true, event, stats: getStats(), attacks: attackStats });
});

// Dashboard-only lab transaction: no terminal commands required.
app.post("/api/actions/lab-client", (req,res) => {
  const mac = normalizeMac(req.body.mac);
  const mode = req.body.mode || "transaction";
  const deviceType = req.body.deviceType || "Laptop";
  if (!validMac(mac)) return res.status(400).json({ error: "Enter a valid MAC like AA:BB:CC:DD:EE:01" });

  const discover = processDiscover(mac, "Dashboard Lab");
  let ack = null;
  if (mode === "transaction" && discover.decision === "ALLOW") ack = processAck(mac, deviceType);

  res.json({ success: true, discover, ack, stats: getStats() });
});

app.post("/api/actions/restart", (req,res) => {
  const event = createEvent("system", "DHCPd Daemon Restarted", "Core service state reloaded successfully", "system");
  sendSSE({ type: "SERVER_RESTARTED", event, stats: getStats() });
  res.json({ success: true, message: "Server state reloaded", timestamp: new Date().toISOString() });
});

app.post("/api/rules/:id", (req,res) => {
  const rule = securityRules.find(r => r.id === Number(req.params.id));
  if (!rule) return res.status(404).json({ error: "Rule not found" });
  rule.status = req.body.enabled ? "Active" : "Disabled";
  const event = createEvent("system", "Security Rule Updated", `${rule.name}: ${rule.status}`, "system");
  sendSSE({ type: "RULE_UPDATED", rule, event, stats: getStats() });
  res.json({ success: true, rule });
});

app.get("/api/events/live", (req,res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  const client = { id: Date.now() + Math.random(), res };
  sseClients.push(client);
  res.write(`data: ${JSON.stringify({ type: "CONNECTED", message: "Live event stream active", stats: getStats() })}\n\n`);
  req.on("close", () => { sseClients = sseClients.filter(c => c.id !== client.id); });
});

// ---------------- DHCP packet engine ----------------
const dhcpEngine = createDhcpEngine({
  port: DHCP_PORT,
  host: "0.0.0.0",
  onPacket: (packet, rawPacket, remote) => {
    const messageType = packet.messageType;
    const names = { 1:"DHCPDISCOVER",2:"DHCPOFFER",3:"DHCPREQUEST",4:"DHCPDECLINE",5:"DHCPACK",6:"DHCPNAK",7:"DHCPRELEASE",8:"DHCPINFORM" };
    console.log(`\n[DHCP] ${names[messageType] || "UNKNOWN"} | ${packet.mac} | ${remote.address}:${remote.port}`);

    if (!packet.mac) return;

    if (messageType === 1) {
      const result = processDiscover(packet.mac, "DHCP Packet");
      console.log(`[STATE] ${result.client.state} | [POOL] ${result.pressure.percent}% ${result.pressure.level} | [DECISION] ${result.decision}`);
    }

    if (messageType === 5) {
      const result = processAck(packet.mac);
      console.log(`[STATE] ${result.client.state} | [LEASE] ${result.lease?.ip || "none"}`);
    }
  }
});

dhcpEngine.start().catch(error => {
  console.error("[DHCPd-Guard] DHCP engine failed to start:", error.message);
});

app.listen(PORT, () => {
  console.log("=========================================");
  console.log(` DHCPd-Guard Server running on port ${PORT}`);
  console.log(` Open: http://localhost:${PORT}`);
  console.log(" Login: admin / admin123");
  console.log(` DHCP Engine listening on UDP port ${DHCP_PORT}`);
  console.log(" Dashboard lab controls enabled");
  console.log("=========================================");
});
