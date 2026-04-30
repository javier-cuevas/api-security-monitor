/**
 * basic-usage.js — Local mode (no Redis, no MongoDB)
 *
 * All endpoints return the same JSON shape as advanced-usage.js so the
 * Chrome Extension Dashboard works with both modes without any changes.
 *
 * Data sources in local mode:
 *   - Active blocks  → monitor.localBlockedIPs (in-memory Map)
 *   - Attack history → NDJSON block log (blockLogPath)
 *
 * Note: method, route, responseTime, statusCode and userAgent are only
 * available in advanced mode (where every request is logged to MongoDB).
 * In local mode those fields are returned as null.
 */

const express = require('express');
const APIMonitor = require('../src/index');
const cors = require('cors');
const fs   = require('fs');
const path = require('path');

const app = express();

app.use(cors());

// Trust one upstream proxy so Express resolves req.ip from X-Forwarded-For
// without allowing client-side IP spoofing.
app.set('trust proxy', 1);

// NDJSON file — one JSON event per line (block / unblock).
// Compatible with jq, grep, tail -f, fail2ban, Filebeat, Logstash, etc.
const BLOCK_LOG = path.join(__dirname, 'blocked-ips.ndjson');

const { middleware, blockIPs, monitor } = APIMonitor({
  maxRequests:     10,
  timeWindow:      60,
  scanThreshold:   5,
  saveRecords:     false,
  blockLogPath:    BLOCK_LOG,
  cleanupInterval: 30_000,    // evict expired in-memory data every 30 s
});

// 1. Reject already-blocked IPs as early as possible
app.use(blockIPs);

// 2. Track requests and detect new attacks
app.use(middleware);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Read and parse all valid lines from the NDJSON block log. */
function readLog() {
  if (!fs.existsSync(BLOCK_LOG)) return [];
  return fs.readFileSync(BLOCK_LOG, 'utf8')
    .split('\n')
    .filter(Boolean)
    .flatMap(line => {
      try { return [JSON.parse(line)]; } catch { return []; }
    });
}

/**
 * Convert an NDJSON block entry to the common log-entry shape.
 * Fields only available in advanced mode are set to null.
 */
function toLogShape(entry) {
  return {
    ip:           entry.ip,
    method:       null,
    route:        null,
    timestamp:    entry.timestamp,
    responseTime: null,
    statusCode:   null,
    userAgent:    null,
    attackType:   entry.action === 'block' ? entry.reason : null,
  };
}

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({ message: 'API working correctly' });
});

app.get('/api/users',    (req, res) => res.json({ users: [] }));
app.get('/api/products', (req, res) => res.json({ products: [] }));

/**
 * GET /logs
 * Recent log entries. Supports query params: ip, attackType, startDate, endDate, limit.
 * Same shape as advanced-usage /logs.
 */
app.get('/logs', (req, res) => {
  try {
    const { ip, attackType, startDate, endDate } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);

    let entries = readLog().filter(e => e.action === 'block');

    if (typeof ip === 'string')
      entries = entries.filter(e => e.ip === ip);
    if (typeof attackType === 'string')
      entries = entries.filter(e => e.reason === attackType);
    if (startDate) {
      const d = new Date(startDate);
      if (isNaN(d)) return res.status(400).json({ error: 'Invalid startDate' });
      entries = entries.filter(e => new Date(e.timestamp) >= d);
    }
    if (endDate) {
      const d = new Date(endDate);
      if (isNaN(d)) return res.status(400).json({ error: 'Invalid endDate' });
      entries = entries.filter(e => new Date(e.timestamp) <= d);
    }

    // Most recent first, capped at limit
    const logs = entries.reverse().slice(0, limit).map(toLogShape);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching logs' });
  }
});

/**
 * GET /logs/attacks
 * Attack-only log entries (same shape as /logs, filtered to attackType != null).
 * Same shape as advanced-usage /logs/attacks.
 */
app.get('/logs/attacks', (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const entries = readLog()
      .filter(e => e.action === 'block')
      .reverse()
      .slice(0, limit)
      .map(toLogShape);

    res.json(entries);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching attack logs' });
  }
});

/**
 * GET /logs/stats
 * Per-IP attack statistics.
 * Same shape as advanced-usage /logs/stats ({ _id, totalRequests, avgResponseTime, attackCount, routes }).
 * totalRequests and avgResponseTime are null in local mode (requests are not individually logged).
 */
app.get('/logs/stats', (req, res) => {
  try {
    const byIP = {};

    for (const entry of readLog().filter(e => e.action === 'block')) {
      if (!byIP[entry.ip]) {
        byIP[entry.ip] = {
          _id:             entry.ip,
          totalRequests:   null,   // not tracked in local mode
          avgResponseTime: null,   // not tracked in local mode
          attackCount:     0,
          routes:          [],     // not tracked in local mode
        };
      }
      byIP[entry.ip].attackCount++;
    }

    const stats = Object.values(byIP).sort((a, b) => b.attackCount - a.attackCount);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

/**
 * GET /blocked
 * Currently blocked IPs with remaining TTL.
 * Same shape as advanced-usage /blocked.
 */
app.get('/blocked', (req, res) => {
  const now     = Date.now();
  const blocked = [];

  for (const [ip, info] of monitor.localBlockedIPs) {
    if (info.expiresAt > now) {
      blocked.push({
        ip,
        reason:       info.reason,
        remainingSec: Math.ceil((info.expiresAt - now) / 1000),
        blockedUntil: new Date(info.expiresAt).toISOString(),
      });
    }
  }

  res.json({ count: blocked.length, blocked });
});

// ---------------------------------------------------------------------------
// Attack event listener
// ---------------------------------------------------------------------------

monitor.on('attack-detected', ({ ip, type, timestamp }) => {
  console.log('Attack detected:', { ip, type, time: new Date(timestamp) });
});

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Basic server running on port ${PORT}`);
  console.log(`Block log: ${BLOCK_LOG}`);
});
