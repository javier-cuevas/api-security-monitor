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
 */
app.get('/logs', async (req, res) => {
  try {
    const { ip, attackType, startDate, endDate } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);

    if (startDate && isNaN(new Date(startDate))) return res.status(400).json({ error: 'Invalid startDate' });
    if (endDate   && isNaN(new Date(endDate)))   return res.status(400).json({ error: 'Invalid endDate' });

    const logs = await monitor.getLogs({ ip, attackType, startDate, endDate, limit });
    res.json(logs);
  } catch {
    res.status(500).json({ error: 'Error fetching logs' });
  }
});

/**
 * GET /logs/attacks
 * Attack-only log entries (attackType != null), most recent first.
 */
app.get('/logs/attacks', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const logs = await monitor.getAttackLogs({ limit });
    res.json(logs);
  } catch {
    res.status(500).json({ error: 'Error fetching attack logs' });
  }
});

/**
 * GET /logs/stats
 * Per-IP attack statistics.
 */
app.get('/logs/stats', async (req, res) => {
  try {
    const stats = await monitor.getStats();
    res.json(stats);
  } catch {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

/**
 * GET /blocked
 * Currently blocked IPs with remaining TTL.
 */
app.get('/blocked', async (req, res) => {
  try {
    const result = await monitor.getBlockedIPs();
    res.json(result);
  } catch {
    res.status(500).json({ error: 'Error fetching blocked IPs' });
  }
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
