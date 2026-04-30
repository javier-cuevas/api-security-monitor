/**
 * advanced-usage.js — Redis + MongoDB mode
 *
 * All endpoints return the same JSON shape as basic-usage.js so the
 * Chrome Extension Dashboard works with both modes without any changes.
 *
 * Data sources in advanced mode:
 *   - Active blocks  → Redis (blocked:<ip> keys)
 *   - Full log history → MongoDB (every request is stored)
 */

const express = require('express');
const APIMonitor = require('../src/index');
const mongoSanitize = require('express-mongo-sanitize');
require('dotenv').config();
const cors = require('cors');

const app = express();

app.use(cors());

// Trust one upstream proxy (e.g. nginx, AWS ALB).
// Adjust the value to match your infrastructure:
//   app.set('trust proxy', 1)            → trust one hop
//   app.set('trust proxy', '10.0.0.1')   → trust a specific proxy IP
app.set('trust proxy', 1);

app.use(express.json());

// Strip MongoDB operators ($gt, $ne, etc.) from all incoming data
// to prevent NoSQL injection on query/body/params.
app.use(mongoSanitize());

const { middleware, blockIPs, monitor } = APIMonitor({
  maxRequests:   1000,
  timeWindow:    3600,
  scanThreshold: 20,
  saveRecords:   true,
  mongoURI:      process.env.MONGO_URI,
  redisURL:      process.env.REDIS_URL,
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
 * Recent log entries with optional filters.
 * Supports: ip, attackType, startDate, endDate, limit (max 100).
 * Same shape as basic-usage /logs.
 */
app.get('/logs', async (req, res) => {
  try {
    const { ip, attackType, startDate, endDate } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const query = {};

    if (ip !== undefined) {
      if (typeof ip !== 'string') return res.status(400).json({ error: 'Invalid ip parameter' });
      query.ip = ip;
    }
    if (attackType !== undefined) {
      if (typeof attackType !== 'string') return res.status(400).json({ error: 'Invalid attackType parameter' });
      query.attackType = attackType;
    }
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) {
        const d = new Date(startDate);
        if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid startDate' });
        query.timestamp.$gte = d;
      }
      if (endDate) {
        const d = new Date(endDate);
        if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid endDate' });
        query.timestamp.$lte = d;
      }
    }

    const logs = await monitor.LogModel.find(query)
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean();

    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching logs' });
  }
});

/**
 * GET /logs/attacks
 * Attack-only log entries (attackType != null), most recent first.
 * Supports: limit (max 100).
 * Same shape as basic-usage /logs/attacks.
 */
app.get('/logs/attacks', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const logs = await monitor.LogModel
      .find({ attackType: { $ne: null } })
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean();

    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching attack logs' });
  }
});

/**
 * GET /logs/stats
 * Per-IP statistics: total requests, average response time, attack count, unique routes.
 * Same shape as basic-usage /logs/stats ({ _id, totalRequests, avgResponseTime, attackCount, routes }).
 */
app.get('/logs/stats', async (req, res) => {
  try {
    const stats = await monitor.LogModel.aggregate([
      {
        $group: {
          _id:             '$ip',
          totalRequests:   { $sum: 1 },
          avgResponseTime: { $avg: '$responseTime' },
          attackCount: {
            $sum: { $cond: [{ $ne: ['$attackType', null] }, 1, 0] },
          },
          routes: { $addToSet: '$route' },
        },
      },
      { $sort: { totalRequests: -1 } },
    ]);

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});

/**
 * GET /blocked
 * Currently blocked IPs with remaining TTL, sourced from Redis.
 * Same shape as basic-usage /blocked ({ count, blocked: [{ ip, reason, remainingSec, blockedUntil }] }).
 */
app.get('/blocked', async (req, res) => {
  try {
    const now     = Date.now();
    const blocked = [];
    let cursor    = '0';

    // Scan Redis for blocked:<ip> keys (skip blocked:<ip>:reason keys)
    do {
      const [next, keys] = await monitor.redis.scan(cursor, 'MATCH', 'blocked:*', 'COUNT', 100);
      cursor = next;

      for (const key of keys) {
        if (key.endsWith(':reason')) continue;

        const ttl    = await monitor.redis.ttl(key);
        const reason = await monitor.redis.get(`${key}:reason`);

        if (ttl > 0) {
          blocked.push({
            ip:           key.replace('blocked:', ''),
            reason:       reason || 'Unknown',
            remainingSec: ttl,
            blockedUntil: new Date(now + ttl * 1000).toISOString(),
          });
        }
      }
    } while (cursor !== '0');

    res.json({ count: blocked.length, blocked });
  } catch (err) {
    res.status(500).json({ error: 'Error fetching blocked IPs' });
  }
});

// ---------------------------------------------------------------------------
// Attack event listener
// ---------------------------------------------------------------------------

monitor.on('attack-detected', ({ ip, type, timestamp }) => {
  console.log('Attack detected:', { ip, type, time: new Date(timestamp) });
  // Add custom logic here:
  // - Send notifications (Slack, PagerDuty, etc.)
  // - Forward to an external logging service
  // - Update metrics / dashboards
});

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Advanced server running on port ${PORT}`);
});
