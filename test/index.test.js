/**
 * api-security-monitor — test suite
 *
 * All tests run in local mode (saveRecords: false) unless explicitly noted,
 * so no real Redis or MongoDB connection is required.
 */

const APIMonitor = require('../src/index');
const express = require('express');
const request = require('supertest');

// Replace ioredis with an in-memory mock so Redis-mode tests work without a server
jest.mock('ioredis', () => require('ioredis-mock'));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a fresh Express app wired up with the monitor.
 * All three objects (middleware, blockIPs, monitor) share the same instance.
 *
 * trust proxy is set to `true` so Express populates req.ip from the
 * X-Forwarded-For header that supertest sets in each test request.
 */
function buildApp(options = {}) {
  const app = express();
  app.set('trust proxy', true); // allow supertest to control req.ip via x-forwarded-for
  const result = APIMonitor(options);
  app.use(result.blockIPs);   // reject blocked IPs early
  app.use(result.middleware); // track and detect
  app.get('*', (_req, res) => res.sendStatus(200));
  return { app, ...result };
}

// ---------------------------------------------------------------------------
// 1. Rate limiting (local mode)
// ---------------------------------------------------------------------------

describe('Rate Limiting', () => {
  it('blocks an IP once it exceeds maxRequests', async () => {
    // With maxRequests:3, count must reach 4 to trigger a block.
    // The request that triggers the block still gets 200; the NEXT one gets 403.
    const { app } = buildApp({ maxRequests: 3, timeWindow: 60 });
    const agent = request(app);

    // maxRequests + 1 requests — the last one triggers the block (still 200)
    for (let i = 0; i <= 3; i++) {
      await agent.get('/').set('x-forwarded-for', '1.1.1.1');
    }

    const res = await agent.get('/').set('x-forwarded-for', '1.1.1.1');
    expect(res.status).toBe(403);
  });

  it('does not block while under the limit', async () => {
    const { app } = buildApp({ maxRequests: 5, timeWindow: 60 });
    const agent = request(app);

    for (let i = 0; i < 5; i++) {
      const res = await agent.get('/').set('x-forwarded-for', '2.2.2.2');
      expect(res.status).toBe(200);
    }
  });

  it('tracks different IPs independently', async () => {
    const { app } = buildApp({ maxRequests: 2, timeWindow: 60 });
    const agent = request(app);

    // Push IP A to the limit trigger (3 requests, 3rd triggers block)
    await agent.get('/').set('x-forwarded-for', '3.3.3.3');
    await agent.get('/').set('x-forwarded-for', '3.3.3.3');
    await agent.get('/').set('x-forwarded-for', '3.3.3.3'); // triggers block for 3.3.3.3

    // IP B must still be free
    const resB = await agent.get('/').set('x-forwarded-for', '4.4.4.4');
    expect(resB.status).toBe(200);

    // IP A is now blocked
    const resA = await agent.get('/').set('x-forwarded-for', '3.3.3.3');
    expect(resA.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// 2. Path scanning detection (local mode)
// ---------------------------------------------------------------------------

describe('Path Scanning Detection', () => {
  it('blocks an IP after exceeding scanThreshold unique routes', async () => {
    // scanThreshold:3 → block triggers when scanCount reaches 4
    const { app } = buildApp({ scanThreshold: 3, maxRequests: 100 });
    const agent = request(app);

    // 4 unique routes — 4th triggers the block (still 200)
    for (const path of ['/a', '/b', '/c', '/d']) {
      await agent.get(path).set('x-forwarded-for', '5.5.5.5');
    }

    const res = await agent.get('/e').set('x-forwarded-for', '5.5.5.5');
    expect(res.status).toBe(403);
  });

  it('does not block when unique routes stay within threshold', async () => {
    const { app } = buildApp({ scanThreshold: 5, maxRequests: 100 });
    const agent = request(app);

    for (const path of ['/x', '/y', '/z']) {
      const res = await agent.get(path).set('x-forwarded-for', '6.6.6.6');
      expect(res.status).toBe(200);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Shared state: factory blockIPs sees blocks set by monitor
// ---------------------------------------------------------------------------

describe('Shared Instance State', () => {
  it('blockIPs (from factory) rejects an IP blocked by the monitor', async () => {
    const { app } = buildApp({ maxRequests: 2, timeWindow: 60 });
    const agent = request(app);

    // 3 requests — 3rd triggers block in the shared monitor
    await agent.get('/').set('x-forwarded-for', '7.7.7.7');
    await agent.get('/').set('x-forwarded-for', '7.7.7.7');
    await agent.get('/').set('x-forwarded-for', '7.7.7.7'); // triggers block (200)

    // Next request hits the shared blockIPs middleware → 403
    const res = await agent.get('/').set('x-forwarded-for', '7.7.7.7');
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// 4. 403 response body shape
// ---------------------------------------------------------------------------

describe('403 Response Body', () => {
  it('contains the required fields', async () => {
    const { app } = buildApp({ maxRequests: 1, timeWindow: 60 });
    const agent = request(app);

    // Trigger block (2 requests to exceed limit of 1)
    await agent.get('/').set('x-forwarded-for', '8.8.8.8');
    await agent.get('/').set('x-forwarded-for', '8.8.8.8'); // triggers block (200)

    const res = await agent.get('/').set('x-forwarded-for', '8.8.8.8');
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({
      error: expect.any(String),
      reason: expect.any(String),
      blockedFor: expect.stringContaining('seconds'),
      blockedUntil: expect.any(String),
    });
  });

  it('blockedUntil is a valid ISO date in the future', async () => {
    const { app } = buildApp({ maxRequests: 1, timeWindow: 60 });
    const agent = request(app);

    await agent.get('/').set('x-forwarded-for', '8.8.8.9');
    await agent.get('/').set('x-forwarded-for', '8.8.8.9');
    const res = await agent.get('/').set('x-forwarded-for', '8.8.8.9');

    const until = new Date(res.body.blockedUntil).getTime();
    expect(until).toBeGreaterThan(Date.now());
  });
});

// ---------------------------------------------------------------------------
// 5. Block expiry (local mode)
// ---------------------------------------------------------------------------

describe('Block Expiry', () => {
  it('unblocks an IP once the TTL has elapsed', async () => {
    const { app, monitor } = buildApp({ maxRequests: 1, timeWindow: 60 });
    const agent = request(app);

    // Trigger block
    await agent.get('/').set('x-forwarded-for', '9.9.9.9');
    await agent.get('/').set('x-forwarded-for', '9.9.9.9'); // triggers block

    // Verify it's blocked
    const blocked = await agent.get('/').set('x-forwarded-for', '9.9.9.9');
    expect(blocked.status).toBe(403);

    // Expire the block manually
    const record = monitor.localBlockedIPs.get('9.9.9.9');
    record.expiresAt = Date.now() - 1;

    // Should be allowed again
    const unblocked = await agent.get('/').set('x-forwarded-for', '9.9.9.9');
    expect(unblocked.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 6. Event emission
// ---------------------------------------------------------------------------

describe('Event Emission', () => {
  it('emits "attack-detected" on a rate-limit breach', async () => {
    const { app, monitor } = buildApp({ maxRequests: 2, timeWindow: 60 });
    const spy = jest.fn();
    monitor.on('attack-detected', spy);
    const agent = request(app);

    await agent.get('/').set('x-forwarded-for', '10.0.0.1');
    await agent.get('/').set('x-forwarded-for', '10.0.0.1');
    await agent.get('/').set('x-forwarded-for', '10.0.0.1'); // triggers event

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        ip: '10.0.0.1',
        type: 'DDoS (Excessive Requests)',
        timestamp: expect.any(Date),
      })
    );
  });

  it('emits "attack-detected" on a path-scan breach', async () => {
    const { app, monitor } = buildApp({ scanThreshold: 2, maxRequests: 100 });
    const spy = jest.fn();
    monitor.on('attack-detected', spy);
    const agent = request(app);

    for (const path of ['/p1', '/p2', '/p3']) {
      await agent.get(path).set('x-forwarded-for', '10.0.0.2');
    }

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        ip: '10.0.0.2',
        type: 'Path Scanning',
        timestamp: expect.any(Date),
      })
    );
  });

  it('emits exactly once per attack (not on every subsequent blocked request)', async () => {
    const { app, monitor } = buildApp({ maxRequests: 1, timeWindow: 60 });
    const spy = jest.fn();
    monitor.on('attack-detected', spy);
    const agent = request(app);

    // Request that triggers the block
    await agent.get('/').set('x-forwarded-for', '10.0.0.3');
    await agent.get('/').set('x-forwarded-for', '10.0.0.3'); // triggers event

    // Subsequent blocked requests should NOT re-emit the event
    await agent.get('/').set('x-forwarded-for', '10.0.0.3');
    await agent.get('/').set('x-forwarded-for', '10.0.0.3');

    expect(spy).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 7. IP resolution
// ---------------------------------------------------------------------------

describe('IP Resolution (getClientIP)', () => {
  // getClientIP now relies on req.ip (set by Express based on trust proxy)
  // instead of manually parsing headers — preventing IP spoofing.
  let monitor;

  beforeEach(() => {
    ({ monitor } = APIMonitor({}));
  });

  function makeReq(ip = '1.2.3.4') {
    return {
      headers: {},
      socket: { remoteAddress: ip },
      ip,
    };
  }

  it('uses req.ip as the primary source', () => {
    expect(monitor.getClientIP(makeReq('5.5.5.5'))).toBe('5.5.5.5');
  });

  it('falls back to socket.remoteAddress when req.ip is absent', () => {
    const req = { headers: {}, socket: { remoteAddress: '7.7.7.7' }, ip: undefined };
    expect(monitor.getClientIP(req)).toBe('7.7.7.7');
  });

  it('returns 0.0.0.0 when no IP source is available', () => {
    const req = { headers: {}, socket: { remoteAddress: undefined }, ip: undefined };
    expect(monitor.getClientIP(req)).toBe('0.0.0.0');
  });

  it('normalises ::1 → 127.0.0.1', () => {
    expect(monitor.getClientIP(makeReq('::1'))).toBe('127.0.0.1');
  });

  it('normalises ::ffff:127.0.0.1 → 127.0.0.1', () => {
    expect(monitor.getClientIP(makeReq('::ffff:127.0.0.1'))).toBe('127.0.0.1');
  });

  it('strips ::ffff: prefix from other IPv4-mapped IPv6 addresses', () => {
    expect(monitor.getClientIP(makeReq('::ffff:192.168.1.100'))).toBe('192.168.1.100');
  });
});

// ---------------------------------------------------------------------------
// 8. Configuration
// ---------------------------------------------------------------------------

describe('Configuration', () => {
  it('applies default values', () => {
    const { monitor } = APIMonitor({});
    expect(monitor.maxRequests).toBe(10);
    expect(monitor.timeWindow).toBe(60);
    expect(monitor.scanThreshold).toBe(5);
    expect(monitor.saveRecords).toBe(false);
  });

  it('accepts custom values', () => {
    const { monitor } = APIMonitor({ maxRequests: 100, timeWindow: 3600, scanThreshold: 20 });
    expect(monitor.maxRequests).toBe(100);
    expect(monitor.timeWindow).toBe(3600);
    expect(monitor.scanThreshold).toBe(20);
  });

  it('throws when saveRecords:true but mongoURI is missing', () => {
    expect(() =>
      APIMonitor({ saveRecords: true, redisURL: 'redis://localhost' })
    ).toThrow('mongoURI and redisURL are required');
  });

  it('throws when saveRecords:true but redisURL is missing', () => {
    expect(() =>
      APIMonitor({ saveRecords: true, mongoURI: 'mongodb://localhost/test' })
    ).toThrow('mongoURI and redisURL are required');
  });

  it('initialises local data structures in local mode', () => {
    const { monitor } = APIMonitor({});
    expect(monitor.localRequestCounts).toBeInstanceOf(Map);
    expect(monitor.localRouteScans).toBeInstanceOf(Map);
    expect(monitor.localBlockedIPs).toBeInstanceOf(Map);
  });
});

// ---------------------------------------------------------------------------
// 9. Standalone APIMonitor.blockIPs factory
// ---------------------------------------------------------------------------

describe('APIMonitor.blockIPs (standalone factory)', () => {
  it('returns a working Express middleware', async () => {
    const mw = APIMonitor.blockIPs({});
    expect(typeof mw).toBe('function');
    expect(mw.length).toBe(3); // (req, res, next)
  });

  it('passes unblocked IPs through', async () => {
    const app = express();
    app.use(APIMonitor.blockIPs({}));
    app.get('*', (_req, res) => res.sendStatus(200));

    const res = await request(app).get('/').set('x-forwarded-for', '20.20.20.20');
    expect(res.status).toBe(200);
  });

  it('has its own independent state — does NOT see blocks from a factory instance', async () => {
    // Block an IP inside a factory monitor
    const { monitor } = APIMonitor({ maxRequests: 2 });
    monitor.localBlockedIPs.set('127.0.0.1', {
      expiresAt: Date.now() + 300_000,
      reason: 'Test block',
    });

    // Standalone instance knows nothing about the above block
    const app = express();
    app.use(APIMonitor.blockIPs({}));
    app.get('*', (_req, res) => res.sendStatus(200));

    // req.ip will be 127.0.0.1 (loopback) — standalone doesn't have it blocked
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 10. Route scan time-window reset
// ---------------------------------------------------------------------------

describe('Route Scan — time-window reset', () => {
  it('does not count routes from an expired window toward the new window', () => {
    const { monitor } = APIMonitor({ timeWindow: 1, scanThreshold: 100, maxRequests: 100 });

    // Simulate stale activity: timestamps older than the 1-second window
    monitor.localRequestCounts.set('50.50.50.50', [Date.now() - 2000]);
    monitor.localRouteScans.set('50.50.50.50', new Set(['/old-a', '/old-b', '/old-c']));

    // New request arrives — window has expired, so routes should reset
    const { scanCount } = monitor.updateLocalTracking('50.50.50.50', '/new-route');
    expect(scanCount).toBe(1); // only /new-route, old routes discarded
  });

  it('accumulates routes within an active window', () => {
    const { monitor } = APIMonitor({ timeWindow: 60, scanThreshold: 100, maxRequests: 100 });

    monitor.updateLocalTracking('51.51.51.51', '/a');
    monitor.updateLocalTracking('51.51.51.51', '/b');
    const { scanCount } = monitor.updateLocalTracking('51.51.51.51', '/c');
    expect(scanCount).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// 11. Cleanup timer
// ---------------------------------------------------------------------------

describe('Cleanup Timer', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('evicts expired blocked IPs when the timer fires', () => {
    const { monitor } = APIMonitor({ cleanupInterval: 1000 });

    monitor.localBlockedIPs.set('60.60.60.60', {
      expiresAt: Date.now() - 1, // already expired
      reason: 'DDoS (Excessive Requests)',
    });

    expect(monitor.localBlockedIPs.has('60.60.60.60')).toBe(true);
    jest.advanceTimersByTime(1000);
    expect(monitor.localBlockedIPs.has('60.60.60.60')).toBe(false);
  });

  it('evicts stale tracking data for inactive IPs', () => {
    const { monitor } = APIMonitor({ cleanupInterval: 1000, timeWindow: 1 });

    // Timestamps older than the 1-second window
    monitor.localRequestCounts.set('61.61.61.61', [Date.now() - 2000]);
    monitor.localRouteScans.set('61.61.61.61', new Set(['/stale']));

    jest.advanceTimersByTime(1000);

    expect(monitor.localRequestCounts.has('61.61.61.61')).toBe(false);
    expect(monitor.localRouteScans.has('61.61.61.61')).toBe(false);
  });

  it('keeps active IPs in tracking data after cleanup', () => {
    const { monitor } = APIMonitor({ cleanupInterval: 1000, timeWindow: 60 });

    monitor.localRequestCounts.set('62.62.62.62', [Date.now()]); // fresh timestamp
    monitor.localRouteScans.set('62.62.62.62', new Set(['/active']));

    jest.advanceTimersByTime(1000);

    expect(monitor.localRequestCounts.has('62.62.62.62')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 12. NDJSON block log persistence
// ---------------------------------------------------------------------------

describe('NDJSON Block Log Persistence', () => {
  const os   = require('os');
  const path = require('path');
  const fs   = require('fs');

  function tmpLog() {
    return path.join(os.tmpdir(), `api-monitor-test-${Date.now()}.ndjson`);
  }

  afterEach(() => {
    // Clean up any temp files created during tests
    const files = fs.readdirSync(os.tmpdir()).filter(f => f.startsWith('api-monitor-test-'));
    for (const f of files) {
      try { fs.unlinkSync(path.join(os.tmpdir(), f)); } catch {}
    }
  });

  it('restores non-expired blocks from the log on startup', () => {
    const logPath   = tmpLog();
    const expiresAt = Date.now() + 300_000;
    fs.writeFileSync(
      logPath,
      JSON.stringify({ action: 'block', ip: '70.70.70.70', reason: 'DDoS (Excessive Requests)', expiresAt }) + '\n'
    );

    const { monitor } = APIMonitor({ blockLogPath: logPath });
    expect(monitor.localBlockedIPs.has('70.70.70.70')).toBe(true);
    expect(monitor.localBlockedIPs.get('70.70.70.70').reason).toBe('DDoS (Excessive Requests)');
  });

  it('ignores blocks that are already expired in the log', () => {
    const logPath   = tmpLog();
    const expiresAt = Date.now() - 1; // expired
    fs.writeFileSync(
      logPath,
      JSON.stringify({ action: 'block', ip: '71.71.71.71', reason: 'Path Scanning', expiresAt }) + '\n'
    );

    const { monitor } = APIMonitor({ blockLogPath: logPath });
    expect(monitor.localBlockedIPs.has('71.71.71.71')).toBe(false);
  });

  it('skips malformed lines without crashing', () => {
    const logPath = tmpLog();
    fs.writeFileSync(logPath, 'not-json\n{"action":"block","ip":"72.72.72.72","reason":"test","expiresAt":' + (Date.now() + 300_000) + '}\n');

    expect(() => APIMonitor({ blockLogPath: logPath })).not.toThrow();
    const { monitor } = APIMonitor({ blockLogPath: logPath });
    expect(monitor.localBlockedIPs.has('72.72.72.72')).toBe(true);
  });

  it('works fine when the log file does not exist yet', () => {
    const logPath = tmpLog(); // file does not exist
    expect(() => APIMonitor({ blockLogPath: logPath })).not.toThrow();
  });

  it('appends a block entry when an IP is blocked', async () => {
    const logPath = tmpLog();
    const { app } = buildApp({ maxRequests: 1, blockLogPath: logPath });
    const agent   = request(app);

    await agent.get('/').set('x-forwarded-for', '73.73.73.73');
    await agent.get('/').set('x-forwarded-for', '73.73.73.73'); // triggers block

    // Allow async appendFile to flush
    await new Promise(r => setTimeout(r, 50));

    const entries    = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    const blockEntry = entries.find(e => e.action === 'block');
    expect(blockEntry).toBeDefined();
    expect(blockEntry.ip).toBe('73.73.73.73');
    expect(blockEntry.reason).toBe('DDoS (Excessive Requests)');
    expect(typeof blockEntry.expiresAt).toBe('number');
    expect(typeof blockEntry.timestamp).toBe('string');
  });

  it('appends an unblock entry when TTL expires (lazy eviction)', async () => {
    const logPath   = tmpLog();
    const { monitor } = APIMonitor({ blockLogPath: logPath });

    // Manually insert an already-expired block
    monitor.localBlockedIPs.set('74.74.74.74', {
      expiresAt: Date.now() - 1,
      reason:    'DDoS (Excessive Requests)',
    });

    // isIPBlocked triggers lazy eviction and writes the unblock entry
    await monitor.isIPBlocked('74.74.74.74');
    await new Promise(r => setTimeout(r, 50));

    const entries      = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    const unblockEntry = entries.find(e => e.action === 'unblock');
    expect(unblockEntry).toBeDefined();
    expect(unblockEntry.ip).toBe('74.74.74.74');
    expect(unblockEntry.reason).toBe('ttl_expired');
  });

  it('cleanup timer writes unblock entries for expired IPs', async () => {
    jest.useFakeTimers();

    const logPath     = tmpLog();
    const { monitor } = APIMonitor({ blockLogPath: logPath, cleanupInterval: 500 });

    monitor.localBlockedIPs.set('75.75.75.75', {
      expiresAt: Date.now() - 1,
      reason:    'Path Scanning',
    });

    jest.advanceTimersByTime(500);
    jest.useRealTimers();

    await new Promise(r => setTimeout(r, 50));

    const entries      = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    const unblockEntry = entries.find(e => e.action === 'unblock' && e.ip === '75.75.75.75');
    expect(unblockEntry).toBeDefined();
  });

  it('full restart cycle: block survives restart, is gone after TTL', async () => {
    const logPath = tmpLog();

    // --- First process: trigger a block ---
    const { app: app1 } = buildApp({ maxRequests: 1, blockLogPath: logPath });
    const agent1        = request(app1);

    await agent1.get('/').set('x-forwarded-for', '76.76.76.76');
    await agent1.get('/').set('x-forwarded-for', '76.76.76.76'); // triggers block
    await new Promise(r => setTimeout(r, 50));

    // Verify block was written
    const entries = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
    expect(entries.find(e => e.action === 'block' && e.ip === '76.76.76.76')).toBeDefined();

    // --- Second process: new instance reads the log and restores the block ---
    const { monitor: monitor2 } = APIMonitor({ blockLogPath: logPath });
    expect(monitor2.localBlockedIPs.has('76.76.76.76')).toBe(true);

    // --- Simulate TTL expiry ---
    const record = monitor2.localBlockedIPs.get('76.76.76.76');
    record.expiresAt = Date.now() - 1;

    const stillBlocked = await monitor2.isIPBlocked('76.76.76.76');
    expect(stillBlocked).toBe(false);
    expect(monitor2.localBlockedIPs.has('76.76.76.76')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 13. Dashboard endpoints — local mode
// ---------------------------------------------------------------------------

/**
 * These tests verify the common API contract that both basic-usage.js and
 * advanced-usage.js expose, so the Chrome Extension Dashboard works with
 * both modes without changes.
 *
 * Endpoints under test:
 *   GET /logs          → array of log-shaped entries
 *   GET /logs/attacks  → same shape, attack entries only
 *   GET /logs/stats    → per-IP stats array
 *   GET /blocked       → { count, blocked: [...] }
 */
describe('Dashboard Endpoints — local mode', () => {
  const os   = require('os');
  const path = require('path');
  const fs   = require('fs');

  // Mirrors the helpers in basic-usage.js exactly
  function readLog(logPath) {
    if (!fs.existsSync(logPath)) return [];
    return fs.readFileSync(logPath, 'utf8')
      .split('\n').filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
  }

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

  // Builds a complete Express app with all dashboard endpoints mounted
  function buildDashboardApp(logPath, monitorOptions = {}) {
    const result  = APIMonitor({ maxRequests: 1, blockLogPath: logPath, ...monitorOptions });
    const { middleware, blockIPs, monitor } = result;

    const app = express();
    app.set('trust proxy', true);
    app.use(blockIPs);
    app.use(middleware);

    app.get('/logs', (req, res) => {
      try {
        const { ip, attackType, startDate, endDate } = req.query;
        const limit = Math.min(parseInt(req.query.limit) || 10, 100);
        let entries = readLog(logPath).filter(e => e.action === 'block');
        if (typeof ip === 'string')
          entries = entries.filter(e => e.ip === ip);
        if (typeof attackType === 'string')
          entries = entries.filter(e => e.reason === attackType);
        if (startDate) {
          const d = new Date(startDate);
          if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid startDate' });
          entries = entries.filter(e => new Date(e.timestamp) >= d);
        }
        if (endDate) {
          const d = new Date(endDate);
          if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid endDate' });
          entries = entries.filter(e => new Date(e.timestamp) <= d);
        }
        res.json(entries.reverse().slice(0, limit).map(toLogShape));
      } catch { res.status(500).json({ error: 'Error fetching logs' }); }
    });

    app.get('/logs/attacks', (req, res) => {
      try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        res.json(
          readLog(logPath).filter(e => e.action === 'block').reverse().slice(0, limit).map(toLogShape)
        );
      } catch { res.status(500).json({ error: 'Error fetching attack logs' }); }
    });

    app.get('/logs/stats', (req, res) => {
      try {
        const byIP = {};
        for (const e of readLog(logPath).filter(e => e.action === 'block')) {
          if (!byIP[e.ip]) byIP[e.ip] = { _id: e.ip, totalRequests: null, avgResponseTime: null, attackCount: 0, routes: [] };
          byIP[e.ip].attackCount++;
        }
        res.json(Object.values(byIP).sort((a, b) => b.attackCount - a.attackCount));
      } catch { res.status(500).json({ error: 'Error fetching stats' }); }
    });

    app.get('/blocked', (req, res) => {
      const now = Date.now();
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

    app.get('*', (_req, res) => res.sendStatus(200));
    return { app, monitor, ...result };
  }

  let logPath, agent, monitor;

  beforeEach(async () => {
    logPath = path.join(os.tmpdir(), `ep-test-${Date.now()}.ndjson`);
    const { app, monitor: m } = buildDashboardApp(logPath);
    monitor = m;
    agent   = request(app);

    // Trigger blocks from two different IPs (maxRequests:1 → 2 requests = block)
    await agent.get('/').set('x-forwarded-for', '100.0.0.1');
    await agent.get('/').set('x-forwarded-for', '100.0.0.1'); // block 100.0.0.1
    await agent.get('/').set('x-forwarded-for', '100.0.0.2');
    await agent.get('/').set('x-forwarded-for', '100.0.0.2'); // block 100.0.0.2

    await new Promise(r => setTimeout(r, 60)); // wait for async appendFile
  });

  afterEach(() => { try { fs.unlinkSync(logPath); } catch {} });

  // --- GET /logs ---

  it('GET /logs returns an array', async () => {
    const res = await agent.get('/logs');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('GET /logs entries have the expected shape', async () => {
    const res = await agent.get('/logs');
    expect(res.body.length).toBeGreaterThan(0);
    const entry = res.body[0];
    expect(entry).toHaveProperty('ip');
    expect(entry).toHaveProperty('attackType');
    expect(entry).toHaveProperty('timestamp');
    expect(entry).toHaveProperty('method');       // null in local mode
    expect(entry).toHaveProperty('route');        // null in local mode
    expect(entry).toHaveProperty('responseTime'); // null in local mode
    expect(entry).toHaveProperty('statusCode');   // null in local mode
    expect(entry).toHaveProperty('userAgent');    // null in local mode
  });

  it('GET /logs local-mode fields are null', async () => {
    const res = await agent.get('/logs');
    const entry = res.body[0];
    expect(entry.method).toBeNull();
    expect(entry.route).toBeNull();
    expect(entry.responseTime).toBeNull();
    expect(entry.statusCode).toBeNull();
    expect(entry.userAgent).toBeNull();
  });

  it('GET /logs filters by ip', async () => {
    const res = await agent.get('/logs?ip=100.0.0.1');
    expect(res.status).toBe(200);
    expect(res.body.every(e => e.ip === '100.0.0.1')).toBe(true);
  });

  it('GET /logs filters by attackType', async () => {
    const res = await agent.get('/logs?attackType=DDoS%20(Excessive%20Requests)');
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.every(e => e.attackType === 'DDoS (Excessive Requests)')).toBe(true);
  });

  it('GET /logs respects limit param', async () => {
    const res = await agent.get('/logs?limit=1');
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(1);
  });

  it('GET /logs rejects invalid startDate with 400', async () => {
    const res = await agent.get('/logs?startDate=not-a-date');
    expect(res.status).toBe(400);
  });

  // --- GET /logs/attacks ---

  it('GET /logs/attacks returns an array', async () => {
    const res = await agent.get('/logs/attacks');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('GET /logs/attacks contains only attack entries', async () => {
    const res = await agent.get('/logs/attacks');
    expect(res.body.length).toBeGreaterThan(0);
    expect(res.body.every(e => e.attackType !== null)).toBe(true);
  });

  it('GET /logs/attacks shape matches /logs shape', async () => {
    const logs    = (await agent.get('/logs')).body;
    const attacks = (await agent.get('/logs/attacks')).body;
    const logsKeys    = Object.keys(logs[0]).sort();
    const attacksKeys = Object.keys(attacks[0]).sort();
    expect(attacksKeys).toEqual(logsKeys);
  });

  it('GET /logs/attacks respects limit param', async () => {
    const res = await agent.get('/logs/attacks?limit=1');
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(1);
  });

  // --- GET /logs/stats ---

  it('GET /logs/stats returns an array', async () => {
    const res = await agent.get('/logs/stats');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('GET /logs/stats entries have the expected shape', async () => {
    const res = await agent.get('/logs/stats');
    expect(res.body.length).toBeGreaterThan(0);
    const stat = res.body[0];
    expect(stat).toHaveProperty('_id');
    expect(stat).toHaveProperty('attackCount');
    expect(stat).toHaveProperty('totalRequests');
    expect(stat).toHaveProperty('avgResponseTime');
    expect(stat).toHaveProperty('routes');
  });

  it('GET /logs/stats counts attacks per IP correctly', async () => {
    const res = await agent.get('/logs/stats');
    for (const stat of res.body) {
      expect(stat.attackCount).toBeGreaterThan(0);
    }
  });

  it('GET /logs/stats local-mode fields are null', async () => {
    const res = await agent.get('/logs/stats');
    const stat = res.body[0];
    expect(stat.totalRequests).toBeNull();
    expect(stat.avgResponseTime).toBeNull();
    expect(Array.isArray(stat.routes)).toBe(true);
  });

  it('GET /logs/stats is sorted by attackCount descending', async () => {
    const res = await agent.get('/logs/stats');
    const counts = res.body.map(s => s.attackCount);
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
  });

  // --- GET /blocked ---

  it('GET /blocked returns { count, blocked }', async () => {
    const res = await agent.get('/blocked');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('count');
    expect(Array.isArray(res.body.blocked)).toBe(true);
    expect(res.body.count).toBe(res.body.blocked.length);
  });

  it('GET /blocked entries have the expected shape', async () => {
    const res = await agent.get('/blocked');
    expect(res.body.blocked.length).toBeGreaterThan(0);
    const entry = res.body.blocked[0];
    expect(entry).toHaveProperty('ip');
    expect(entry).toHaveProperty('reason');
    expect(entry).toHaveProperty('remainingSec');
    expect(entry).toHaveProperty('blockedUntil');
  });

  it('GET /blocked remainingSec is a positive number', async () => {
    const res = await agent.get('/blocked');
    for (const entry of res.body.blocked) {
      expect(entry.remainingSec).toBeGreaterThan(0);
    }
  });

  it('GET /blocked blockedUntil is a valid ISO date in the future', async () => {
    const res = await agent.get('/blocked');
    for (const entry of res.body.blocked) {
      expect(new Date(entry.blockedUntil).getTime()).toBeGreaterThan(Date.now());
    }
  });

  it('GET /blocked count decreases after an IP is unblocked', async () => {
    const before = (await agent.get('/blocked')).body.count;

    // Expire one block manually
    const [ip] = monitor.localBlockedIPs.keys();
    monitor.localBlockedIPs.get(ip).expiresAt = Date.now() - 1;

    const after = (await agent.get('/blocked')).body.count;
    expect(after).toBe(before - 1);
  });
});

// ---------------------------------------------------------------------------
// 14. Redis mode (mocked via ioredis-mock)
// ---------------------------------------------------------------------------

describe('Redis Mode (saveRecords: true)', () => {
  const redisConfig = {
    saveRecords: true,
    mongoURI: 'mongodb://localhost/test', // no real connection — async failures are swallowed
    redisURL: 'redis://localhost',
    maxRequests: 3,
    timeWindow: 60,
    scanThreshold: 5,
  };

  it('blocks an IP via Redis-backed rate limiting', async () => {
    const { app } = buildApp(redisConfig);
    const agent = request(app);

    for (let i = 0; i <= 3; i++) {
      await agent.get('/').set('x-forwarded-for', '30.30.30.30');
    }

    const res = await agent.get('/').set('x-forwarded-for', '30.30.30.30');
    expect(res.status).toBe(403);
  });

  it('returns a 403 body in Redis mode', async () => {
    const { app } = buildApp({ ...redisConfig, maxRequests: 1 });
    const agent = request(app);

    await agent.get('/').set('x-forwarded-for', '30.30.30.31');
    await agent.get('/').set('x-forwarded-for', '30.30.30.31');
    const res = await agent.get('/').set('x-forwarded-for', '30.30.30.31');

    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({
      error: expect.any(String),
      reason: expect.any(String),
      blockedFor: expect.stringContaining('seconds'),
      blockedUntil: expect.any(String),
    });
  });
});
