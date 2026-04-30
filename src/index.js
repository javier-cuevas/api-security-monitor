const mongoose = require('mongoose');
const Redis = require('ioredis');
const EventEmitter = require('events');
const fs = require('fs');

// Defines the schema for the logs
const LogSchema = new mongoose.Schema({
  ip: String,
  method: String,
  route: String,
  timestamp: { type: Date, default: Date.now },
  responseTime: Number,
  statusCode: Number,
  userAgent: String,
  attackType: String
}, { timestamps: true });

/**
 * APIMonitor class for detecting and preventing API attacks
 * @class APIMonitor
 */
class APIMonitor extends EventEmitter {
  /**
   * Create an APIMonitor instance
   * @param {Object} options - Configuration options
   * @param {string}  [options.mongoURI]         - MongoDB connection URI
   * @param {string}  [options.redisURL]          - Redis connection URL
   * @param {number}  [options.maxRequests=10]    - Maximum requests allowed per time window
   * @param {number}  [options.timeWindow=60]     - Time window in seconds
   * @param {number}  [options.scanThreshold=5]   - Maximum unique endpoints per time window
   * @param {number}  [options.cleanupInterval=60000] - Local-mode cleanup interval in ms
   * @param {string}  [options.blockLogPath]      - Path for the NDJSON block log file
   */
  constructor(options = {}) {
    super();
    this.maxRequests    = options.maxRequests    || 10;
    this.timeWindow     = options.timeWindow     || 60;
    this.scanThreshold  = options.scanThreshold  || 5;
    this.saveRecords    = options.saveRecords    || false;

    if (this.saveRecords) {
      this.mongoURI = options.mongoURI || process.env.MONGO_URI;
      this.redisURL = options.redisURL || process.env.REDIS_URL;
      if (!this.mongoURI || !this.redisURL) {
        throw new Error('mongoURI and redisURL are required when saveRecords is true');
      }
      this.connectToMongo();
      this.connectToRedis();
    } else {
      // In-memory tracking structures
      this.localRequestCounts = new Map(); // ip → number[]  (request timestamps)
      this.localRouteScans    = new Map(); // ip → Set<route> (within current window)
      this.localBlockedIPs    = new Map(); // ip → { expiresAt, reason }

      // Optional NDJSON block log — restore non-expired blocks from a previous run
      this.blockLogPath = options.blockLogPath || null;
      if (this.blockLogPath) {
        this._loadBlockLog();
      }

      // Periodic cleanup — evicts stale data so Maps don't grow unbounded
      const cleanupInterval = options.cleanupInterval ?? 60_000;
      this._startCleanupTimer(cleanupInterval);
    }
  }

  // ---------------------------------------------------------------------------
  // Local-mode helpers
  // ---------------------------------------------------------------------------

  /**
   * Starts the periodic cleanup timer.
   * Uses unref() so the timer never prevents the process from exiting.
   * @private
   */
  _startCleanupTimer(intervalMs) {
    const timer = setInterval(() => {
      const now         = Date.now();
      const windowStart = now - (this.timeWindow * 1000);

      // Evict expired blocked IPs
      for (const [ip, info] of this.localBlockedIPs) {
        if (now >= info.expiresAt) {
          this.localBlockedIPs.delete(ip);
          this._appendBlockLog({
            timestamp: new Date().toISOString(),
            ip,
            action: 'unblock',
            reason: 'ttl_expired',
          });
        }
      }

      // Evict stale tracking entries (IPs with no activity in current window)
      for (const [ip, timestamps] of this.localRequestCounts) {
        const active = timestamps.filter(t => t > windowStart);
        if (active.length === 0) {
          this.localRequestCounts.delete(ip);
          this.localRouteScans.delete(ip);
        } else {
          this.localRequestCounts.set(ip, active);
        }
      }
    }, intervalMs);

    // Don't keep the process alive just for cleanup
    if (timer.unref) timer.unref();
    this._cleanupTimer = timer;
  }

  /**
   * Appends one JSON line to the block log file (NDJSON format).
   * Each line is a self-contained JSON object — compatible with jq, grep,
   * tail -f, fail2ban, Filebeat, Logstash, and most SIEM tools.
   * @private
   */
  _appendBlockLog(entry) {
    if (!this.blockLogPath) return;
    const line = JSON.stringify(entry) + '\n';
    fs.appendFile(this.blockLogPath, line, (err) => {
      if (err) console.error('Error writing to block log:', err);
    });
  }

  /**
   * Reads the NDJSON block log on startup and restores non-expired blocks
   * into localBlockedIPs so state survives process restarts.
   * @private
   */
  _loadBlockLog() {
    try {
      if (!fs.existsSync(this.blockLogPath)) return;
      const content = fs.readFileSync(this.blockLogPath, 'utf8');
      const now     = Date.now();

      for (const line of content.split('\n').filter(Boolean)) {
        try {
          const entry = JSON.parse(line);
          if (entry.action === 'block' && entry.expiresAt > now) {
            this.localBlockedIPs.set(entry.ip, {
              expiresAt: entry.expiresAt,
              reason:    entry.reason,
            });
          }
        } catch {
          // Skip malformed lines silently
        }
      }
    } catch (err) {
      console.error('Error loading block log:', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Connection helpers (Redis / MongoDB mode)
  // ---------------------------------------------------------------------------

  /**
   * Establishes connection to MongoDB and initializes models
   * @private
   */
  async connectToMongo() {
    try {
      await mongoose.connect(this.mongoURI);
      console.log('Connected to MongoDB');
      this.LogModel = mongoose.model('RequestLog', LogSchema);
    } catch (err) {
      console.error('MongoDB Error:', err);
    }
  }

  /**
   * Establishes connection to Redis
   * @private
   */
  connectToRedis() {
    try {
      this.redis = new Redis(this.redisURL);
      this.redis.on('connect', () => console.log('Connected to Redis'));
      this.redis.on('error',   (err) => console.error('Redis Error:', err));
    } catch (err) {
      console.error('Redis Connection Error:', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Core logic
  // ---------------------------------------------------------------------------

  /**
   * Gets the real IP address from the request.
   *
   * Relies on Express's req.ip, which correctly resolves the client IP
   * based on the host application's `trust proxy` setting.
   * Configure it in your app before mounting this middleware:
   *
   *   app.set('trust proxy', 1)            // trust one upstream proxy (e.g. nginx)
   *   app.set('trust proxy', '10.0.0.1')   // trust a specific proxy IP
   *
   * WARNING: Do NOT parse X-Forwarded-For manually — it is trivially spoofed
   * unless validated by a trusted proxy at the network edge.
   *
   * @private
   * @param {Object} req - Express request object
   * @returns {string} IP address
   */
  getClientIP(req) {
    const ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    if (ip === '::1' || ip === '::ffff:127.0.0.1') return '127.0.0.1';
    if (ip.startsWith('::ffff:')) return ip.substring(7);
    return ip;
  }

  /**
   * Checks and updates local request tracking.
   * Both request counts and route scans are bounded to the current time window,
   * preventing unbounded Set growth for long-lived IPs.
   * @private
   * @param {string} ip    - IP address
   * @param {string} route - Request path (without query string)
   * @returns {{ requestCount: number, scanCount: number }}
   */
  updateLocalTracking(ip, route) {
    const now         = Date.now();
    const windowStart = now - (this.timeWindow * 1000);

    // Slide the request-count window
    const requests = (this.localRequestCounts.get(ip) || []).filter(t => t > windowStart);

    // If no requests exist in the current window the window has fully expired —
    // reset route tracking so old routes don't count toward the new window.
    if (requests.length === 0) {
      this.localRouteScans.set(ip, new Set());
    } else if (!this.localRouteScans.has(ip)) {
      this.localRouteScans.set(ip, new Set());
    }

    requests.push(now);
    this.localRequestCounts.set(ip, requests);
    this.localRouteScans.get(ip).add(route);

    return {
      requestCount: requests.length,
      scanCount:    this.localRouteScans.get(ip).size,
    };
  }

  /**
   * Saves request log to MongoDB
   * @private
   */
  async saveLog(logData) {
    if (logData.attackType) {
      console.log('Attack log:', logData);
    }
    if (this.saveRecords) {
      try {
        const log = new this.LogModel(logData);
        await log.save();
      } catch (err) {
        console.error('Error saving log:', err);
      }
    }
  }

  /**
   * Middleware for monitoring API requests
   * @param {Object}   req  - Express request object
   * @param {Object}   res  - Express response object
   * @param {Function} next - Express next function
   */
  async monitorMiddleware(req, res, next) {
    try {
      const start  = Date.now();
      const ip     = this.getClientIP(req);
      const route  = req.path; // excludes query strings — prevents PII leakage
      const method = req.method;

      const isBlocked = await this.isIPBlocked(ip);
      if (isBlocked) {
        const blockInfo = await this.getBlockInfo(ip);
        return res.status(403).json(blockInfo);
      }

      if (this.saveRecords) {
        const requestKey = `req_count:${ip}`;
        const scanKey    = `scan_count:${ip}`;

        await this.redis.multi()
          .incr(requestKey)
          .expire(requestKey, this.timeWindow)
          .exec();

        await this.redis.sadd(scanKey, route);
        await this.redis.expire(scanKey, this.timeWindow);

        const requestCount = await this.redis.get(requestKey);
        const scanCount    = await this.redis.scard(scanKey);

        await this.handleAttackDetection(ip, parseInt(requestCount), parseInt(scanCount));
      } else {
        const { requestCount, scanCount } = this.updateLocalTracking(ip, route);
        await this.handleAttackDetection(ip, requestCount, scanCount);
      }

      res.on('finish', async () => {
        try {
          const responseTime = Date.now() - start;
          const blocked      = await this.isIPBlocked(ip);
          const attackType   = blocked ? 'Blocked' : null;

          if (this.saveRecords || blocked) {
            await this.saveLog({
              ip,
              method,
              route,
              timestamp:   new Date(),
              responseTime,
              statusCode:  res.statusCode,
              userAgent:   req.headers['user-agent'],
              attackType,
            });
          }
        } catch (finishErr) {
          console.error('Error in response finish handler:', finishErr);
        }
      });

      next();
    } catch (err) {
      next(err);
    }
  }

  /**
   * Checks if an IP is currently blocked.
   * In local mode, lazily evicts expired entries and logs the unblock event.
   * @private
   * @param {string} ip
   * @returns {Promise<boolean>}
   */
  async isIPBlocked(ip) {
    if (this.saveRecords) {
      try {
        return !!(await this.redis.get(`blocked:${ip}`));
      } catch (err) {
        console.error('Error checking blocked IP:', err);
        return false;
      }
    }

    const blockInfo = this.localBlockedIPs.get(ip);
    if (!blockInfo) return false;

    if (Date.now() >= blockInfo.expiresAt) {
      this.localBlockedIPs.delete(ip);
      this._appendBlockLog({
        timestamp: new Date().toISOString(),
        ip,
        action:    'unblock',
        reason:    'ttl_expired',
      });
      return false;
    }

    return true;
  }

  async getBlockInfo(ip) {
    if (this.saveRecords) {
      const ttl    = await this.redis.ttl(`blocked:${ip}`);
      const reason = await this.redis.get(`blocked:${ip}:reason`);
      return {
        error:        'Access denied due to suspicious activity',
        reason:       reason || 'Rate limit exceeded',
        blockedFor:   `${ttl} seconds`,
        blockedUntil: new Date(Date.now() + ttl * 1000).toISOString(),
      };
    }

    const blockInfo      = this.localBlockedIPs.get(ip);
    const remainingTime  = Math.ceil((blockInfo.expiresAt - Date.now()) / 1000);
    return {
      error:        'Access denied due to suspicious activity',
      reason:       blockInfo.reason,
      blockedFor:   `${remainingTime} seconds`,
      blockedUntil: new Date(blockInfo.expiresAt).toISOString(),
    };
  }

  async handleAttackDetection(ip, requestCount, scanCount) {
    let attackType = null;
    if (requestCount > this.maxRequests) {
      attackType = 'DDoS (Excessive Requests)';
    } else if (scanCount > this.scanThreshold) {
      attackType = 'Path Scanning';
    }

    if (!attackType) return;

    this.emit('attack-detected', { ip, type: attackType, timestamp: new Date() });
    console.warn(`Possible attack detected: ${attackType} from IP ${ip}`);

    if (this.saveRecords) {
      await this.redis.multi()
        .set(`blocked:${ip}`,          '1',        'EX', 300)
        .set(`blocked:${ip}:reason`,   attackType, 'EX', 300)
        .exec();
    } else {
      const expiresAt = Date.now() + 300_000; // 5 minutes

      this.localBlockedIPs.set(ip, { expiresAt, reason: attackType });
      this._appendBlockLog({
        timestamp: new Date().toISOString(),
        ip,
        reason:    attackType,
        expiresAt,
        action:    'block',
      });

      // Clear tracking so the IP starts fresh after the block expires
      this.localRequestCounts.delete(ip);
      this.localRouteScans.delete(ip);
    }
  }

  async blockIPsMiddleware(req, res, next) {
    try {
      const ip        = this.getClientIP(req);
      const isBlocked = await this.isIPBlocked(ip);
      if (isBlocked) {
        const blockInfo = await this.getBlockInfo(ip);
        return res.status(403).json(blockInfo);
      }
      next();
    } catch (err) {
      next(err);
    }
  }
}

/**
 * Creates an APIMonitor instance and returns middleware functions all sharing the same instance.
 * @param {Object} options - Configuration options
 * @returns {{ middleware: Function, blockIPs: Function, monitor: APIMonitor }}
 *   - middleware: tracks requests and detects attacks
 *   - blockIPs:   rejects blocked IPs early — shares state with monitor, mount before middleware
 *   - monitor:    the underlying APIMonitor instance (use for event listening, direct access)
 */
module.exports = (options) => {
  const monitor   = new APIMonitor(options);
  const middleware = (req, res, next) => monitor.monitorMiddleware(req, res, next);
  const blockIPs   = (req, res, next) => monitor.blockIPsMiddleware(req, res, next);
  return { middleware, blockIPs, monitor };
};

/**
 * Creates a standalone IP-blocking middleware with its own independent APIMonitor instance.
 *
 * NOTE: This creates a separate instance — it does NOT share state with any factory instance.
 * For shared state use the `blockIPs` property returned by the factory instead.
 *
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
module.exports.blockIPs = (options) => {
  const monitor = new APIMonitor(options);
  return (req, res, next) => monitor.blockIPsMiddleware(req, res, next);
};
