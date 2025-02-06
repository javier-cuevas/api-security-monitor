const mongoose = require('mongoose');
const Redis = require('ioredis');
const EventEmitter = require('events');

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
   * @param {string} [options.mongoURI] - MongoDB connection URI
   * @param {string} [options.redisURL] - Redis connection URL
   * @param {number} [options.maxRequests=10] - Maximum requests allowed per time window
   * @param {number} [options.timeWindow=60] - Time window in seconds
   * @param {number} [options.scanThreshold=5] - Maximum unique endpoints allowed per time window
   */
  constructor(options = {}) {
    super();
    this.saveRecords = options.saveRecords || false;
    this.maxRequests = options.maxRequests || 10;
    this.timeWindow = options.timeWindow || 60;
    this.scanThreshold = options.scanThreshold || 5;
    this.mongoURI = options.mongoURI || process.env.MONGO_URI;
    this.redisURL = options.redisURL || process.env.REDIS_URL;

    this.connectToMongo();
    this.connectToRedis();
  }

  /**
   * Establishes connection to MongoDB and initializes models
   * @private
   */
  async connectToMongo() {
    try {
      await mongoose.connect(this.mongoURI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
      console.log('✅ Connected to MongoDB');
      
      // Initialize the Log model
      this.LogModel = mongoose.model('RequestLog', LogSchema);
    } catch (err) {
      console.error('❌ MongoDB Error:', err);
    }
  }

  /**
   * Establishes connection to Redis
   * @private
   */
  connectToRedis() {
    try {
      this.redis = new Redis(this.redisURL);
      this.redis.on('connect', () => console.log('✅ Connected to Redis'));
      this.redis.on('error', (err) => console.error('❌ Redis Error:', err));
    } catch (err) {
      console.error('❌ Redis Connection Error:', err);
    }
  }

  /**
   * Gets the real IP address from the request
   * @private
   * @param {Object} req - Express request object
   * @returns {string} IP address
   */
  getClientIP(req) {
    let ip;

    // Check x-forwarded-for header
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      // Get the first IP in the list (client's original IP)
      ip = forwardedFor.split(',')[0].trim();
    } else {
      // Check other common headers
      ip = req.headers['x-real-ip'] ||
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip ||
           '0.0.0.0';
    }

    // Convert IPv6 localhost to IPv4
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
      ip = '127.0.0.1';
    }
    // Remove IPv6 prefix if present
    else if (ip.startsWith('::ffff:')) {
      ip = ip.substring(7);
    }

    return ip;
  }

  /**
   * Saves request log to MongoDB
   * @private
   * @param {Object} logData - Log data to save
   */
  async saveLog(logData) {
    try {
      const log = new this.LogModel(logData);
      await log.save();
    } catch (err) {
      console.error('❌ Error saving log:', err);
    }
  }

  /**
   * Middleware for monitoring API requests
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async monitorMiddleware(req, res, next) {
    const start = Date.now();
    const ip = this.getClientIP(req);
    const route = req.originalUrl;
    const method = req.method;
    const requestKey = `req_count:${ip}`;
    const scanKey = `scan_count:${ip}`;

    // Count IP requests within time window
    await this.redis.multi()
      .incr(requestKey)
      .expire(requestKey, this.timeWindow)
      .exec();

    await this.redis.sadd(scanKey, route);
    await this.redis.expire(scanKey, this.timeWindow);

    const requestCount = await this.redis.get(requestKey);
    const scanCount = await this.redis.scard(scanKey);

    let attackType = null;
    if (requestCount > this.maxRequests) {
      attackType = 'DDoS (Excessive Requests)';
    } else if (scanCount > this.scanThreshold) {
      attackType = 'Path Scanning';
    }

    // Capture response data
    res.on('finish', async () => {
      const responseTime = Date.now() - start;
      
      // Prepare log data
      const logData = {
        ip,
        method,
        route,
        timestamp: new Date(),
        responseTime,
        statusCode: res.statusCode,
        userAgent: req.headers['user-agent'],
        attackType
      };

      // Save log to MongoDB
      await this.saveLog(logData);

      if (attackType) {
        this.emit('attack-detected', {
          ip,
          type: attackType,
          timestamp: new Date()
        });
        console.warn(`🚨 Possible attack detected: ${attackType} from IP ${ip}`);
        await this.redis.set(`blocked:${ip}`, '1', 'EX', 300);
      }
    });

    next();
  }

  /**
   * Middleware for blocking suspicious IPs
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next function
   */
  async blockIPsMiddleware(req, res, next) {
    const ip = this.getClientIP(req);
    const isBlocked = await this.redis.get(`blocked:${ip}`);

    if (isBlocked) {
      return res.status(403).json({ error: '🚫 Access denied due to suspicious activity' });
    }

    next();
  }
}

/**
 * Creates an instance of the monitoring middleware and returns both middleware and monitor
 * @param {Object} options - Configuration options
 * @returns {Object} Object containing middleware function and monitor instance
 */
module.exports = (options) => {
  const monitor = new APIMonitor(options);
  const middleware = (req, res, next) => monitor.monitorMiddleware(req, res, next);
  
  // Return both the middleware and the monitor instance
  return {
    middleware,
    monitor
  };
};

/**
 * Creates an instance of the IP blocking middleware
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
module.exports.blockIPs = (options) => {
  const monitor = new APIMonitor(options);
  return (req, res, next) => monitor.blockIPsMiddleware(req, res, next);
};
