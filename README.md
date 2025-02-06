# API Security Monitor

![npm version](https://img.shields.io/npm/v/api-security-monitor)
![License](https://img.shields.io/npm/l/api-security-monitor)
![Downloads](https://img.shields.io/npm/dm/api-security-monitor)

A robust middleware for monitoring and protecting Express.js APIs against common attacks using Redis and MongoDB. This package provides real-time detection of DDoS attacks, suspicious scanning activities, and automatic IP blocking.

## Features

- 🛡️ Rate limiting by IP address
- 🔍 Detection of path scanning attempts
- 🚫 Automatic IP blocking for suspicious activity
- ⚙️ Highly configurable thresholds and time windows
- ⚡ Redis-based request tracking for high performance
- 📝 MongoDB logging support for attack analysis
- 🔌 Easy integration with Express.js applications

## Installation

```bash
npm install api-security-monitor
```

## Quick Start

```javascript
const express = require('express');
const APIMonitor = require('api-security-monitor');

const app = express();

// Basic configuration
const basicConfig = {
  mongoURI: process.env.MONGO_URI,
  redisURL: process.env.REDIS_URL
  // Default values:
  // maxRequests: 10
  // timeWindow: 60
  // scanThreshold: 5
};

// Create monitor instance
const { middleware, monitor } = APIMonitor(basicConfig);

// First apply the IP blocking middleware
app.use(APIMonitor.blockIPs(basicConfig));

// Then apply the monitoring middleware
app.use(middleware);

// Example routes
app.get('/', (req, res) => {
  res.json({ message: 'API working correctly' });
});

// Listen for attack events
monitor.on('attack-detected', (data) => {
  console.log('🚨 Attack detected:', {
    ip: data.ip,
    type: data.type,
    time: new Date(data.timestamp)
  });
});
```

## Advanced Usage

```javascript
const express = require('express');
const APIMonitor = require('api-security-monitor');

const app = express();

// Advanced configuration
const monitorConfig = {
  mongoURI: process.env.MONGO_URI,
  redisURL: process.env.REDIS_URL,
  maxRequests: 1000,    // Allow 1000 requests
  timeWindow: 3600,     // Per hour
  scanThreshold: 20     // Maximum 20 unique endpoints
};

const { middleware, monitor } = APIMonitor(monitorConfig);

// Create monitor instance
const { middleware, monitor } = APIMonitor(monitorConfig);

// First apply the IP blocking middleware
app.use(APIMonitor.blockIPs(monitorConfig));

// Then apply the monitoring middleware
app.use(middleware);

// Example routes
app.get('/', (req, res) => {
  res.json({ message: 'API working correctly' });
});

// Query logs with filters
app.get('/logs', async (req, res) => {
  try {
    const { ip, attackType, startDate, endDate, limit = 10 } = req.query;
    const query = {};

    if (ip) query.ip = ip;
    if (attackType) query.attackType = attackType;
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    const logs = await monitor.LogModel.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching logs' });
  }
});

// Get attack statistics
app.get('/logs/stats', async (req, res) => {
  try {
    const stats = await monitor.LogModel.aggregate([
      {
        $group: {
          _id: '$ip',
          totalRequests: { $sum: 1 },
          avgResponseTime: { $avg: '$responseTime' },
          attackCount: {
            $sum: { $cond: [{ $ne: ['$attackType', null] }, 1, 0] }
          },
          routes: { $addToSet: '$route' }
        }
      },
      { $sort: { totalRequests: -1 } }
    ]);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching stats' });
  }
});
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mongoURI` | string | `process.env.MONGO_URI` | MongoDB connection URI |
| `redisURL` | string | `process.env.REDIS_URL` | Redis connection URL |
| `maxRequests` | number | `10` | Maximum requests allowed per time window |
| `timeWindow` | number | `60` | Time window in seconds |
| `scanThreshold` | number | `5` | Maximum unique endpoints allowed per time window |

## Environment Variables

Create a `.env` file in your project root:

```env
MONGO_URI=mongodb://localhost:27017/api-monitor
REDIS_URL=redis://localhost:6379
```

## Advanced Usage

### Custom Rate Limiting

```javascript
const monitor = APIMonitor({
  maxRequests: 1000,    // Allow 1000 requests
  timeWindow: 3600,     // Per hour
  scanThreshold: 20     // Allow up to 20 unique endpoints
});
```

### Blocking Suspicious IPs

```javascript
// Add both monitoring and blocking middleware
app.use(APIMonitor());
app.use(APIMonitor.blockIPs());

// The blocked IPs will receive a 403 response
```

## Events

The middleware emits events that you can listen to:

```javascript
const monitor = APIMonitor();
monitor.on('attack-detected', (data) => {
  console.log(`Attack detected from IP: ${data.ip}`);
});
```

## Contributing

🚧 **Note:** We are not accepting contributions at this time as the project is in early development stage. Please check back later.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 🐛 Issues: [GitHub Issues](https://github.com/javier-cuevas/api-security-monitor/issues)
- 📖 Documentation: [Wiki](https://github.com/javier-cuevas/api-security-monitor/wiki)

## Acknowledgments

- Express.js team
- MongoDB team
- Redis team
