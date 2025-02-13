const express = require('express');
const APIMonitor = require('../src/index');
require('dotenv').config();
const cors = require('cors');

const app = express();

// Enable CORS for all routes
app.use(cors());

// Advanced configuration
const monitorConfig = {
  maxRequests: 1000,      // Maximum 5 requests
  timeWindow: 3600,       // In a 5-second window
  scanThreshold: 20,    // Maximum 3 unique routes
  saveRecords: true,   // Use Redis and MongoDB
  mongoURI: process.env.MONGO_URI, // MongoDB URI
  redisURL: process.env.REDIS_URL, // Redis URI
};

// Create monitor instance
const { middleware, monitor } = APIMonitor(monitorConfig);

// Use the same monitor for IP blocking
app.use((req, res, next) => monitor.blockIPsMiddleware(req, res, next));

// Then apply the monitoring middleware
app.use(middleware);

// Base route
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

// Advanced log queries
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

// Query attack logs route
app.get('/logs/attacks', async (req, res) => {
  try {
    const attackLogs = await monitor.LogModel.find({ 
      attackType: { $ne: null } 
    }).sort({ timestamp: -1 });
    res.json(attackLogs);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching attack logs' });
  }
});

// Example routes
app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.get('/api/products', (req, res) => {
  res.json({ products: [] });
});

// Listen for attack events
monitor.on('attack-detected', (data) => {
  console.log('🚨 Attack detected:', {
    ip: data.ip,
    type: data.type,
    timestamp: new Date(data.timestamp),
    details: {
      maxRequestsAllowed: monitorConfig.maxRequests,
      timeWindow: `${monitorConfig.timeWindow} seconds`,
      scanThreshold: monitorConfig.scanThreshold
    }
  });
  
  // Here you could add additional logic like:
  // - Send notifications
  // - Log to external services
  // - Update metrics
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Advanced server running on port ${PORT}`);
}); 