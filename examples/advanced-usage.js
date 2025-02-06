const express = require('express');
const APIMonitor = require('../src/index');
require('dotenv').config();

const app = express();

// Advanced configuration
const monitorConfig = {
  saveRecords: true, // Save records
  maxRequests: 1000,    // Allow 1000 requests
  timeWindow: 3600,     // Per hour
  scanThreshold: 20,     // Maximum 20 unique endpoints
  mongoURI: process.env.MONGO_URI, // MongoDB URI
  redisURL: process.env.REDIS_URL, // Redis URI
};

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