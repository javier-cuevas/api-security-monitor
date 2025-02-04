const express = require('express');
const APIMonitor = require('../src/index');
require('dotenv').config();

const app = express();

// Basic configuration
const basicConfig = {
    mongoURI: process.env.MONGO_URI,
    redisURL: process.env.REDIS_URL
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

app.get('/protected', (req, res) => {
  res.json({ message: 'Protected route' });
});

// Query logs route
app.get('/logs', async (req, res) => {
  try {
    const logs = await monitor.LogModel.find()
      .sort({ timestamp: -1 })
      .limit(10);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching logs' });
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

// Listen for attack events
monitor.on('attack-detected', (data) => {
  console.log('🚨 Attack detected:', {
    ip: data.ip,
    type: data.type,
    time: new Date(data.timestamp)
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Example server running on port ${PORT}`);
}); 