const APIMonitor = require('../src/index');
const express = require('express');
const request = require('supertest');
const Redis = require('ioredis-mock');
const mongoose = require('mongoose');
require('dotenv').config();

// Mock Redis
jest.mock('ioredis', () => require('ioredis-mock'));

describe('APIMonitor', () => {
  let app;
  let monitor;

  beforeEach(() => {
    app = express();
    const config = {
      mongoURI: process.env.MONGO_URI,
      redisURL: process.env.REDIS_URL,
      maxRequests: 5,
      timeWindow: 60,
      scanThreshold: 3
    };
    
    const { middleware, monitor: monitorInstance } = APIMonitor(config);
    monitor = monitorInstance;
    
    // First apply IP blocking
    app.use(APIMonitor.blockIPs(config));
    // Then apply monitoring
    app.use(middleware);
    
    // Add a default route for testing
    app.get('*', (req, res) => {
      res.sendStatus(200);
    });
  });

  afterEach(async () => {
    await mongoose.connection.close();
  });

  describe('Rate Limiting', () => {
    it('should block excessive requests', async () => {
      const agent = request(app);
      
      // Make 5 requests (up to limit)
      for (let i = 0; i < 5; i++) {
        await agent
          .get('/')
          .set('x-forwarded-for', '127.0.0.1');
      }

      // Make one more request that should be blocked
      const response = await agent
        .get('/')
        .set('x-forwarded-for', '127.0.0.1');
      
      expect(response.status).toBe(403);
    });
  });

  describe('Path Scanning Detection', () => {
    it('should detect path scanning attempts', async () => {
      const agent = request(app);
      const paths = ['/admin', '/wp-admin', '/phpmyadmin', '/config'];
      
      // Make suspicious requests
      for (const path of paths) {
        await agent
          .get(path)
          .set('x-forwarded-for', '127.0.0.1');
      }

      const response = await agent
        .get('/another-path')
        .set('x-forwarded-for', '127.0.0.1');
      
      expect(response.status).toBe(403);
    });
  });

  describe('IP Blocking', () => {
    it('should block previously marked IPs', async () => {
      const app = express();
      const config = {
        mongoURI: process.env.MONGO_URI,
        redisURL: process.env.REDIS_URL
      };
      
      const { middleware, monitor } = APIMonitor(config);
      
      app.use(APIMonitor.blockIPs(config));
      app.use(middleware);

      const agent = request(app);
      
      // Simulate blocked IP
      await new Redis().set('blocked:127.0.0.1', '1', 'EX', 300);

      const response = await agent
        .get('/')
        .set('x-forwarded-for', '127.0.0.1');
      
      expect(response.status).toBe(403);
    });
  });

  describe('Configuration', () => {
    it('should use default values when no options provided', () => {
      const { monitor } = APIMonitor({
        mongoURI: process.env.MONGO_URI,
        redisURL: process.env.REDIS_URL
      });
      expect(monitor.maxRequests).toBe(10);
      expect(monitor.timeWindow).toBe(60);
      expect(monitor.scanThreshold).toBe(5);
    });

    it('should use provided configuration values', () => {
      const { monitor } = APIMonitor({
        mongoURI: process.env.MONGO_URI,
        redisURL: process.env.REDIS_URL,
        maxRequests: 100,
        timeWindow: 3600,
        scanThreshold: 20
      });
      expect(monitor.maxRequests).toBe(100);
      expect(monitor.timeWindow).toBe(3600);
      expect(monitor.scanThreshold).toBe(20);
    });
  });

  describe('Event Emission', () => {
    it('should emit event when attack is detected', async () => {
      const app = express();
      const config = {
        mongoURI: process.env.MONGO_URI,
        redisURL: process.env.REDIS_URL,
        maxRequests: 1
      };
      
      const { middleware, monitor } = APIMonitor(config);
      const mockCallback = jest.fn();
      
      monitor.on('attack-detected', mockCallback);
      
      app.use(APIMonitor.blockIPs(config));
      app.use(middleware);
      
      const agent = request(app);
      
      // Make two requests to trigger the limit
      await agent.get('/').set('x-forwarded-for', '127.0.0.1');
      await agent.get('/').set('x-forwarded-for', '127.0.0.1');
      
      expect(mockCallback).toHaveBeenCalled();
    });
  });
}); 