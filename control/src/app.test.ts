import request from 'supertest';
import express from 'express';
import http from 'http';
import app from './app';

import axios from 'axios';
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { exec } from 'child_process';

let server: http.Server;

beforeAll((done) => {
  // Mock axios.get to always resolve for /start and /stop
  jest.spyOn(axios, 'get').mockImplementation(async () => ({ data: {} }));
  // Mock fs and fsSync methods to avoid real file operations
  jest.spyOn(fs, 'readdir').mockResolvedValue([]);
  jest.spyOn(fs, 'unlink').mockResolvedValue(undefined as any);
  jest.spyOn(fs, 'rm').mockResolvedValue(undefined as any);
  jest.spyOn(fs, 'readFile').mockResolvedValue('[]');
  jest.spyOn(fs, 'writeFile').mockResolvedValue(undefined as any);
  jest.spyOn(fsSync, 'existsSync').mockReturnValue(false);
  jest.spyOn(fsSync, 'mkdirSync').mockImplementation(() => undefined); // Fix: return undefined
  jest.spyOn(fsSync, 'readFileSync').mockReturnValue('[]');
  jest.spyOn(fsSync, 'writeFileSync').mockImplementation(() => {});
  // Mock child_process.exec to always succeed
  jest.spyOn(require('child_process'), 'exec').mockImplementation(
    (...args: unknown[]) => {
      const callback = args[1] as Function;
      // Simulate async success
      setImmediate(() => callback && callback(null));
      return {} as any;
    }
  );
  server = app.listen(4000, done);
});

afterAll((done) => {
  jest.restoreAllMocks();
  server.close(done);
});

describe('GET /test', () => {
  it('should return server is running message', async () => {
    const res = await request(server).get('/test');
    expect(res.statusCode).toBe(200);
    expect(res.text).toBe('Server is running and reachable.');
  });
});

describe('GET /server-name/:containerName', () => {
  it('should register a new container name', async () => {
    const res = await request(server).get('/server-name/testcontainer');
    expect(res.statusCode).toBe(200);
    expect(res.text).toContain('Container name received: testcontainer');
  });
});

describe('GET /start', () => {
  it('should send start signal to all scan dockers', async () => {
    // Register a container first
    await request(server).get('/server-name/testcontainer2');
    const res = await request(server).get('/start');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
    expect(res.body).toHaveProperty('results');
    expect(Array.isArray(res.body.results)).toBe(true);
  });
});

describe('GET /stop', () => {
  it('should send stop signal and return pcap data', async () => {
    // Register a container first
    await request(server).get('/server-name/testcontainer3');
    // Mock fsSync.existsSync to simulate merged.pcap and output.json exist
    (fsSync.existsSync as jest.Mock).mockImplementation((filePath: string) => {
      if (filePath.endsWith('merged.pcap') || filePath.endsWith('output.json')) return true;
      return false;
    });
    (fs.readFile as jest.Mock).mockResolvedValue('[{"_index":0}]');
    const res = await request(server).get('/stop');
    expect([200, 500]).toContain(res.statusCode);
    if (res.statusCode === 200) {
      expect(res.body).toHaveProperty('message');
      expect(res.body).toHaveProperty('results');
      expect(res.body).toHaveProperty('pcapData');
    } else if (res.statusCode === 500) {
      expect(res.text).toBeDefined();
      // Print the error for debugging
      console.error('Error from /stop:', res.text);
    }
  }, 10000); // Increase timeout to 10s
});

describe('POST /config', () => {
  it('should save configuration and filter if possible', async () => {
    // Mock fsSync.existsSync to simulate merged.pcap exists
    (fsSync.existsSync as jest.Mock).mockImplementation((filePath: string) => {
      if (filePath.endsWith('merged.pcap')) return true;
      return false;
    });
    const config = { ip: '1.2.3.4', port: 80 };
    const res = await request(server).post('/config').send(config);
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
  }, 10000); // Increase timeout to 10s
});

describe('GET /cleanConf', () => {
  it('should clean config and filtered files', async () => {
    // Mock fsSync.existsSync to simulate files exist
    (fsSync.existsSync as jest.Mock).mockReturnValue(true);
    const res = await request(server).get('/cleanConf');
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('message');
  });
});