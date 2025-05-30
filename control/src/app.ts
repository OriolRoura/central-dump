/**
 * @file app.ts
 * @description This file contains the implementation of an Express server that acts as a control application
 * to manage and communicate with scan dockers by sending start/stop signals and registering container names.
 * 
 * @dependencies
 * - express: Web framework for Node.js
 * - axios: For making HTTP requests
 * 
 * @usage
 * - Start the server: `node app.js`
 * - Endpoints:
 *   - GET /server-name/:containerName: Registers a container name
 *   - GET /start: Sends a start signal to all registered containers
 *   - GET /stop: Sends a stop signal to all registered containers
 * 
 * @note Ensure the control server is accessible by all scan dockers for proper communication.
 */

import express, { Request, Response } from 'express';
import axios from 'axios';
import { exec } from 'child_process';
import path from 'path';
import fs from 'fs/promises';
import cors from 'cors';
import bodyParser from 'body-parser';
import fsSync from 'fs';
import pathSync from 'path';

const app = express();
app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

const port = 3000;
const containerNames: string[] = [];
const pcapDir = '/data';
const logFilePath = path.join(pcapDir, 'control.log');

/**
 * Logs an event to the control log file.
 * @param event - The event description.
 * @param details - Additional details about the event.
 * @param success - Whether the event was successful.
 */
function logEvent(event: string, details?: string, success?: boolean) {
  const timestamp = new Date().toISOString();
  let msg = `[${timestamp}] ${event}`;
  if (details) msg += ` | Details: ${details}`;
  if (success !== undefined) msg += ` | Success: ${success}`;
  msg += '\n';
  fsSync.appendFileSync(logFilePath, msg, 'utf-8');
}

// --- Utility Functions ---

function ensureDirSync(dir: string) {
  if (!fsSync.existsSync(dir)) {
    fsSync.mkdirSync(dir, { recursive: true });
  }
}

function getLatestConfig(): any | undefined {
  const configFilePath = path.join(pcapDir, 'config.json');
  if (!fsSync.existsSync(configFilePath)) return undefined;
  return JSON.parse(fsSync.readFileSync(configFilePath, 'utf-8'));
}

async function clearOldPcaps(dir: string) {
  const files = await fs.readdir(dir);
  for (const file of files) {
    if (file.endsWith('.pcap')) {
      await fs.unlink(path.join(dir, file));
    }
  }
  // Also delete output.json if it exists
  const outputJsonPath = path.join(dir, 'output.json');
  if (fsSync.existsSync(outputJsonPath)) {
    await fs.unlink(outputJsonPath);
  }
  // Also delete filtered.pcap and filtered.json if they exist
  const filteredPcapPath = path.join(dir, 'filtered.pcap');
  if (fsSync.existsSync(filteredPcapPath)) {
    await fs.unlink(filteredPcapPath);
  }
  const filteredJsonPath = path.join(dir, 'filtered.json');
  if (fsSync.existsSync(filteredJsonPath)) {
    await fs.unlink(filteredJsonPath);
  }
  logEvent('Monitoring started', 'Cleared old pcap files, output.json, filtered.pcap, and filtered.json', true);
}

async function mergePcaps(dir: string, mergedPcapFile: string) {
  await fs.rm(mergedPcapFile, { force: true });
  const pcapFiles = (await fs.readdir(dir))
    .filter((file:any) => file.endsWith('.pcap'))
    .map((file:any) => path.join(dir, file));
  if (pcapFiles.length === 0) {
    logEvent('Monitoring stopped', 'No .pcap files found to merge', false);
    throw new Error('No .pcap files found to merge.');
  }
  const mergecapCommand = `mergecap -w ${mergedPcapFile} ${pcapFiles.join(' ')}`;
  await new Promise((resolve, reject) => {
    exec(mergecapCommand, (error:any) => {
      logEvent('Monitoring stopped', `Command: ${mergecapCommand}`, !error);
      if (error) return reject(error);
      resolve(null);
    });
  });
}

async function pcapToJson(pcapFile: string, jsonFile: string) {
  const tsharkCmd = `tshark -r ${pcapFile} -T json > ${jsonFile}`;
  await new Promise((resolve, reject) => {
    exec(tsharkCmd, (error) => {
      logEvent('Filtering', `Command: ${tsharkCmd}`, !error && fsSync.existsSync(jsonFile));
      if (error) return reject(error);
      resolve(null);
    });
  });
}

async function filterPcapAndJson(
  mergedPcapFile: string,
  filterString: string,
  outputDir: string
): Promise<{ status: 'ok' | 'ko', filteredJsonData?: any, errorMsg?: string }> {
  const filteredPcapFile = path.join(outputDir, 'filtered.pcap');
  const filteredJsonFile = path.join(outputDir, 'filtered.json');
  try {
    const filterCmd = filterString
      ? `tshark -r ${mergedPcapFile} -Y "${filterString}" -w ${filteredPcapFile}`
      : `cp ${mergedPcapFile} ${filteredPcapFile}`;
    await new Promise((resolve, reject) => {
      exec(filterCmd, (error:any) => {
        logEvent('Filtering', `Command: ${filterCmd}`, !error && fsSync.existsSync(filteredPcapFile));
        if (error) return reject(error);
        resolve(null);
      });
    });
    await pcapToJson(filteredPcapFile, filteredJsonFile);
    if (fsSync.existsSync(filteredJsonFile)) {
      const filteredJsonData = JSON.parse(fsSync.readFileSync(filteredJsonFile, 'utf-8'));
      logEvent('Filtering', `Output: ${filteredJsonFile}`, true);
      return { status: 'ok', filteredJsonData };
    } else {
      logEvent('Filtering', `Output: ${filteredJsonFile}`, false);
      return { status: 'ko', errorMsg: 'Filtered JSON file not found after filtering.' };
    }
  } catch (err: any) {
    logEvent('Filtering', `Error: ${err?.message || String(err)}`, false);
    return { status: 'ko', errorMsg: 'Filtering failed: ' + (err?.message || String(err)) };
  }
}

function saveConfig(config: any) {
  ensureDirSync(pcapDir);
   const configFilePath = path.join(pcapDir, 'config.json');
  fsSync.writeFileSync(configFilePath, JSON.stringify(config, null, 2), 'utf-8');
  return configFilePath;
}

/**
 * Converts a config object to a Wireshark display filter string.
 * Supports multiple comma-separated values for each field.
 */
function buildWiresharkFilterFromConfig(config: any): string {
  const filters: string[] = [];

  // Helper to handle multiple values per field
  function multiFilter(field: string, cb: (val: string) => string): string | undefined {
    if (!config[field]) return undefined;
    const values = config[field].split(',').map((v: string) => v.trim()).filter(Boolean);
    if (values.length === 0) return undefined;
    return values.map(cb).join(' or ');
  }

  // IP address (src or dst)
  const ipFilter = multiFilter('ip', (ip) => `ip.addr == ${ip}`);
  if (ipFilter) filters.push(`(${ipFilter})`);

  // Port (tcp or udp)
  const portFilter = multiFilter('port', (port) => `(tcp.port == ${port} or udp.port == ${port})`);
  if (portFilter) filters.push(`(${portFilter})`);

  // Protocol (tcp, udp, icmp, etc.)
  const protocolFilter = multiFilter('protocol', (proto) => proto.toLowerCase());
  if (protocolFilter) filters.push(`(${protocolFilter})`);

  // Source IP
  const srcIpFilter = multiFilter('sourceIp', (ip) => `ip.src == ${ip}`);
  if (srcIpFilter) filters.push(`(${srcIpFilter})`);

  // Destination IP
  const dstIpFilter = multiFilter('destinationIp', (ip) => `ip.dst == ${ip}`);
  if (dstIpFilter) filters.push(`(${dstIpFilter})`);

  // Source Port
  const srcPortFilter = multiFilter('sourcePort', (port) => `(tcp.srcport == ${port} or udp.srcport == ${port})`);
  if (srcPortFilter) filters.push(`(${srcPortFilter})`);

  // Destination Port
  const dstPortFilter = multiFilter('destinationPort', (port) => `(tcp.dstport == ${port} or udp.dstport == ${port})`);
  if (dstPortFilter) filters.push(`(${dstPortFilter})`);

  // Packet size min/max
  if (config.packetSizeMin) {
    filters.push(`frame.len >= ${config.packetSizeMin}`);
  }
  if (config.packetSizeMax) {
    filters.push(`frame.len <= ${config.packetSizeMax}`);
  }

  // Time range
  if (config.timeRange) {
    const [start, end] = config.timeRange.split('/');
    if (start) filters.push(`frame.time >= "${start}"`);
    if (end) filters.push(`frame.time <= "${end}"`);
  }

  // TCP Flags
  const tcpFlagsFilter = multiFilter('tcpFlags', (flag) => `tcp.flags.${flag.toLowerCase()} == 1`);
  if (tcpFlagsFilter) filters.push(`(${tcpFlagsFilter})`);

  // Payload content
  const payloadContentFilter = multiFilter('payloadContent', (content) => `frame contains "${content}"`);
  if (payloadContentFilter) filters.push(`(${payloadContentFilter})`);

  // MAC address
  const macFilter = multiFilter('macAddress', (mac) => `eth.addr == ${mac}`);
  if (macFilter) filters.push(`(${macFilter})`);

  return filters.join(' and ');
}

// --- API Endpoints ---

app.get('/server-name/:containerName', (req: Request, res: Response): void => {
  const { containerName } = req.params;
  if (!containerNames.includes(containerName)) {
    containerNames.push(containerName);
    console.log(`Container name added: ${containerName}`);
  } else {
    console.log(`Container name already exists: ${containerName}`);
  }
  res.send(`Container name received: ${containerName}`);
});

app.get('/start', async (req: Request, res: Response): Promise<void> => {
  if (containerNames.length === 0) {
    res.status(400).send('No container names available to start.');
    return;
  }
  await clearOldPcaps(pcapDir);
  const results = await Promise.all(
    containerNames.map(async (containerName) => {
      try {
        const cmd = `http://${containerName}:3000/start`;
        await axios.get(cmd);
        logEvent('Monitoring started', `Command: ${cmd}`, true);
        return { containerName, status: 'success' };
      } catch (error) {
        logEvent('Monitoring started', `Command: http://${containerName}:3000/start`, false);
        return { containerName, status: 'failed' };
      }
    })
  );
  res.json({ message: 'Start signal sent to all scan dockers.', results });
});

app.get('/stop', async (req: Request, res: Response): Promise<void> => {
  if (containerNames.length === 0) {
    res.status(400).send('No container names available to stop.');
    return;
  }
  const results = await Promise.all(
    containerNames.map(async (containerName) => {
      try {
        const cmd = `http://${containerName}:3000/stop`;
        await axios.get(cmd);
        logEvent('Monitoring stopped', `Command: ${cmd}`, true);
        return { containerName, status: 'success' };
      } catch (error) {
        logEvent('Monitoring stopped', `Command: http://${containerName}:3000/stop`, false);
        return { containerName, status: 'failed' };
      }
    })
  );
  await new Promise((resolve) => setTimeout(resolve, 5000));
  const mergedPcapFile = path.join(pcapDir, 'merged.pcap');
  const jsonOutputFile = path.join(pcapDir, 'output.json');
  try {
    await mergePcaps(pcapDir, mergedPcapFile);
    await pcapToJson(mergedPcapFile, jsonOutputFile);
    const config = getLatestConfig();
    let filterStatus: 'ok' | 'ko' | undefined = undefined;
    let filteredJsonData: any = undefined;
    let errorMsg: string | undefined = undefined;
    const jsonData = await fs.readFile(jsonOutputFile, 'utf-8');
    if (config) {
      const filterString = buildWiresharkFilterFromConfig(config);
      const filterResult = await filterPcapAndJson(mergedPcapFile, filterString, pcapDir);
      filterStatus = filterResult.status;
      filteredJsonData = filterResult.filteredJsonData;
      errorMsg = filterResult.errorMsg;
    }
    logEvent('Monitoring stopped', `Output: ${jsonOutputFile}`, true);
    res.json({
      message: 'Stop signal sent to all scan dockers.',
      results,
      pcapData: filteredJsonData || JSON.parse(jsonData),
      filterStatus,
      error: filterStatus === 'ko' ? errorMsg : undefined
    });
  } catch (error: any) {
    logEvent('Monitoring stopped', `Error: ${error.message || 'Failed to process pcap files.'}`, false);
    res.status(500).send(error.message || 'Failed to process pcap files.');
  }
});

app.post('/config', async (req: Request, res: Response): Promise<void> => {
  const config = req.body;
  if (!config) {
    res.status(400).json({ message: 'Invalid configuration data' });
    return;
  }
  try {
    saveConfig(config);
    const mergedPcapFile = path.join(pcapDir, 'merged.pcap');
    const jsonOutputFile = path.join(pcapDir, 'output.json');

    let filteredJsonData: any = undefined;
    let filterStatus: 'ok' | 'ko' = 'ko';
    let errorMsg: string | undefined = undefined;
    if (fsSync.existsSync(mergedPcapFile)) {
      const filterString = buildWiresharkFilterFromConfig(config);
      const filterResult = await filterPcapAndJson(mergedPcapFile, filterString, pcapDir);
      filterStatus = filterResult.status;
      filteredJsonData = filterResult.filteredJsonData;
      errorMsg = filterResult.errorMsg;
    }
    if (filterStatus === 'ok' && filteredJsonData) {
      logEvent('Filtering', `Output: filtered.json`, true);
      res.status(200).json({ message: 'Configuration saved and filtering succeeded', pcapData: filteredJsonData });
    } else if (filterStatus === 'ko') {
      logEvent('Filtering', `Output: filtered.json`, false);
      res.status(422).json({ message: 'Configuration saved but filtering failed', error: errorMsg });
    } else {
      res.status(200).json({ message: 'Configuration saved successfully (no merged.pcap to filter yet)' });
    }
  } catch (error: any) {
    logEvent('Filtering', `Error: ${error?.message || 'Failed to save configuration'}`, false);
    res.status(500).json({ message: 'Failed to save configuration' });
  }
});

app.get('/cleanConf', async (req: Request, res: Response): Promise<void> => {
  try {
    // Remove config.json and filtered files
    const filesToRemove = ['config.json', 'filtered.pcap', 'filtered.json'];
    for (const file of filesToRemove) {
      const filePath = path.join(pcapDir, file);
      if (fsSync.existsSync(filePath)) {
        await fs.unlink(filePath);
      }
    }
    res.status(200).json({ message: 'Config and filtered files cleaned.' });
  } catch (err: any) {
    res.status(500).json({ message: 'Failed to clean files', error: err?.message || String(err) });
  }
});

app.get('/test', (req: Request, res: Response): void => {
  res.send('Server is running and reachable.');
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});


export default app;