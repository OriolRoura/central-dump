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
}

async function mergePcaps(dir: string, mergedPcapFile: string) {
  await fs.rm(mergedPcapFile, { force: true });
  const pcapFiles = (await fs.readdir(dir))
    .filter((file:any) => file.endsWith('.pcap'))
    .map((file:any) => path.join(dir, file));
  if (pcapFiles.length === 0) throw new Error('No .pcap files found to merge.');
  await new Promise((resolve, reject) => {
    const mergecapCommand = `mergecap -w ${mergedPcapFile} ${pcapFiles.join(' ')}`;
    exec(mergecapCommand, (error:any) => {
      if (error) return reject(error);
      resolve(null);
    });
  });
}

async function pcapToJson(pcapFile: string, jsonFile: string) {
  await new Promise((resolve, reject) => {
    exec(`tshark -r ${pcapFile} -T json > ${jsonFile}`, (error) => {
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
    await new Promise((resolve, reject) => {
      const filterCmd = filterString
        ? `tshark -r ${mergedPcapFile} -Y "${filterString}" -w ${filteredPcapFile}`
        : `cp ${mergedPcapFile} ${filteredPcapFile}`;
      exec(filterCmd, (error:any) => {
        if (error) return reject(error);
        resolve(null);
      });
    });
    await pcapToJson(filteredPcapFile, filteredJsonFile);
    if (fsSync.existsSync(filteredJsonFile)) {
      const filteredJsonData = JSON.parse(fsSync.readFileSync(filteredJsonFile, 'utf-8'));
      return { status: 'ok', filteredJsonData };
    } else {
      return { status: 'ko', errorMsg: 'Filtered JSON file not found after filtering.' };
    }
  } catch (err: any) {
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
 * Only non-empty fields are included.
 */
function buildWiresharkFilterFromConfig(config: any): string {
  const filters: string[] = [];

  if (config.ip) {
    filters.push(`ip.addr == ${config.ip}`);
  }
  if (config.port) {
    filters.push(`tcp.port == ${config.port} || udp.port == ${config.port}`);
  }
  if (config.packetType) {
    const types = config.packetType.split(',').map((t: string) => t.trim().toLowerCase());
    if (types.includes('tcp')) filters.push('tcp');
    if (types.includes('udp')) filters.push('udp');
    // Add more types if needed
  }
  if (config.protocol) {
    filters.push(config.protocol.toLowerCase());
  }
  if (config.sourceIp) {
    filters.push(`ip.src == ${config.sourceIp}`);
  }
  if (config.destinationIp) {
    filters.push(`ip.dst == ${config.destinationIp}`);
  }
  if (config.sourcePort) {
    filters.push(`tcp.srcport == ${config.sourcePort} || udp.srcport == ${config.sourcePort}`);
  }
  if (config.destinationPort) {
    filters.push(`tcp.dstport == ${config.destinationPort} || udp.dstport == ${config.destinationPort}`);
  }
  if (config.packetSizeMin) {
    filters.push(`frame.len >= ${config.packetSizeMin}`);
  }
  if (config.packetSizeMax) {
    filters.push(`frame.len <= ${config.packetSizeMax}`);
  }
  if (config.timeRange) {
    // Wireshark filter for time is not direct, but you can use frame.time >=/<= if available
    const [start, end] = config.timeRange.split('/');
    if (start) filters.push(`frame.time >= "${start}"`);
    if (end) filters.push(`frame.time <= "${end}"`);
  }
  if (config.tcpFlags) {
    // Example: SYN, ACK
    const flags = config.tcpFlags.split(',').map((f: string) => f.trim().toUpperCase());
    flags.forEach(flag => {
      filters.push(`tcp.flags.${flag.toLowerCase()} == 1`);
    });
  }
  if (config.payloadContent) {
    // Wireshark filter for payload content (simple contains)
    filters.push(`frame contains "${config.payloadContent}"`);
  }
  if (config.macAddress) {
    filters.push(`eth.addr == ${config.macAddress}`);
  }

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
        await axios.get(`http://${containerName}:3000/start`);
        return { containerName, status: 'success' };
      } catch (error) {
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
        await axios.get(`http://${containerName}:3000/stop`);
        return { containerName, status: 'success' };
      } catch (error) {
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
    res.json({
      message: 'Stop signal sent to all scan dockers.',
      results,
      pcapData: filteredJsonData || JSON.parse(jsonData),
      filterStatus,
      error: filterStatus === 'ko' ? errorMsg : undefined
    });
  } catch (error: any) {
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
      res.status(200).json({ message: 'Configuration saved and filtering succeeded', pcapData: filteredJsonData });
    } else if (filterStatus === 'ko') {
      res.status(200).json({ message: 'Configuration saved but filtering failed', error: errorMsg });
    } else {
      res.status(200).json({ message: 'Configuration saved successfully (no merged.pcap to filter yet)' });
    }
  } catch (error) {
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


