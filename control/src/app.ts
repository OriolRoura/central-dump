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
import axios from 'axios'; // Add this import for making HTTP requests
import { exec } from 'child_process';
import path from 'path';
import fs from 'fs/promises';
import cors from 'cors'; // Import the cors package

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS for all routes

const port = 3000;

const containerNames: string[] = [];

// Endpoint to listen for container names and save them in an array
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

// Endpoint to send a start signal to all scan dockers
app.get('/start', async (req: Request, res: Response): Promise<void> => {
  if (containerNames.length === 0) {
    res.status(400).send('No container names available to start.');
    return;
  }

  const results = await Promise.all(
    containerNames.map(async (containerName) => {
      try {
        const response = await axios.get(`http://${containerName}:3000/start`);
        console.log(`Start signal sent to container: ${containerName}, Response: ${response.status}`);
        return { containerName, status: 'success' };
      } catch (error) {
        console.error(`Failed to send start signal to container: ${containerName}, Error: ${(error as Error).message}`);
        return { containerName, status: 'failed' };
      }
    })
  );

  res.json({ message: 'Start signal sent to all scan dockers.', results });
});

// Endpoint to send a stop signal to all scan dockers
app.get('/stop', async (req: Request, res: Response): Promise<void> => {
  if (containerNames.length === 0) {
    res.status(400).send('No container names available to stop.');
    return;
  }

  const results = await Promise.all(
    containerNames.map(async (containerName) => {
      try {
        const response = await axios.get(`http://${containerName}:3000/stop`);
        console.log(`Stop signal sent to container: ${containerName}, Response: ${response.status}`);
        return { containerName, status: 'success' };
      } catch (error) {
        console.error(`Failed to send stop signal to container: ${containerName}, Error: ${(error as Error).message}`);
        return { containerName, status: 'failed' };
      }
    })
  );
  // wait for 5 seconds before merging pcap files
  await new Promise((resolve) => setTimeout(resolve, 5000));
  
  // Directory where pcap files are stored
  const pcapDir = '/data';
  const mergedPcapFile = path.join(pcapDir, 'merged.pcap');
  const jsonOutputFile = path.join(pcapDir, 'output.json');

  try {
    // rmmove existing merged pcap file if it exists
    await fs.rm(mergedPcapFile, { force: true });
  // Get all .pcap files in the directory
  const pcapFiles = (await fs.readdir(pcapDir))
    .filter((file) => file.endsWith('.pcap'))
    .map((file) => path.join(pcapDir, file));

  if (pcapFiles.length === 0) {
    console.log('No .pcap files found to merge.');
    res.status(400).send('No .pcap files found to merge.');
    return;
  }

  // Merge .pcap files using mergecap
  await new Promise((resolve, reject) => {
    const mergecapCommand = `mergecap -w ${mergedPcapFile} ${pcapFiles.join(' ')}`;
    exec(mergecapCommand, (error, stdout, stderr) => {
      if (error) {
        console.error('Error merging pcap files:', stderr || error.message);
        return reject(error);
      }
      console.log('Pcap files merged successfully using mergecap.');
      resolve(null);
    });
  });

  // Convert merged pcap file to JSON
  await new Promise((resolve, reject) => {
    exec(`tshark -r ${mergedPcapFile} -T json > ${jsonOutputFile}`, (error) => {
      if (error) {
        console.error('Error converting pcap to JSON:', error.message);
        return reject(error);
      }
      console.log('Pcap file converted to JSON successfully.');
      resolve(null);
    });
  });


    // Read and send the JSON output
    const jsonData = await fs.readFile(jsonOutputFile, 'utf-8');
    res.json({ message: 'Stop signal sent to all scan dockers.', results, pcapData: JSON.parse(jsonData) });
  } catch (error) {
    if (error instanceof Error) {
      console.error('Error processing pcap files:', error.message);
    } else {
      console.error('Error processing pcap files:', error);
    }
    res.status(500).send('Failed to process pcap files.');
  }
});

// Test endpoint to verify server functionality
app.get('/test', (req: Request, res: Response): void => {
  res.send('Server is running and reachable.');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});


