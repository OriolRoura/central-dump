/**
 * @file app.ts
 * @description This file contains the implementation of an Express server that manages tcpdump processes
 * and communicates with a control server to log the current Docker container name.
 * 
 * @dependencies
 * - express: Web framework for Node.js
 * - child_process: To execute shell commands
 * - axios: For making HTTP requests
 * 
 * @usage
 * - Start the server: `node app.js`
 * - Endpoints:
 *   - GET /start: Starts the tcpdump process
 *   - GET /stop: Stops the tcpdump process
 * 
 * @note Ensure the required environment variables and permissions are set for tcpdump to work.
 */

import express, { Request, Response } from 'express';
import { exec, ChildProcess } from 'child_process';
import axios from 'axios'; // Add axios for HTTP requests

var containerName = '';
// Log the current Docker container name and send it to the control server
exec('cat /etc/hostname', (error, stdout, stderr) => {
  if (error) {
    console.error(`Error retrieving container name: ${error.message}`);
    return;
  }
  if (stderr) {
    console.error(`Error: ${stderr}`);
    return;
  }
  containerName = stdout.trim();
  console.log(`Current Docker container name: ${containerName}`);

  // Wait 5 seconds before sending the container name to the control server
  setTimeout(() => {
    axios
      .get(`http://control:3000/server-name/${containerName}`)
      .then(() => {
        console.log(`Successfully sent container name to control server.`);
      })
      .catch((err) => {
        console.error(`Failed to send container name to control server: ${err.message}`);
      });
  }, 5000);
});

const app = express();
app.use(express.json());
const port = 3000;

const tcpdumpPort = process.env.TCPDUMP_PORT || '80'; // Get tcpdump port from environment variable or default to 80
console.log(`tcpdump port: ${tcpdumpPort}`);
let tcpdumpProcess: ChildProcess | null = null;

// Endpoint to start tcpdump
app.get('/start', (req: Request, res: Response): void => {
    if (tcpdumpProcess) {
        res.status(400).send('tcpdump is already running.');
        return;
    }

    try {
        tcpdumpProcess = exec(`tcpdump -v -s 0 dst port ${tcpdumpPort} -w /data/dumpfile_${containerName}.pcap`, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error: ${error.message}`);
            }
            if (stderr) {
                console.error(`Stderr: ${stderr}`);
            }
            console.log(`tcpdump started on port ${tcpdumpPort} with full packet capture.`);
            console.log(`Stdout: ${stdout}`);
        });

        res.send('tcpdump started.');
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to start tcpdump.');
    }
});

// Endpoint to stop tcpdump
app.get('/stop', (req: Request, res: Response): void => {
    if (!tcpdumpProcess) {
        res.status(400).send('tcpdump is not running.');
        return;
    }

    try {

        // Properly terminate the tcpdump process
        tcpdumpProcess.kill('SIGINT');
        tcpdumpProcess = null;

        res.send('tcpdump stopped.');
    } catch (err) {
        console.error(err);
        res.status(500).send('Failed to stop tcpdump.');
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});