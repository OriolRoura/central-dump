
### Build the Docker Images

Build the Docker images for the control and scan services:
```bash
docker build -t project-dump-control -f control/dockerfile control
docker build -t project-dump-scan -f scan/dockerfile scan
```

### Start the System

define the correct path on volume scan_shared_volume

Start the system using Docker Compose:
```bash
docker-compose up -d
```

Verify that the services are running:
- **Control service**: Accessible at `http://localhost:3000/test`.

To stop the system, use:
```bash
docker-compose down
```

## Usage

### Starting and Stopping Monitoring

To start monitoring, ensure Docker Compose is running:
```bash
docker-compose up -d
```

To stop monitoring, use:
```bash
docker-compose down
```

### Starting and Stopping Scanning

To start scanning, send a `GET` request to the `/start` endpoint of the control service:
```bash
curl http://localhost:3000/start
```

This will send a start signal to all scan services, initiating the `tcpdump` process in each container.

To stop scanning, send a `GET` request to the `/stop` endpoint of the control service:
```bash
curl http://localhost:3000/stop
```

This will stop the `tcpdump` process in all scan services, merge the captured `.pcap` files, and convert the merged file into a JSON format for analysis.

## System Overview

This system is designed to monitor network traffic across multiple Docker containers. It uses `tcpdump` to capture packets from specific ports and merges the captured data for analysis. The system consists of:
1. **Control Service**: Manages and communicates with scan services, sends start/stop signals, and merges packet capture files.
2. **Scan Services**: Runs `tcpdump` to capture network traffic from specific containers.

