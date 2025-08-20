# DNS Interceptor
[![Build Status](https://github.com/mestery/dns_interceptor/actions/workflows/build.yml/badge.svg)](https://github.com/mestery/dns_interceptor/actions/workflows/build.yml)

A simple DNS packet interceptor written in Rust that captures and analyzes DNS queries on your network.

## Features

- Captures DNS packets from network traffic
- Displays DNS query information in real-time
- Tracks statistics about DNS requests
- Graceful shutdown with Ctrl+C
- REST API for accessing DNS statistics

## Usage

To run the DNS interceptor:

```bash
 cargo run
```

To run with a custom API port:

```bash
 cargo run -- --api-port 9090
```

> Note: You may need to run with `sudo` privileges on some systems to capture network packets.

The program will capture DNS packets on the default network interface and display them in the console.

## API Endpoints

Once running, you can access statistics via these endpoints:

- `GET /stats` - Get all DNS statistics
- `GET /stats/total` - Get total request count
- `GET /stats/domains` - Get domain request counts

Example usage with curl:

```bash
curl http://localhost:9090/stats
```

## How It Works

1. Uses `pcap` crate to capture network packets
2. Parses DNS packets using `dns-parser` crate
3. Displays DNS queries with source IP and port
4. Tracks statistics about domain requests
5. Shows top domains every 5 seconds

## Requirements

- Rust (stable version)
- libpcap development libraries

On macOS:
```bash
brew install libpcap
```

On Ubuntu/Debian:
```bash
sudo apt-get install libpcap-dev
```

On CentOS/RHEL/Fedora:
```bash
sudo yum install libpcap-devel
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
