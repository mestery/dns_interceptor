# DNS Interceptor

A simple DNS packet interceptor written in Rust that captures and analyzes DNS queries on your network.

## Features

- Captures DNS packets from network traffic
- Displays DNS query information in real-time
- Tracks statistics about DNS requests
- Graceful shutdown with Ctrl+C

## Usage

To run the DNS interceptor:

```bash
 cargo run
```

> Note: You may need to run with `sudo` privileges on some systems to capture network packets.

The program will capture DNS packets on the default network interface and display them in the console.

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