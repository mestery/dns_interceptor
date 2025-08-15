// This is the main application module
pub mod dns_interceptor {
    use pcap::{Capture};
    use dns_parser::{Packet as DnsPacket};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration};

    // Structure to hold DNS request information
    #[derive(Debug, Clone)]
    pub struct DnsRequest {
        pub query_name: String,
        pub source_ip: IpAddr,
        pub source_port: u16,
    }

    // Global statistics structure
    #[derive(Debug, Clone)]
    pub struct Stats {
        pub total_requests: usize,
        pub requests_by_domain: HashMap<String, usize>,
    }

    impl Stats {
        pub fn new() -> Self {
            Stats {
                total_requests: 0,
                requests_by_domain: HashMap::new(),
            }
        }
        
        pub fn increment_total(&mut self) {
            self.total_requests += 1;
        }
        
        pub fn add_request_by_domain(&mut self, domain: String) {
            *self.requests_by_domain.entry(domain).or_insert(0) += 1;
        }
    }

    pub fn main() {
        println!("DNS Interceptor - Starting...");
        
        // Create a capture object for the default interface
        let mut cap = Capture::from_device("en0")
            .unwrap()
            .immediate_mode(true)
            .open()
            .expect("Failed to open capture");
        
        // Create an atomic boolean for graceful shutdown
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        
        // Handle Ctrl+C gracefully
        ctrlc::set_handler(move || {
            println!("Shutting down...");
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        
        // Statistics tracking
        let stats = Arc::new(Mutex::new(Stats::new()));
        let stats_for_thread = Arc::clone(&stats);
        
        // Print statistics every 5 seconds
        let stats_thread = thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(5));
                let stats = stats_for_thread.lock().unwrap(); // Lock to read stat
                println!("\n--- DNS Statistics ---");
                println!("Total requests: {}", stats.total_requests);
                
                // Print top domains
                let mut domains: Vec<_> = stats.requests_by_domain.iter().collect();
                domains.sort_by(|a, b| b.1.cmp(a.1));
                println!("Top domains:");
                for (domain, count) in domains.iter().take(5) {
                    println!("  {}: {} requests", domain, count);
                }
            }
        });
        
        // Main packet processing loop
        while running.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    // Parse DNS packet
                    if let Some(dns_request) = parse_dns_packet(&packet.data) {
                        println!("DNS Request: {} from {}:{}.", dns_request.query_name, dns_request.source_ip, dns_request.source_port);
                        
                        // Update stats
                        let mut stats = stats.lock().unwrap(); // Lock to update stats
                        stats.increment_total();
                        stats.add_request_by_domain(dns_request.query_name);
                    } else {
                        println!("Non-DNS packet received: {} bytes", packet.data.len());
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
        
        // Wait for stats thread to finish
        stats_thread.join().unwrap();
    }

    fn parse_dns_packet(packet: &[u8]) -> Option<DnsRequest> {
        // Parse the DNS packet using dns-parser crate
        match DnsPacket::parse(packet) {
            Ok(dns_packet) => {
                // Check if it's a query (not a response)
                if dns_packet.header.query {
                    // Get the first question (query)
                    if let Some(question) = dns_packet.questions.first() {
                        return Some(DnsRequest {
                            query_name: question.qname.to_string(),
                            source_ip: std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
                            source_port: 53,
                        });
                    }
                }
            }
            Err(_) => {
                // If parsing fails, it's not a valid DNS packet
                return None;
            }
        }
        
        None
    }
}

fn main() {
    dns_interceptor::main();
}
