// This is the main application module
//
// Copyright (c) 2025, Kyle Mestery
//

mod api;

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

        // Methods to get stats for API
        pub fn get_total_requests(&self) -> usize {
            self.total_requests
        }

        pub fn get_requests_by_domain(&self) -> &HashMap<String, usize> {
            &self.requests_by_domain
        }
    }

    // Simple command line argument parsing
    #[derive(Debug)]
    pub struct Args {
        pub debug: bool,
        pub api_port: u16,
    }

    impl Args {
        pub fn parse() -> Self {
            let mut debug = false;
            let mut api_port = 9090; // Default API port

            // Check for command line arguments
            let args: Vec<String> = std::env::args().collect();
            for i in 0..args.len() {
                if args[i] == "--debug" || args[i] == "-d" {
                    debug = true;
                }
                if args[i] == "--api-port" && i + 1 < args.len() {
                    api_port = args[i + 1].parse().unwrap_or(9090);
                }
            }

            Args { debug, api_port }
        }
    }

    // Function to print final statistics
    fn print_final_stats(stats: &Stats) {
        println!("\n--- Final DNS Statistics ---");
        println!("Total requests: {}", stats.total_requests);

        // Print top domains
        let mut domains: Vec<_> = stats.requests_by_domain.iter().collect();
        domains.sort_by(|a, b| b.1.cmp(a.1));
        println!("Top domains:");
        for (domain, count) in domains.iter().take(5) {
            println!("  {}: {} requests", domain, count);
        }
    }

    // Function to start the API server
    pub fn start_api_server(stats: Arc<Mutex<Stats>>, port: u16) {
        // Import the API filter from api.rs
        let api_filter = crate::api::api_filter(stats);

        // Start the server in a separate thread
        println!("Starting API server on port {}", port);
        std::thread::spawn(move || {
            // Use tokio runtime to run the warp server
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                warp::serve(api_filter)
                    .run(([127, 0, 0, 1], port))
                    .await;
            });
        });
    }



    pub fn main() {
        let args = Args::parse();

        println!("DNS Interceptor - Starting...");
        if args.debug {
            println!("Debug mode enabled - non-DNS packet messages will be hidden");
        }
        
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
        let running_for_stats = running.clone();
        let stats_thread = thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(5));

                // Check if we should still run
                if !running_for_stats.load(Ordering::SeqCst) {
                    break;
                }

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
        
        // Start API server in a separate thread
        let api_stats = Arc::clone(&stats);
        let api_port = args.api_port;
        let _api_thread = thread::spawn(move || {
            start_api_server(api_stats, api_port);
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
                        if args.debug {
                            println!("Non-DNS packet received: {} bytes", packet.data.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }

        // Wait for stats thread to finish
        if let Err(e) = stats_thread.join() {
            eprintln!("Error joining stats thread: {:?}", e);
        }

        // Print final statistics
        let stats = stats.lock().unwrap();
        print_final_stats(&stats);
        println!("DNS Interceptor stopped.");
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
