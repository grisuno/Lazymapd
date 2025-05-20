use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{self, Read, Write};
use std::process;
use std::str;
use std::fs::File;
use rayon::prelude::*;
use clap::{Arg, App, ArgMatches};


const DEFAULT_TIMEOUT: u64 = 1000;
const FAST_TIMEOUT: u64 = 150;
const DEFAULT_CHUNK_SIZE: usize = 2048;

#[derive(Debug, Clone)]
enum ScanMode {
    Fast,      
    Detailed,  
}

#[derive(Debug, Clone)]
struct ScanConfig {
    target_ip: Ipv4Addr,
    ports: Vec<u16>,
    mode: ScanMode,
    timeout: Duration,
    spoof_ip: Option<Ipv4Addr>,
    threads: Option<usize>,
    output_file: Option<String>,
}

fn main() {
    let app = App::new("lazymap")
        .version("0.0.1")
        .author("LazyOwn Red Team")
        .about("Port scanner with banner grabbing")
        .arg(Arg::with_name("target")
            .help("Target IP address")
            .required(true)
            .index(1))
        .arg(Arg::with_name("ports")
            .short("p")
            .long("ports")
            .value_name("PORTS")
            .help("Ports to scam (ex: 80,443,1-1000)")
            .takes_value(true))
        .arg(Arg::with_name("syn_scan")
            .short("s")
            .long("syn")
            .help("SYN tcp port scan"))
        .arg(Arg::with_name("version_scan")
            .short("v")
            .long("version")
            .help("Version detection scan"))
        .arg(Arg::with_name("all_ports")
            .short("A")
            .long("all")
            .help("Scan all ports (1-65535)"))
        .arg(Arg::with_name("top_ports")
            .short("T")
            .long("top")
            .value_name("NUM")
            .help("Scan the most common ports (default: 100)")
            .takes_value(true))
        .arg(Arg::with_name("timeout")
            .short("t")
            .long("timeout")
            .value_name("MS")
            .help("Timeout in milisecs (default: 1000)")
            .takes_value(true))
        .arg(Arg::with_name("spoof")
            .long("spoof-source")
            .value_name("IP")
            .help("Spoofing IP")
            .takes_value(true))
        .arg(Arg::with_name("threads")
            .long("max-threads")
            .value_name("NUM")
            .help("Max number of threads")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("FILE")
            .help("Save output CSV")
            .takes_value(true));

    let matches = app.get_matches();
    let config = match parse_config(&matches) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };
    print_banner(&config);
    match config.mode {
        ScanMode::Fast => run_fast_scan(&config),
        ScanMode::Detailed => run_detailed_scan(&config),
    }
}

fn parse_config(matches: &ArgMatches) -> Result<ScanConfig, String> {
    
    let target_ip = matches.value_of("target")
        .ok_or("IP target required")?
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IP")?;

    
    let mode = if matches.is_present("version_scan") {
        ScanMode::Detailed
    } else {
        ScanMode::Fast
    };

    
    let ports = if matches.is_present("all_ports") {
        (1..=65535).collect()
    } else if let Some(top_ports) = matches.value_of("top_ports") {
        let n: usize = top_ports.parse()
            .map_err(|_| "Invalid number of ports")?;
        get_top_ports(n)
    } else if let Some(port_spec) = matches.value_of("ports") {
        parse_port_spec(port_spec)?
    } else {
        
        get_top_ports(100)
    };

    
    let timeout_ms = if let Some(timeout_str) = matches.value_of("timeout") {
        timeout_str.parse::<u64>()
            .map_err(|_| "Invalid Timeout")?
    } else {
        match mode {
            ScanMode::Fast => FAST_TIMEOUT,
            ScanMode::Detailed => DEFAULT_TIMEOUT,
        }
    };

    
    let spoof_ip = if let Some(spoof_str) = matches.value_of("spoof") {
        Some(spoof_str.parse::<Ipv4Addr>()
            .map_err(|_| "Invalid IP spoofing")?)
    } else {
        None
    };

    
    let threads = if let Some(threads_str) = matches.value_of("threads") {
        Some(threads_str.parse::<usize>()
            .map_err(|_| "Invalid number of threads")?)
    } else {
        None
    };

    
    let output_file = matches.value_of("output").map(|s| s.to_string());

    Ok(ScanConfig {
        target_ip,
        ports,
        mode,
        timeout: Duration::from_millis(timeout_ms),
        spoof_ip,
        threads,
        output_file,
    })
}

fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    
    for part in spec.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse()
                    .map_err(|_| format!("Invalid Port: {}", range[0]))?;
                let end: u16 = range[1].parse()
                    .map_err(|_| format!("Invalid Port: {}", range[1]))?;
                ports.extend(start..=end);
            } else {
                return Err(format!("Invalid Range: {}", part));
            }
        } else {
            let port: u16 = part.parse()
                .map_err(|_| format!("Invalid Port: {}", part))?;
            ports.push(port);
        }
    }
    
    Ok(ports)
}

fn get_top_ports(n: usize) -> Vec<u16> {
    
    let common_ports = vec![
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 993, 143, 53, 135, 3306, 8080,
        1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
        81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
        631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
        513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
        444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
        6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001,
        5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19,
        8031, 1041, 255, 1049, 1048, 2967, 1053, 3703, 1056, 1065, 1064, 1054,
    ];
    
    common_ports.into_iter().take(n).collect()
}

fn print_banner(config: &ScanConfig) {
    println!("lazymap 1.0.0 - Super Fast Port Scanner");
    println!("==========================================");
    println!("Target: {}", config.target_ip);
    println!("Ports: {} ports", config.ports.len());
    println!("Mode: {:?}", config.mode);
    println!("Timeout: {:?}", config.timeout);
    
    if let Some(spoof) = &config.spoof_ip {
        println!("Spoofing from: {}", spoof);
    }
    
    println!("==========================================");
    println!();
}

fn run_fast_scan(config: &ScanConfig) {
    println!("[+] Quick scan...");
    
    
    if let Some(threads) = config.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .unwrap();
    }

    let open_ports: Vec<u16> = config.ports
        .par_iter()
        .with_min_len(DEFAULT_CHUNK_SIZE)
        .filter_map(|&port| {
            let socket = SocketAddr::new(config.target_ip.into(), port);
            match TcpStream::connect_timeout(&socket, config.timeout) {
                Ok(_) => {
                    print!(".");
                    io::stdout().flush().unwrap();
                    Some(port)
                },
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => None,
                Err(_) => None,
            }
        })
        .collect();

    println!(); 
    print_fast_results(&open_ports);
    
    
    if let Some(ref output_file) = config.output_file {
        save_fast_results_to_csv(&open_ports, &config.target_ip, output_file)
            .unwrap_or_else(|e| eprintln!("Error saving CSV: {}", e));
    }
}

fn run_detailed_scan(config: &ScanConfig) {
    println!("[+] Detailed Scaner...");
    
    
    if let Some(threads) = config.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .unwrap();
    }

    let results: Vec<(u16, String)> = config.ports
        .par_iter()
        .filter_map(|&port| {
            match grab_banner(&config.target_ip, port, config.timeout.as_millis() as u64) {
                Ok(banner) => {
                    println!("[+] Port {} analized", port);
                    Some((port, banner))
                },
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    eprintln!("[-] Port {}: timeout", port);
                    None
                },
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => None,
                Err(e) => {
                    eprintln!("[-] Port {}: error ({})", port, e);
                    None
                }
            }
        })
        .collect();

    print_detailed_results(&results);
    
    
    if let Some(ref output_file) = config.output_file {
        save_detailed_results_to_csv(&results, &config.target_ip, output_file)
            .unwrap_or_else(|e| eprintln!("Error saving CSV: {}", e));
    }
}

fn grab_banner(target: &Ipv4Addr, port: u16, timeout_ms: u64) -> io::Result<String> {
    let socket = SocketAddr::new((*target).into(), port);
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_millis(timeout_ms))?;
    
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let payload = get_protocol_payload(port);
    
    if let Err(e) = stream.write(payload) {
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(e);
        }
    }

    let mut buffer = [0; 2048];
    match stream.read(&mut buffer) {
        Ok(size) if size > 0 => Ok(process_response(port, &buffer[..size])),
        Ok(_) => Ok(format!("Service on port {} (no response)", port)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(format!("Service on port {} (no response)", port))
            } else {
                Err(e)
            }
        }
    }
}

fn get_protocol_payload(port: u16) -> &'static [u8] {
    match port {
        // HTTP
        80 | 8080 | 8000 | 8008 | 8081 => b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: lazymap/1.0\r\nAccept: */*\r\n\r\n",
        
        // HTTPS
        443 | 8443 => b"\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03",
        
        // SSH
        22 => b"SSH-2.0-lazymap\r\n",
        
        // FTP
        21 => b"USER anonymous\r\nPASS lazymap\r\n",
        
        // SMTP
        25 | 587 | 465 => b"EHLO localhost\r\n",
        
        // POP3
        110 | 995 => b"USER test\r\n",
        
        // IMAP
        143 | 993 => b"A001 CAPABILITY\r\n",
        
        // DNS
        53 => b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        
        // MySQL
        3306 => b"\x85\xa6\xff\x01\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        
        // PostgreSQL
        5432 => b"\x00\x00\x00\x08\x04\xd2\x16/",
        
        // Redis
        6379 => b"PING\r\n",
        
        // MongoDB
        27017 => b"\x3f\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00",
        
        // Telnet
        23 => b"\xff\xfe\x01\xff\xfe\x1f\xff\xfe\x20\xff\xfe\x21",
        
        // SNMP
        161 => b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63",
        
        // LDAP
        389 | 636 => b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        
        // Ollama
        11434 => b"GET /api/tags HTTP/1.1\r\nHost: localhost\r\n\r\n",
        
        // Servicios comunes sin respuesta esperada
        4444 | 4443 | 4567 | 4848 | 9999 => b"\r\n\r\n",
        
        // Intento genérico para otros puertos
        _ => b"\r\n",
    }
}

fn process_response(port: u16, response: &[u8]) -> String {
    let raw_response = str::from_utf8(response).unwrap_or("").trim();
    
    match port {
        // HTTP/HTTPS
        80 | 8080 | 8000 | 8008 | 8081 | 443 | 8443 => {
            if raw_response.contains("HTTP/") {
                if let Some(server_header) = raw_response.lines()
                    .find(|line| line.to_lowercase().starts_with("server:"))
                {
                    return server_header.to_string();
                }
                return raw_response.lines().next().unwrap_or("HTTP Service").to_string();
            }
            "Web Service".to_string()
        },
        
        // SSH
        22 => {
            if raw_response.starts_with("SSH-") {
                return raw_response.split_whitespace().next().unwrap_or("SSH Service").to_string();
            }
            "SSH Service".to_string()
        },
        
        // FTP
        21 => {
            if raw_response.starts_with("220") {
                return raw_response.splitn(2, ' ').nth(1).unwrap_or("FTP Service").to_string();
            }
            "FTP Service".to_string()
        },
        
        // SMTP
        25 | 587 | 465 => {
            if raw_response.starts_with("220") {
                return raw_response.splitn(2, ' ').nth(1).unwrap_or("SMTP Service").to_string();
            }
            "SMTP Service".to_string()
        },
        
        // POP3
        110 | 995 => {
            if raw_response.starts_with("+OK") {
                return raw_response.splitn(2, ' ').nth(1).unwrap_or("POP3 Service").to_string();
            }
            "POP3 Service".to_string()
        },
        
        // MySQL
        3306 => {
            if response.len() > 5 && response[4] == 0x0a {
                "MySQL Service".to_string()
            } else {
                "Database Service".to_string()
            }
        },
        
        // Redis
        6379 => {
            if raw_response.starts_with("+PONG") {
                "Redis Service".to_string()
            } else {
                "Key-Value Store".to_string()
            }
        },
        
        // Procesamiento genérico
        _ => {
            if raw_response.is_empty() {
                get_service_name(port)
            } else {
                let cleaned: String = raw_response.chars()
                    .take(100)
                    .filter(|c| c.is_ascii() && (!c.is_ascii_control() || *c == ' '))
                    .collect();
                if cleaned.trim().is_empty() {
                    get_service_name(port)
                } else {
                    cleaned.trim().to_string()
                }
            }
        }
    }
}

fn get_service_name(port: u16) -> String {
    match port {
        23 => "Telnet".to_string(),
        53 => "DNS".to_string(),
        135 => "MS-RPC".to_string(),
        139 => "NetBIOS".to_string(),
        389 => "LDAP".to_string(),
        445 => "SMB".to_string(),
        993 => "IMAPS".to_string(),
        995 => "POP3S".to_string(),
        1433 => "MS-SQL".to_string(),
        1521 => "Oracle DB".to_string(),
        3389 => "RDP".to_string(),
        5432 => "PostgreSQL".to_string(),
        5900 => "VNC".to_string(),
        6379 => "Redis".to_string(),
        27017 => "MongoDB".to_string(),
        _ => format!("Unknown service on port {}", port),
    }
}

fn print_fast_results(ports: &[u16]) {
    if ports.is_empty() {
        println!("\n[!] Not Lucky! No open ports found");
        return;
    }

    println!("\n[+] Open ports found:");
    println!("{:-<40}", "");
    
    for (i, port) in ports.iter().enumerate() {
        if i % 10 == 0 && i > 0 {
            println!();
        }
        print!("{:<6}", port);
    }
    
    println!("\n{:-<40}", "");
    println!("Total: {} open ports", ports.len());
}

fn print_detailed_results(results: &[(u16, String)]) {
    if results.is_empty() {
        println!("\n[!] Not lucky! No open services found");
        return;
    }

    println!("\n[+] Results:");
    println!("{:-<70}", "");
    println!("{:<8} {:<25} {:<35}", "PORT", "SERVICE", "DETAILS");
    println!("{:-<70}", "");
    
    for (port, banner) in results {
        let service = get_service_name(*port);
        println!("{:<8} {:<25} {:<35}", port, service, banner);
    }
    
    println!("{:-<70}", "");
    println!("Total: {} servicios detectados", results.len());
}

fn save_fast_results_to_csv(ports: &[u16], target_ip: &Ipv4Addr, filename: &str) -> io::Result<()> {
    let mut file = File::create(filename)?;
    
    writeln!(file, "target_ip,port,status")?;
    
    for port in ports {
        writeln!(file, "{},{},open", target_ip, port)?;
    }
    
    println!("[+] Results saved in {}", filename);
    Ok(())
}

fn save_detailed_results_to_csv(results: &[(u16, String)], target_ip: &Ipv4Addr, filename: &str) -> io::Result<()> {
    let mut file = File::create(filename)?;
    
    writeln!(file, "target_ip,port,status,service,banner")?;
    
    for (port, banner) in results {
        let service = get_service_name(*port);

        let escaped_banner = banner.replace("\"", "\"\"");
        writeln!(file, "{},{},open,\"{}\",\"{}\"", target_ip, port, service, escaped_banner)?;
    }
    
    println!("[+] Results saved in {}", filename);
    Ok(())
}
