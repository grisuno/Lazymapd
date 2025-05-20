# Lazymapd

![image](https://github.com/user-attachments/assets/5a7026de-143d-4b26-b46e-f4961c2bd647)

## Description

Lazymapd is a fast and efficient port scanner with banner grabbing functionality, written in Rust by the LazyOwn Red Team. It allows you to quickly identify open ports on a target IP address and, in detailed mode, attempts to grab service banners to identify running applications.

## Features

* **Target Specification:** Scan a specific target IP address.
* **Port Scanning Options:**
    * Scan specific ports (e.g., `80,443,1-1000`).
    * Perform a SYN TCP port scan.
    * Perform a version detection scan (banner grabbing).
    * Scan all 65535 ports.
    * Scan the top N most common ports (default: 100).
* **Timeout Configuration:** Set a custom timeout in milliseconds for connections.
* **Source IP Spoofing:** Spoof the source IP address for scanning.
* **Thread Control:** Specify the maximum number of threads to use for scanning.
* **Output to CSV:** Save the scan results in a CSV file.
* **Fast Scan:** Quickly identify open ports.
* **Detailed Scan:** Perform banner grabbing to detect service versions.

## Installation

1.  **Install Rust:** If you haven't already, you'll need to install Rust and Cargo (the Rust package manager). You can find installation instructions on the official Rust website: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/grisuno/Lazymapd.git](https://github.com/grisuno/Lazymapd.git)
    cd Lazymapd
    ```

3.  **Build the Project:**
    ```bash
    ./install.sh # or
    cargo build --release
    ```
    The compiled executable will be located in the `target/release` directory.

## Usage

Navigate to the `target/release` directory after building the project. You can then run `lazymap` with various options.

**Basic Scan (Top 100 Ports):**


```bash
./target/release/lazymapd --help
lazymap 0.0.1
LazyOwn Red Team
Port scanner with banner grabbing

USAGE:
    lazymapd [FLAGS] [OPTIONS] <target>

FLAGS:
    -A, --all        Scan all ports (1-65535)
    -h, --help       Prints help information
    -s, --syn        SYN tcp port scan
    -v, --version    Version detection scan

OPTIONS:
    -o, --output <FILE>        Save output CSV
    -p, --ports <PORTS>        Ports to scam (ex: 80,443,1-1000)
        --spoof-source <IP>    Spoofing IP
        --max-threads <NUM>    Max number of threads
    -t, --timeout <MS>         Timeout in milisecs (default: 1000)
    -T, --top <NUM>            Scan the most common ports (default: 100)

ARGS:
    <target>    Target IP address

```
Replace <target_ip> with the IP address of the target you want to scan.

Scanning Specific Ports:

```Bash

./lazymap <target_ip> -p 80,443,21,22,1000-1050
```
This command will scan ports 80, 443, 21, 22, and the range from 1000 to 1050.

Performing a Version Detection Scan (Banner Grabbing):

```Bash

./lazymap <target_ip> -v
```
Scanning All Ports:

```Bash

./lazymap <target_ip> -A
```
Scanning the Top 500 Ports:

```Bash

./lazymap <target_ip> -T 500
```
Setting a Custom Timeout (e.g., 500 milliseconds):

```Bash

./lazymap <target_ip> -t 500
```
Spoofing the Source IP Address:

```Bash

./lazymap <target_ip> --spoof-source <spoof_ip>
```
Replace <spoof_ip> with the IP address you want to use for spoofing.

Setting the Maximum Number of Threads:

```Bash

./lazymap <target_ip> --max-threads 50
```
Saving the Output to a CSV File:

```Bash

./lazymap <target_ip> -o results.csv
```
This will save the scan results to a file named results.csv.

## Combining Options:

You can combine multiple options as needed:

```bash
./lazymap <target_ip> -p 80,443 -v -t 2000 -o detailed_results.csv
Command-Line Arguments
Argument	Short	Long	Value Name	Description	Default Value (if applicable)
<target>			IP	Target IP address	Required
--ports <PORTS>	-p	--ports	PORTS	Ports to scan (e.g., 80,443,1-1000)	Top 100 common ports
--syn	-s	--syn		Perform SYN TCP port scan	
--version	-v	--version		Version detection scan (banner grabbing)	
--all	-A	--all		Scan all ports (1-65535)	
--top <NUM>	-T	--top	NUM	Scan the most common ports (default: 100)	100
--timeout <MS>	-t	--timeout	MS	Timeout in milliseconds	1000 (Detailed), 150 (Fast)
--spoof-source <IP>		--spoof-source	IP	Spoofing IP address	None
--max-threads <NUM>		--max-threads	NUM	Maximum number of threads to use	Determined by system
--output <FILE>	-o	--output	FILE	Save output to a CSV file	None

Exportar a Hojas de cálculo
Output
The output of lazymap will be displayed in the console.

Fast Scan Output:

For fast scans, the output will list the open ports found on the target.

lazymap 1.0.0 - Super Fast Port Scanner
==========================================
Target: 127.0.0.1
Ports: 100 ports
Mode: Fast
Timeout: 150ms
==========================================

[+] Quick scan...
......
[+] Open ports found:
----------------------------------------
22    80
----------------------------------------
Total: 2 open ports
Detailed Scan Output:

For detailed scans, the output will include the port number, the detected service name, and any banner information retrieved.

lazymap 1.0.0 - Super Fast Port Scanner
==========================================
Target: 127.0.0.1
Ports: 100 ports
Mode: Detailed
Timeout: 1s
==========================================

[+] Detailed Scaner...
[+] Port 80 analized
[+] Port 22 analized

[+] Results:
----------------------------------------------------------------------
PORT     SERVICE                  DETAILS
----------------------------------------------------------------------
80       Web Service              Server: Apache/2.4.59 (Debian)
22       SSH Service              SSH-2.0-OpenSSH_9.6p1 Debian-1
----------------------------------------------------------------------
Total: 2 servicios detectados
CSV Output:

If the -o option is used, the results will be saved to a CSV file.
```
## Fast Scan CSV Format:

### Fragmento de código
```bash
target_ip,port,status
<target_ip>,<port>,open
Detailed Scan CSV Format:
```
### Fragmento de código
```bash
target_ip,port,status,service,banner
<target_ip>,<port>,open,"<service_name>","<banner_information>"
```
## Contributing
Contributions are welcome! Please feel free to submit issues and pull requests on the GitHub repository.

## Author
LazyOwn Red Team

## License

This project is licensed under the MIT License. Feel free to use and modify it according to the terms of the license.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
