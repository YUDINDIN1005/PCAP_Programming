# PCAP_Programming
TCP Packet Sniffer using PCAP Library

This repository contains a simple TCP packet sniffer implemented in C using the PCAP library.
The program captures and analyzes TCP packet, specifically focusing on HTTP traffic.
It demonstrates how to utilize the PCAP library for packet capturing and decoding network protocols.

Features:
- Capture and display TCP packets
- Analyze HTTP requests and responses
- Print source and destination IP/MAC addresses
- Filter packets by port

This project is intended for educational purposes and to assist in understading network programming and packet analysis.

## How to Run
1. **Create the File**: Create the `tcp_sniff.c` file.
2. **Compile**: Use the following command to compile the program:
     ```bash
     gcc -o tcp_sniff tcp_sniff.c -lpcap
3. **Run**: Once compiled, run the program using:
   ```bash
   sudo ./tcp_sniff
4. **Test in Browser**: Open Firefox and enter http://www.example.com as an example.  
   Make sure to use the HTTP protocol, as HTTPS is encrypted and will make it difficult to see the HTTP messages in the capture.  
   ![스크린샷 2025-04-06 033746](https://github.com/user-attachments/assets/e6fdaed9-9f2b-4807-8a15-0f2d1a0261f0)  
   *An example using HTTPS.*
