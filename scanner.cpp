#include "scanner.h"
#include "resolver.h"

#include <sys/socket.h>
#include <arpa/inet.h>  // provides functions for converting IP addresses from text to binary format.
#include <netinet/in.h> // contains definitions for internet operations, including data structures used in network programming.
#include <unistd.h>
#include <netdb.h>
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <cstring>
#include <netinet/tcp.h>

void tcp_connect_scan(const std::string& target_ip, int port_number) 
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) 
    {
        std::cerr << "[-] Socket creation failed.\n";
        return;
    }

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port   = htons(port_number);
    inet_pton(AF_INET, target_ip.c_str(), &server_address.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) == 0) 
    {
        struct servent* service = getservbyport(htons(port_number), "tcp");

        if (service) 
        {
            std::cout << "[+] Port " << port_number << " is open (" << service->s_name << ")\n";
        }
        else 
        {
            std::cout << "[+] Port " << port_number << " is open (Unknown Service)\n";
        }
    }

    close(sock);
}

void tcp_syn_scan(const std::string& target_ip, int port_number) 
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) 
    {
        perror("[-] Raw socket creation failed");
        return;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port_number);
    inet_pton(AF_INET, target_ip.c_str(), &target.sin_addr);

    char packet[sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct tcphdr *tcp = (struct tcphdr *) packet;
    tcp->source = htons(54321);  // Rastgele kaynak portu
    tcp->dest = htons(port_number);
    tcp->syn = 1;  // SYN bayrağını aç
    tcp->doff = 5;

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&target, sizeof(target)) < 0) 
    {
        perror("[-] Packet send failed");
    } 
    else 
    {
        std::cout << "[*] SYN Packet Sent to " << target_ip << ":" << port_number << std::endl;
    }

    close(sock);
}

void udp_scan(const std::string& target_ip, int port_number) 
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) 
    {
        perror("[-] UDP socket creation failed");
        return;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port_number);
    inet_pton(AF_INET, target_ip.c_str(), &target.sin_addr);

    char message[] = "Hello";
    if (sendto(sock, message, sizeof(message), 0, (struct sockaddr*)&target, sizeof(target)) < 0) 
    {
        perror("[-] UDP Packet send failed");
    } 
    else 
    {
        std::cout << "[*] UDP Packet Sent to " << target_ip << ":" << port_number << std::endl;
    }

    close(sock);
}


void scan(const std::vector<std::string>& target_ip_list, int start_port, int end_port, scan_type scan_type) 
{
    if (target_ip_list.empty()) 
    {
        std::cout << "Target IP list is empty!" << std::endl;
        exit(-1);
    }

    std::cout << "\nScanning Ports...\n";

    for (const auto& target_ip : target_ip_list) 
    {
        std::cout << "\nTarget: " << target_ip << "\n";

        for (int port_number = start_port; port_number <= end_port; port_number++) 
        {
            if (scan_type == scan_type::tcp_connect) 
            {
                tcp_connect_scan(target_ip, port_number);
            } 
            else if (scan_type == scan_type::tcp_syn) 
            {
                tcp_syn_scan(target_ip, port_number);
            }
            else if (scan_type == scan_type::tcp_connect)
            {
                udp_scan(target_ip, port_number);
            }
        }
    }
    std::cout << "\nScan complete!\n";
}


std::vector<std::string> resolve_ip(const std::string& ip)
{
    if (is_valid_ip(ip))
    {
        std::cout << ip << " formatı geçerli!" << std::endl;
        return std::vector<std::string>{ip};
    }
    
    else if (is_valid_wildcard_format(ip))
    {
        std::cout << ip << " formatı geçerli!" << std::endl;
        std::vector<std::string> expanded_ip_list = expand_wildcard_ip(ip);
        return expanded_ip_list;
    }

    else if (is_valid_range_format(ip)) 
    {
        std::vector<std::string> ips = get_ips_from_range(ip);
        return ips;
    } 
    
    else
    {
        std::vector<std::string> ips = get_two_ips(ip);

        if (!ips.empty()) 
        {
            return ips;
        } 
        else 
        {
            std::cout << ip << " formatı geçersiz!" << std::endl;
            std::cerr << "--- Mümkün Formatlar --- " << std::endl;
            std::cerr << "2-) 192.168.0.1    -> scan single IP" << std::endl;
            std::cerr << "2-) 192.168.0.*    -> scan all IPs in range" << std::endl;
            std::cerr << "3-) 192.168.0.1-10 -> scan IPs in range 192.168.0.1 - 192.168.0.10 (10 values)" << std::endl;
            std::cerr << "4-) 192.168.0.10 192.168.0.20 -> scan just 2 IPs" << std::endl;
            exit(-1);
        }
    }
}

scan_type scan_type_resolver_by_index(int index)
{
    switch (index) 
    {
        case 1: return scan_type::tcp_connect;
        case 2: return scan_type::tcp_syn;
        case 3: return scan_type::udp_scan;
    }
}