#include <iostream>
#include <cstring>
#include <cerrno>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>  // provides functions for converting IP addresses from text to binary format.
#include <netinet/in.h> // contains definitions for internet operations, including data structures used in network programming.
#include <unistd.h>
#include <netdb.h>
#include "resolver.h"

void scan(const std::string& target_ip, const int& start_port, const int& end_port)
{
    std::cout << "\nOpening Ports\n";
    for (int port_number = start_port; port_number < end_port; port_number++)
    {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
        if (sock == -1)
        {
            std::cerr << "Socket could be created: ";
            continue;
        }

        sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_port   = htons(port_number); 

        if (inet_pton(AF_INET, target_ip.c_str(), &server_address.sin_addr) <= 0)
        {
            std::cerr << "Invalid IP address !!!\n";
            close(sock);
            return;
        }
        if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) == 0) 
        {
            struct servent* service = getservbyport(server_address.sin_port, NULL);
            std::cout << "Port " << port_number << " ( " << service->s_name << " )\n";
        }

        close(sock);
    }
}

void resolve_ip(const std::string& ip)
{
    if (is_valid_ip(ip))
    {
        std::cout << ip << " formatı geçerli!" << std::endl;
    }
    
    else if (is_valid_wildcard_format(ip))
    {
        std::cout << ip << " formatı geçerli!" << std::endl;
        std::vector<std::string> expanded_ip_list = expand_wildcard_ip(ip);

        for (const auto& ip : expanded_ip_list)
        {
            std::cout << ip << std::endl;
        }
    }

    else if (is_valid_range_format(ip)) 
    {
        std::vector<std::string> ips = get_ips_from_range(ip);
        
        std::cout << "Geçerli IP'ler:" << std::endl;
        for (const auto& ip : ips) 
        {
            std::cout << ip << std::endl;
        }
    } 
    
    else
    {
        std::vector<std::string> ips = get_two_ips(ip);

        if (!ips.empty()) 
        {
            std::cout << "Girilen 2 IP:" << std::endl;
            for (const auto& ip : ips) 
            {
                std::cout << ip << std::endl;
            }
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

void take_inputs(std::string& ip, int& start_port, int& end_port)
{
    std::cout << "Target IP: " << std::flush;
    std::cin >> ip;

    resolve_ip(ip);

    std::cout << "Start Port: " << std::flush;
    std::cin >> start_port;
    
    std::cout << "End Port: " << std::flush;
    std::cin >> end_port;
}

void print_port_scanner(const std::string& text) 
{
    std::cout << "\n";

    std::vector<std::string> ascii_lines =
    {
        " PPPP   OOO    RRRR   TTTTT       SSSSS  CCCCC   A    N   N  N   N  EEEEE  RRRR  ",
        " P   P  O  O   R   R    T    ---  S      C      A A   NN  N  NN  N  E      R   R ",
        " PPPP   O  O   RRRR     T    ---  SSSSS  C      AAAA  N N N  N N N  EEEE   RRRR  ",
        " P      O  O   R  R     T    ---      S  C      A  A  N  NN  N  NN  E      R  R  ",
        " P      OOO    R   R    T         SSSSS  CCCCC  A  A  N   N  N   N  EEEEE  R   R "
    };

    for (auto line : ascii_lines)
    {
        std::cout << line << std::endl;
    }

    std::cout << "\n";
}


int main()
{
    print_port_scanner("PORT SCANNER");

    std::string target_ip;
    int start_port;
    int end_port;

    take_inputs(target_ip, start_port, end_port);
    scan(target_ip, start_port, end_port);

    return 0;
}   