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

void scan(const std::string& target_ip, const int& start_port, const int& end_port)
{
    for (int port_number = start_port; port_number < end_port; port_number++)
    {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
        if (sock == -1)
        {
            std::cerr << "Socket could be created: ";
            continue;
        }

        // Network protocols uses Big-Endian (MSB is first) style. 
        // IPv4 addressing structure
        sockaddr_in server_address;
        server_address.sin_family = AF_INET; // socketaddr_in family
        server_address.sin_port   = htons(port_number); 

        if (inet_pton(AF_INET, target_ip.c_str(), &server_address.sin_addr) <= 0)
        {
            std::cerr << "Invalid IP address !!!\n";
            close(sock);
            return;
        }
        
        
        std::cout << "\nOpening Ports\n";

        if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) == 0) 
        {
            struct servent* service = getservbyport(server_address.sin_port, NULL);
            std::cout << "Port " << port_number << " ( " << service->s_name << " )\n";
        }

        close(sock);
    }
}

void take_inputs(std::string& ip, int& start_port, int& end_port)
{
    std::cout << "Target IP: " << std::flush;
    std::cin >> ip;

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