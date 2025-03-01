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
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include "resolver.h"
#include "scanner.h"

void take_inputs(std::vector<std::string>& ip_list,  std::string& ip, int& start_port, int& end_port)
{
    std::cout << "Target IP: " << std::flush;
    std::getline(std::cin, ip);

    ip_list = resolve_ip(ip);

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

    std::vector<std::string> ip_list;
    std::string target_ip;
    int start_port;
    int end_port;
    std::string choice;

    std::cout << "Select Scan Type:\n";
    std::cout << "1. TCP Connect Scan\n";
    std::cout << "2. TCP SYN Scan\n";
    std::cout << "3. UDP Scan\n";
    std::cout << "Enter choice: ";
    std::getline(std::cin, choice);

    take_inputs(ip_list, target_ip, start_port, end_port);
    scan(ip_list, start_port, end_port, scan_type_resolver_by_index(atoi(choice.c_str())));

    return 0;
}   