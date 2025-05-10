// PRE-DEFINED
#include <iostream>
// CUSTOM
#include "../include/linux_scanner.hpp"

void print_invalid_usage(const char* argv)
{
    std::cerr << "Usage: " << argv << " <target_ip> </CIDR> [-p ports] [-t time-out]" << std::endl;
    std::cerr << "Instances:" << std::endl;
    std::cerr << " - " << argv << " 192.168.1.1 /16 -p 22,80,100-200" << std::endl;
    std::cerr << " - " << argv << " 192.168.1.1 /16 -p 1-65535 -t 500" << std::endl;
    std::cerr << " - " << argv << " 192.168.1.1 >>>>> !! If any ports do not specify as input, most popular ports are scanned. " << std::endl;
    std::cerr << "Time-out: in milliseconds (as default: 1000ms)." << std::endl;
}

std::vector<std::string> split_input_to_usable(int argc, char* argv[])
{
    std::vector<std::string> output{};

    for (size_t i = 1; i < argc; i += 2)
    {
        output.push_back(argv[i]);
    }
    
    return output;
}

int main(int argc, char *argv[]) 
{
    if (argc < 7)
    {
        print_invalid_usage(argv[0]);   
        return 1;
    }

    std::string ip_or_host = argv[1];
    std::string CIDR = argv[2];
    std::string _p = argv[3];
    std::string ports = argv[4];
    std::string _t = argv[5];
    std::string timeout_ms = argv[6];

    if (_p != "-p")
    {
        throw std::invalid_argument("Invalid Usage !!\n");
        return 1;
    }

    if (_t != "-t")
    {
        throw std::invalid_argument("Invalid Usage !!\n");
        return 1;
    }
    
    /* for(int i = 0; i < argc; i++)
    {
        std::cout << argv[i] << std::endl;
    }*/ 

    /* 
    for (const auto port : ports_to_scan)
    {
        std::cout << "-" << port << "-" << std::endl;
    } 
    */
    
#ifdef __linux__
    if (ip_or_host.empty() || ports.empty() || CIDR.empty() || timeout_ms.empty()) { return 1; }
    
    int timeout_ms_int = stoi(timeout_ms);
    linux_scanner _linux_scanner(ip_or_host, ports, CIDR, timeout_ms_int);
    _linux_scanner.scan();

#endif
    return 0;
}