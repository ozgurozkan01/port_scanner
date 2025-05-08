// PRE-DEFINED
#include <iostream>
// CUSTOM
#include "../include/linux_scanner.hpp"
#include "../include/input_validator.hpp"

void print_invalid_usage(const char* argv)
{
    std::cerr << "Usage: " << argv << " <target_ip> [-p ports] [-t time-out]" << std::endl;
    std::cerr << "Instances:" << std::endl;
    std::cerr << " - " << argv << " 192.168.1.1 -p 22,80,100-200" << std::endl;
    std::cerr << " - " << argv << " 192.168.1.1 -p 1-65535 -t 500" << std::endl;
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
    if (argc < 6)
    {
        print_invalid_usage(argv[0]);   
        return 1;
    }

    std::string ip_or_host = argv[1];
    std::string _p = argv[2];
    std::string protocols = argv[3];
    std::string _t = argv[4];
    int timeout_ms = atoi(argv[5]);

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
    
    for(int i = 0; i < argc; i++)
    {
        std::cout << argv[i] << std::endl;
    }

    target_type tt = classify_target_type(ip_or_host);

    if (tt == target_type::invalid_format)
    {
        throw std::invalid_argument("Target is not classified correctly !!\n");
        return 1;
    }

    std::vector<int> ports_to_scan = parse_ports_string_to_list(protocols);
    
    if (ports_to_scan.empty())
    {
        std::cout << "Port container is empty!!\n";
    }
    

    for (const auto port : ports_to_scan)
    {
        std::cout << "-" << port << "-" << std::endl;
    }
    
    return 0;
}