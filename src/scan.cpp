// PRE-DEFINED
#include <iostream>
// CUSTOM
#include "../include/linux_scanner.hpp"

void print_invalid_usage(const char* argv)
{
    std::cerr << "Usage: " << argv << " <target_ip/domain_name> </CIDR> [-p ports] [-t time-out] -tc\n";
    std::cerr << "< ! IMPORTANT ! > If you type domain name, you should specify /32 CIDR value !!\n"; 
    std::cerr << "Instances:\n";
    std::cerr << " - " << argv << " 192.168.1.1 /16 -p 22,80,100 -t 1000 tcp_connect\n";
    std::cerr << " - " << argv << " 172.16.1.1 /12 -p 1-65535 -t 500 tcp_syn\n";
    std::cerr << " - " << argv << " google.com /32 -p 1-65535 -t 500 udp\n";
    std::cerr << "Time-out: in milliseconds (as default: 1000ms).\n";
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
#ifdef __linux__
    if (argc < 8)
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
    std::string scan_type = argv[7];

    if (_p != "-p")
    {
        std::cerr << "Invalid Usage !!\n";
        return 1;
    }

    if (_t != "-t")
    {
        std::cerr << "Invalid Usage !!\n";
        return 1;
    }

    if (ip_or_host.empty() || ports.empty() || CIDR.empty() || timeout_ms.empty() || scan_type.empty()) 
    { 
        std::cerr << "You have to enter correct inputs !!\n";
        return 1; 
    }
    
    int timeout_ms_int = stoi(timeout_ms);
    linux_scanner _linux_scanner(ip_or_host, ports, CIDR, scan_type, timeout_ms_int);
    _linux_scanner.scan();
#elif
    std::cerr << "Operating System that you use cannot suitable with this program !!\n";
    std::cerr << "Please try it again on any LINUX DISTRO !!\n";
#endif

    return 0;
}

//  ./scan scanme.nmap.org /32 -p 21,22,53,80,443 -t 1000 -tc