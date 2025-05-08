#include "../include/linux_scanner.hpp"

    
linux_scanner::linux_scanner(const std::string& target_host_or_ip, std::vector<int> ports_to_scan, const int timeout_ms)  : 
    target_host_or_ip(target_host_or_ip),
    timeout_ms(timeout_ms),
    is_scanning_initiated(false)
{
    if (target_host_or_ip.empty())
    {
        throw std::invalid_argument("Target IP or Port Range is invalid !!\n");
        exit(1);
    }

    if (timeout_ms <= 0)
    {
        throw std::invalid_argument("Time-out must be a positive value !!\n");
        exit(1);
    }

    if (ports_to_scan.empty())
    {
        throw std::invalid_argument("Port information is not provided !!\n");
        exit(1);
    }
    
    this->ports_to_scan = std::move(ports_to_scan);
}

std::string linux_scanner::resolve_target(const std::string& hostname)
{
    return "";
}

void linux_scanner::scan_single_port(const int& port) 
{

}

void linux_scanner::scan_multiple_ports(const std::vector<int> ports_to_scan) 
{
    for (const int port : ports_to_scan) 
    {
        scan_single_port(port); 
    }
}

void linux_scanner::scan() 
{
    if (is_scanning_initiated)
    {
        std::cerr << "Scanning is also initiated !!\n";
        return;
    }

    is_scanning_initiated = true;
    open_ports.clear();
}