#include <iostream>
#include <vector>

class linux_scanner
{
public:
    linux_scanner(const std::string& target_host_or_ip, std::vector<int> ports_to_scan, const int timeout_ms);

    std::string resolve_target(const std::string& hostname);

    void scan();
    void scan_single_port(const int& port);
    void scan_multiple_ports(const std::vector<int> ports_to_scan);
    
private:
    std::string target_host_or_ip;
    std::vector<int> ports_to_scan;
    std::vector<int> open_ports;
    int timeout_ms;
    bool is_scanning_initiated;
};