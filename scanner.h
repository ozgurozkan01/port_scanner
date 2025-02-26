#include <cstdlib>
#include <iostream>
#include <vector>
#include <cstdint>

enum class scan_type : uint8_t
{
    tcp_connect,
    tcp_syn,
    udp_scan
};

void scan(const std::vector<std::string>& target_ip_list, int start_port, int end_port, ScanType scanType);
std::vector<std::string> resolve_ip(const std::string& ip);
scan_type scan_type_resolver_by_index(int index);

void udp_scan(const std::string& target_ip, int port_number);
void tcp_syn_scan(const std::string& target_ip, int port_number);
void tcp_connect_scan(const std::string& target_ip, int port_number);