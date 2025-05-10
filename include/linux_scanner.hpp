#include <iostream>
#include <vector>
#include <cstdint>
#include <netinet/in.h>
enum class ip_range_type : uint8_t
{
    localhost,
    private_ip,
    public_ip,
    reserved_unusable,
    invalid_ip
};

enum class target_type : uint8_t

{
    ip_v4_format,
    hostname_format,
    invalid_format
};

class linux_scanner
{
public:
    linux_scanner(const std::string& target_host_or_ip, const std::string& ports, const std::string& CIDR_string, const int timeout_ms);

    void scan();
    
    // 127.0.0.0    /8
    void scan_localhost_network(); 
    // 10.0.0.0     /8
    // 172.16.0.0   /12
    // 192.168.0.0  /16
    void scan_internal_network();  
    // Others
    void scan_external_network();  

    bool static_ip_string_to_uint32(const char* static_ip_str, uint32_t& out_ip_numeric);

    ip_range_type classify_ip_range_type();
    target_type classify_target_type(const std::string& target);
    
    std::string target_host_or_ip;
    struct in_addr ipv4_addr_target;
    int CIDR;
    std::vector<int> ports_to_scan;
    std::vector<int> open_ports;
    int timeout_ms;
    bool is_scanning_initiated;
};