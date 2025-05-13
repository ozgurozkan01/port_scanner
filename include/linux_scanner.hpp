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
    domain_name,
    invalid_format
};

class linux_scanner
{
public:
    linux_scanner(const std::string& target_host_or_ip, const std::string& ports, const std::string& CIDR_string, const int timeout_ms);

    void scan();
    void scan_localhost_network(); 
    void scan_internal_network();  
    void scan_external_network();  

    std::string resolve_domainname_to_ip(const std::string& hostname); 
    bool static_ip_string_to_uint32(const char* static_ip_str, uint32_t& out_ip_numeric);

    ip_range_type classify_ip_range_type();
    target_type classify_target_type(const std::string& target);
    

    struct in_addr ipv4_addr_target;

    std::vector<int> ports_to_scan;
    std::vector<int> open_ports;

    std::string target_host_or_ip;
    int timeout_ms;
    int CIDR;
    bool is_scanning_initiated;

    target_type _target_type;
    ip_range_type _ip_range_type;
};