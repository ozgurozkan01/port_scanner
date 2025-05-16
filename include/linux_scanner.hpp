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
    domain_name_format,
    invalid_format
};

enum class scan_type : uint8_t
{
    tcp_connect,
    tcp_syn,
    tcp_ack,
    tcp_fin,
    udp,
    invalid
};

enum class port_statu : uint8_t
{
    open,
    close,
    filtered,
    unknown 
};

struct port_info
{
    uint16_t number;
    port_statu statu;
    std::string service_name;
    std::string info; 
};

struct scan_target
{
    std::string target_str;                 // "127.0.0.1", "192.168.1.1", "google.com"
    struct in_addr ipv4_addr;               // resolved IP 
    std::vector<port_info> ports_to_scan;
    std::vector<port_info> open_ports;
};

struct tcp_checksum_header
{
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t place_holder;
    uint8_t protocol_field;
    uint16_t tcp_length;
};

class linux_scanner
{
public:
    linux_scanner(const std::string& target_host_or_ip, const std::string& ports, const std::string& CIDR_string, const std::string& scan_type, const int timeout_ms);

    void scan();
    void scan_localhost_network();
    void scan_internal_network();
    void scan_external_network();

    // TCP CONNECTION SCANNING
    void tcp_connect_scan();
    // TCP SYN SCANNING
    void tcp_syn_scan();
    uint16_t calculate_checksum(const char* buffer, const uint32_t size);
    uint16_t calculate_tcp_checksum(const char* buffer, const uint32_t size);

    void tcp_ack_scan();
    void tcp_fin_scan();
    void udp_scan();

    std::string get_port_statu(port_statu statu);
    std::string resolve_domainname_to_ip(const std::string& hostname); 
    bool static_ip_string_to_uint32(const char* static_ip_str, uint32_t& out_ip_numeric);

    ip_range_type classify_ip_range_type();
    target_type classify_target_type(const std::string& target);

    std::vector<uint16_t>input_port_list;

    int timeout_ms;
    int CIDR;
    bool is_scanning_initiated;

    scan_target _scan_target;

    ip_range_type _ip_range_type;
    scan_type _scan_type;
    target_type _target_type;
    tcp_checksum_header _tcp_checksum_header;
};