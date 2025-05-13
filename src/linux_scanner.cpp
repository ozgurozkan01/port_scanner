#include "../include/linux_scanner.hpp"
#include "../include/input_validator.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>

linux_scanner::linux_scanner(const std::string& target_host_or_ip, const std::string& ports, const std::string& CIDR_string,  const int timeout_ms) : 
    target_host_or_ip(target_host_or_ip),
    timeout_ms(timeout_ms)
{
    is_scanning_initiated = false;
    if (timeout_ms <= 0)
    {
        std::cerr << "Time-out must be a positive value !!\n";
        exit(1);
    }

    if (!is_CIDR_valid(CIDR_string)) 
    {
        std::cerr << "CIDR is invalid !!\n";
        exit(1);
    }

    CIDR = stoi(CIDR_string.substr(1)); 

    _target_type = classify_target_type(target_host_or_ip);

    if (_target_type == target_type::invalid_format) 
    {   
        std::cerr << "Target '" + this->target_host_or_ip + "' is not a valid IPv4 or domain-name.";
        exit(1);
    }

    else if (_target_type == target_type::ip_v4_format) 
    {
        if (inet_pton(AF_INET, this->target_host_or_ip.c_str(), &this->ipv4_addr_target) != 1) 
        {
            std::cerr << "Failed to convert IP string to binary: " + this->target_host_or_ip;
            exit(1);
        }

        _ip_range_type = classify_ip_range_type();
    } 
    else if (_target_type == target_type::domain_name)
    {
        std::string original_hostname = this->target_host_or_ip;
        std::string resolved_ip_str = resolve_domainname_to_ip(original_hostname);

        if (resolved_ip_str.empty())
        {
            std::cerr << "Hostname '" << original_hostname << "' could not be resolved to an IPv4 address!\n";
            exit(1);
        }
        std::cout << "Resolved " << original_hostname << " to IP: " << resolved_ip_str << std::endl;

        if (inet_pton(AF_INET, resolved_ip_str.c_str(), &this->ipv4_addr_target) != 1) 
        {
            std::cerr << "Internal error: Failed to convert resolved IP string '" << resolved_ip_str << "' to binary.\n";
            exit(1);
        }

        _ip_range_type = classify_ip_range_type();
    }

    ports_to_scan = parse_ports_string_to_list(ports);
    
    if (ports_to_scan.empty())
    {
        std::cerr << "Port information is not provided !!\n";
        exit(1);
    }
}

std::string linux_scanner::resolve_domainname_to_ip(const std::string& hostname)
{
    std::string resolved_ip = "";
    struct addrinfo hints;
    struct addrinfo *result_list, *p;
    int status;

    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result_list);
    if (status != 0) 
    {
        std::cerr << "getaddrinfo error for '" << hostname << "': " << gai_strerror(status) << std::endl;
        return resolved_ip;
    }

    for (p = result_list; p != nullptr; p = p->ai_next) 
    {
        if (p->ai_family == AF_INET) 
        {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            char ip_str_buffer[INET_ADDRSTRLEN];

            if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str_buffer, sizeof(ip_str_buffer)) != nullptr) 
            {
                resolved_ip = ip_str_buffer;
                break;
            }
            else
            {
                perror("inet_ntop error");
            }
        }
    }

    freeaddrinfo(result_list);

    return resolved_ip;
}

bool linux_scanner::static_ip_string_to_uint32(const char* static_ip_str, uint32_t& out_ip_numeric)
{
    struct in_addr temp_addr = {0};
    if (inet_pton(AF_INET, static_ip_str, &temp_addr) == 1)
    {
        out_ip_numeric = ntohl(temp_addr.s_addr);
        return true;
    }
    return false;
}

ip_range_type linux_scanner::classify_ip_range_type()
{
    // host byte order -> Little endian
    // network byte order -> Big endian
    uint32_t target_ip_numeric_H = ntohl(this->ipv4_addr_target.s_addr);

    uint32_t scan_range_netmask_H;
    if      (this->CIDR == 0)  { scan_range_netmask_H = 0x00000000; } 
    else if (this->CIDR == 32) { scan_range_netmask_H = 0xFFFFFFFF; } 
    else                       { scan_range_netmask_H = (0xFFFFFFFF << (32 - this->CIDR)); }

    uint32_t scan_range_network_addr_H = target_ip_numeric_H & scan_range_netmask_H;
    uint32_t scan_range_broadcast_addr_H = scan_range_network_addr_H | (~scan_range_netmask_H);

    uint32_t localhost_ip_numeric_H;

    static_ip_string_to_uint32("127.0.0.1", localhost_ip_numeric_H);

    if (target_ip_numeric_H == localhost_ip_numeric_H && this->CIDR == 32) 
    {
        return ip_range_type::localhost;
    }

    if (this->CIDR >= 0 && this->CIDR <= 32) 
    {
        if (this->CIDR < 31) 
        {
            if (target_ip_numeric_H == scan_range_network_addr_H || target_ip_numeric_H == scan_range_broadcast_addr_H)
            {
                std::cerr << "Tried to scan network or broadcast IP address...\n";
                return ip_range_type::reserved_unusable;
            }
        }
    } 
    else 
    {
        return ip_range_type::invalid_ip;
    }

    auto is_range_fully_contained_in_block =
        [&](uint32_t scan_start_H, uint32_t scan_end_H,
            const char* block_ip_str, int block_prefix) -> bool
    {
        uint32_t block_base_numeric_H;
        if (!static_ip_string_to_uint32(block_ip_str, block_base_numeric_H)) 
        {
            std::cerr << "Internal error: Could not convert static block IP: " << block_ip_str << std::endl;
            return false;
        }

        if (block_prefix < 0 || block_prefix > 32) return false;

        uint32_t block_netmask_H;
        if      (block_prefix == 0)  { block_netmask_H = 0x00000000; }
        else if (block_prefix == 32) { block_netmask_H = 0xFFFFFFFF; }
        else                         { block_netmask_H = (0xFFFFFFFF << (32 - block_prefix)); }

        uint32_t block_network_addr_H = block_base_numeric_H & block_netmask_H;
        uint32_t block_broadcast_addr_H = block_network_addr_H | (~block_netmask_H);

        return (scan_start_H >= block_network_addr_H) &&
               (scan_end_H <= block_broadcast_addr_H);
    };

    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "10.0.0.0", 8)    ||
        is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "172.16.0.0", 12) ||
        is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "192.168.0.0", 16))
    {
        return ip_range_type::private_ip;
    }

    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "0.0.0.0"     , 8))  return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "100.64.0.0"  , 10)) return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "127.0.0.0"   , 8))  return ip_range_type::reserved_unusable; // Loopback bloğu
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "169.254.0.0" , 16)) return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "192.0.0.0"   , 24)) return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "192.0.2.0"   , 24)) return ip_range_type::reserved_unusable; // TEST-NET-1
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "192.88.99.0" , 24)) return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "198.18.0.0"  , 15)) return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "198.51.100.0", 24)) return ip_range_type::reserved_unusable; // TEST-NET-2
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "203.0.113.0" , 24)) return ip_range_type::reserved_unusable; // TEST-NET-3
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "224.0.0.0"   , 4))  return ip_range_type::reserved_unusable; // Multicast
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "240.0.0.0"   , 4))  return ip_range_type::reserved_unusable; // Future use

    if (this->CIDR == 32 && target_ip_numeric_H == 0xFFFFFFFF) 
    {
        return ip_range_type::reserved_unusable;
    }
    
    return ip_range_type::public_ip;
} 

void linux_scanner::scan_localhost_network() {}
void linux_scanner::scan_internal_network()  {}
void linux_scanner::scan_external_network()  {}

void linux_scanner::scan()
{
    if (is_scanning_initiated)
    {
        std::cerr << "Scanning is also initiated !!\n";
        return;
    }

    is_scanning_initiated = true;
    open_ports.clear();

    switch (_ip_range_type)
    {
    case ip_range_type::localhost:
        std::cout << "Localhost is scanning...\n";
        scan_localhost_network();
        break;
    case ip_range_type::private_ip:
        std::cout << "Internal is scanning...\n";
        scan_internal_network();
        break;
    case ip_range_type::public_ip:
        std::cout << "External is scanning...\n";
        scan_external_network();
        break;
    case ip_range_type::reserved_unusable:
        std::cout << "You tried to scan network or broadcast IP address...\n";
        break;
    default:
        std::cerr << "This IP Range is not valid !!\n";
        exit(1);
    }
}

target_type linux_scanner::classify_target_type(const std::string& target)
{
    if      (is_target_ip_v4(target))    { std::cout << "IP V4 FORMAT       : "  << target << "\n"; return target_type::ip_v4_format; }
    else if (is_target_domainname(target, CIDR)) { std::cout << "DOMAIN NAME FORMAT : "  << target << "\n"; return target_type::domain_name;  }

    std::cout << "INVALID FORMAT : " << target << "\n"; 
    return target_type::invalid_format;
}