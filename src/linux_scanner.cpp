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
        throw std::invalid_argument("Time-out must be a positive value !!\n");
    }

    if (!is_CIDR_valid(CIDR_string)) 
    {
        throw std::invalid_argument("CIDR is invalid !!\n");
    }

    CIDR = stoi(CIDR_string.substr(1)); 

    target_type tt = classify_target_type(target_host_or_ip);

    if (tt == target_type::invalid_format) 
    {
        throw std::invalid_argument("Target '" + this->target_host_or_ip + "' is not a valid IPv4 or hostname.");
    }

    if (tt == target_type::ip_v4_format) 
    {
        if (inet_pton(AF_INET, this->target_host_or_ip.c_str(), &this->ipv4_addr_target) != 1) 
        {
            throw std::runtime_error("Failed to convert IP string to binary: " + this->target_host_or_ip);
        }
    } 
    else 
    { 
        struct addrinfo hints, *res_list, *p;
        
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        int status = getaddrinfo(this->target_host_or_ip.c_str(), nullptr, &hints, &res_list);
        
        if (status != 0)
        {
            throw std::runtime_error(std::string("Failed to resolve hostname '") + this->target_host_or_ip + "': " + gai_strerror(status));
        }
        
        bool found_ipv4 = false;
        
        for(p = res_list; p != NULL; p = p->ai_next) 
        {
            if (p->ai_family == AF_INET) 
            {
                struct sockaddr_in* ipv4_saddr = (struct sockaddr_in*)p->ai_addr;
                this->ipv4_addr_target = ipv4_saddr->sin_addr;
                found_ipv4 = true;
                break;
            }
        }

        freeaddrinfo(res_list);
        
        if (!found_ipv4) 
        {
             std::runtime_error(std::string("No IPv4 address found for hostname: ") + this->target_host_or_ip);
        }
    }

    ports_to_scan = parse_ports_string_to_list(ports);
    
    if (ports_to_scan.empty())
    {
        throw std::invalid_argument("Port information is not provided !!\n");
    }
}

bool linux_scanner::static_ip_string_to_uint32(const char* static_ip_str, uint32_t& out_ip_numeric) 
{
        struct in_addr temp_addr;
        if (inet_pton(AF_INET, static_ip_str, &temp_addr) == 1) 
        {
            std::cout << " temp addr : " << temp_addr.s_addr << std::endl;
            out_ip_numeric = ntohl(temp_addr.s_addr);
            std::cout << "out ip numeric : " << out_ip_numeric << std::endl;
            return true;
        }

        std::cout << " temp addr : " << temp_addr.s_addr << std::endl;

        return false;
}

ip_range_type linux_scanner::classify_ip_range_type()
{
    uint32_t ip_numeric = ntohl(this->ipv4_addr_target.s_addr);

    auto is_in_cidr_block = [&](uint32_t addr_to_check, const char* network_base_str, int prefix_len)
    {
        uint32_t network_base_numeric;
        if (!static_ip_string_to_uint32(network_base_str, network_base_numeric))
        {
            return false;
        }
        if (prefix_len < 0 || prefix_len > 32) return false;
        if (prefix_len == 0) return true;
        uint32_t mask = (prefix_len == 32) ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - prefix_len));
        return (addr_to_check & mask) == (network_base_numeric & mask);
    };

    if (is_in_cidr_block(ip_numeric, "127.0.0.0", 8))
    {
        return ip_range_type::localhost;
    }

    if (this->CIDR >= 0 && this->CIDR <= 32) 
    { 
        if (this->CIDR <= 30) 
        { 
            uint32_t netmask_for_cidr;
            if (this->CIDR == 0) 
            {
                netmask_for_cidr = 0x00000000;
            } 
            else 
            {
                netmask_for_cidr = (0xFFFFFFFF << (32 - this->CIDR));
            }
            
            uint32_t network_address_for_cidr = ip_numeric & netmask_for_cidr;
            uint32_t broadcast_address_for_cidr = network_address_for_cidr | (~netmask_for_cidr);

            if (ip_numeric == network_address_for_cidr || ip_numeric == broadcast_address_for_cidr) 
            {
                return ip_range_type::reserved_unusable;
            }
        }
    } 
    else 
    {
        return ip_range_type::invalid_ip;
    }


    if (is_in_cidr_block(ip_numeric, "10.0.0.0", 8) ||
        is_in_cidr_block(ip_numeric, "172.16.0.0", 12) ||
        is_in_cidr_block(ip_numeric, "192.168.0.0", 16)) 
    {
        return ip_range_type::private_ip;
    }

    if (is_in_cidr_block(ip_numeric, "0.0.0.0", 8))         return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "100.64.0.0", 10))     return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "169.254.0.0", 16))    return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "192.0.0.0", 24))      return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "192.0.2.0", 24))      return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "192.88.99.0", 24))    return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "198.18.0.0", 15))     return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "198.51.100.0", 24))   return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "203.0.113.0", 24))    return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "224.0.0.0", 4))       return ip_range_type::reserved_unusable;
    if (is_in_cidr_block(ip_numeric, "240.0.0.0", 4))       return ip_range_type::reserved_unusable;
    if (ip_numeric == 0xFFFFFFFF)                           return ip_range_type::reserved_unusable; // 255.255.255.255

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

    ip_range_type range_type = classify_ip_range_type();

    switch (range_type)
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
    if      (is_target_ip_v4(target))    { std::cout << "IP V4 FORMAT : " << target << "\n"; return target_type::ip_v4_format; }
    else if (is_target_hostname(target)) { std::cout << "HOSTNAME FORMAT : " << target << "\n"; return target_type::hostname_format; }

    std::cout << "INVALID FORMAT : " << target << "\n"; 
    return target_type::invalid_format;
}