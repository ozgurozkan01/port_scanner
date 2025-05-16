#include "../include/linux_scanner.hpp"
#include "../include/input_validator.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

linux_scanner::linux_scanner(const std::string& target_host_or_ip, const std::string& ports, const std::string& CIDR_string, const std::string& scan_type, const int timeout_ms = 1000) : 
    timeout_ms(timeout_ms)
{
    _scan_target.target_str = target_host_or_ip;

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

    _target_type = classify_target_type(_scan_target.target_str);

    if (_target_type == target_type::invalid_format) 
    {   
        std::cerr << "Target '" + this->_scan_target.target_str + "' is not a valid IPv4 or domain-name.";
        exit(1);
    }

    else if (_target_type == target_type::ip_v4_format) 
    {
        if (inet_pton(AF_INET, this->_scan_target.target_str.c_str(), &this->_scan_target.ipv4_addr) != 1) 
        {
            std::cerr << "Failed to convert IP string to binary: " + this->_scan_target.target_str;
            exit(1);
        }

        _ip_range_type = classify_ip_range_type();
    } 
 
    else if (_target_type == target_type::domain_name_format)
    {
        std::string original_hostname = this->_scan_target.target_str;
        std::string resolved_ip_str = resolve_domainname_to_ip(original_hostname);

        if (resolved_ip_str.empty())
        {
            std::cerr << "Hostname '" << original_hostname << "' could not be resolved to an IPv4 address!\n";
            exit(1);
        }
        std::cout << "Resolved " << original_hostname << " to IP: " << resolved_ip_str << "\n";

        if (inet_pton(AF_INET, resolved_ip_str.c_str(), &this->_scan_target.ipv4_addr) != 1) 
        {
            std::cerr << "Internal error: Failed to convert resolved IP string '" << resolved_ip_str << "' to binary.\n";
            exit(1);
        }

        _ip_range_type = classify_ip_range_type();
    }

    input_port_list = parse_ports_string_to_list(ports);
    
    if (input_port_list.empty())
    {
        std::cerr << "Port information is not provided !!\n";
        exit(1);
    }

    for (auto port : input_port_list)
    {
        _scan_target.ports_to_scan.push_back({port, port_statu::unknown, "< NO DESCRIPTION >", "< NO NAME >"});
    }

    _scan_type == get_scan_type(scan_type);

    if (_scan_type == scan_type::invalid)
    {
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
        std::cerr << "getaddrinfo error for '" << hostname << "': " << gai_strerror(status) << "\n";
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
    uint32_t target_ip_numeric_H = ntohl(this->_scan_target.ipv4_addr.s_addr);

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
            std::cerr << "Internal error: Could not convert static block IP: " << block_ip_str << "\n";
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

    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "127.0.0.0"   , 8))  return ip_range_type::localhost; // Loopback bloğu
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "0.0.0.0"     , 8))  return ip_range_type::reserved_unusable;
    if (is_range_fully_contained_in_block(scan_range_network_addr_H, scan_range_broadcast_addr_H, "100.64.0.0"  , 10)) return ip_range_type::reserved_unusable;
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

void linux_scanner::scan()
{
    if (is_scanning_initiated)
    {
        std::cerr << "Scanning is also initiated !!\n";
        return;
    }

    is_scanning_initiated = true;
    // this->_scan_target.open_ports.clear();

    switch (_ip_range_type)
    {
    case ip_range_type::localhost:
        std::cout << "\n----- Localhost is scanning... -----\n\n";
        scan_localhost_network();
        break;
    case ip_range_type::private_ip:
        std::cout << "\n----- Internal is scanning... -----\n\n";
        scan_internal_network();
        break;
    case ip_range_type::public_ip:
        std::cout << "\n----- External is scanning... -----\n\n";
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
    else if (is_target_domainname(target, CIDR)) { std::cout << "DOMAIN NAME FORMAT : "  << target << "\n"; return target_type::domain_name_format;  }

    std::cout << "INVALID FORMAT : " << target << "\n"; 
    return target_type::invalid_format;
}

void linux_scanner::tcp_connect_scan()
{
    char ip_str_buffer[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &this->_scan_target.ipv4_addr, ip_str_buffer, sizeof(ip_str_buffer)) == nullptr)
    {
        perror("tcp_connect_scan: inet_ntop failed for target IP");
        return;
    }

    std::string current_target_ip_str(ip_str_buffer);

    std::cout << "\nInitiating TCP Connect Scan (-tc) for target: " << this->_scan_target.target_str << " (" << current_target_ip_str << ")\n";
    std::cout << "Timeout per port: " << this->timeout_ms << "ms\n";
    std::cout << "-----------------------------------------------------\n";
    std::cout << "PORT\tSTATE\tSERVICE (from scan)\n";
    std::cout << "-----------------------------------------------------\n";

    // _scan_target.open_ports.clear();

    for (auto port : this->_scan_target.ports_to_scan)
    {
        struct servent service_entry_data;
        struct servent *service_entry_result = nullptr;
        char service_buffer[1024];
        port.service_name = "unknown";
        if (getservbyport_r(htons(port.number), "tcp", &service_entry_data, service_buffer, sizeof(service_buffer), &service_entry_result) == 0 && service_entry_result != nullptr)
        {
            port.service_name = service_entry_result->s_name;
        }

        int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_fd < 0)
        {
            port.statu = port_statu::close;
            port.info = "Socket creation failed: " + std::string(strerror(errno));
            std::cout << port.number << "\t" << get_port_statu(port.statu) << "\t" << " " << port.info << "\n";
            continue;
        }

        struct sockaddr_in server_addr{0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port.number);
        server_addr.sin_addr = this->_scan_target.ipv4_addr;

        int get_flag = fcntl(sock_fd, F_GETFL, 0);
        if (get_flag == -1)
        {
            close(sock_fd);
            port.statu = port_statu::close;
            port.info = "fcntl(F_GETFL) failed: " + std::string(strerror(errno));
            std::cout << port.number << "\t" << get_port_statu(port.statu) << "\t" << " " << port.info << "\n";
            continue;
        }

        int set_flag = fcntl(sock_fd, F_SETFL, get_flag | O_NONBLOCK); 
        if (set_flag == -1)
        {
            close(sock_fd);
            port.statu = port_statu::close;
            port.info = "fcntl(O_NONBLOCK) failed: " + std::string(strerror(errno));
            std::cout << port.number << "\t" << get_port_statu(port.statu) << "\t" << " " << port.info << "\n";
            continue;
        }

        int connect_result = connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
        bool port_is_open_flag = false;

        if (connect_result == 0)
        {
            port_is_open_flag = true;
            port.info = "\tConnected: (immediate)";
        }
        else if (errno == EINPROGRESS)
        {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock_fd, &write_fds);

            struct timeval tv;
            tv.tv_sec = this->timeout_ms / 1000;
            tv.tv_usec = (this->timeout_ms % 1000) * 1000;

            int select_status = select(sock_fd + 1, nullptr, &write_fds, nullptr, &tv);

            if (select_status > 0)
            {
                if (FD_ISSET(sock_fd, &write_fds))
                {
                    int optval = -1;
                    socklen_t optlen = sizeof(optval);
                    if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == 0)
                    {
                        if (optval == 0)
                        {
                            port_is_open_flag = true;
                            port.info = "\tConnected: (selected)";
                        }
                        else
                        {
                            port.info = "Connection error: " + std::string(strerror(optval));
                        }
                    }
                    else
                    {
                        port.info = "getsockopt failed: " + std::string(strerror(errno));
                    }
                }
            }
            else if (select_status == 0)
            {
                port.info = "\tTimeout";
            }
            else
            {
                port.info = "Select error: " + std::string(strerror(errno));
            }
        }
        else
        {
            port.info = "Immediate connect error: " + std::string(strerror(errno));
        }

        close(sock_fd);

        if (port_is_open_flag)
        {
            port.statu = port_statu::open;
            _scan_target.open_ports.push_back(port);
        }
        else
        {
            port.statu = port_statu::close;
            if (port.info.empty() && port.statu == port_statu::close) {}
        }

            std::cout << port.number << "\t" << get_port_statu(port.statu) << "\t" << " " << port.info << "\n";
    }

    std::cout << "-----------------------------------------------------\n";
    if (_scan_target.open_ports.empty())
    {
        std::cout << "< NO OPEN PORTS FOUND >\n";
    }
    else
    {
        std::cout << "Scan complete. Open ports on " << current_target_ip_str << ":\n";
        for (auto open_port : _scan_target.open_ports)
        {
            std::cout << "-" << open_port.number << " (" << open_port.service_name << ") " << "/ tcp\n";
        }
    }
    std::cout << "-----------------------------------------------------\n";
}

void linux_scanner::tcp_syn_scan()
{

}
void linux_scanner::tcp_ack_scan()
{
    
}
void linux_scanner::tcp_fin_scan()
{
    
}
void linux_scanner::udp_scan()
{
    
}

void linux_scanner::scan_localhost_network() { tcp_connect_scan(); }
void linux_scanner::scan_internal_network()  { tcp_connect_scan(); }
void linux_scanner::scan_external_network()  { tcp_connect_scan(); }

std::string linux_scanner::get_port_statu(port_statu statu)
{
    if (statu == port_statu::close)   { return "CLOSE"; }
    if (statu == port_statu::open)    { return "OPEN"; }
    if (statu == port_statu::unknown) { return "UNKNOWN"; }

    return "INVALID STUATION";
}