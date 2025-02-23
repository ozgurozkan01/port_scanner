#include <iostream>
#include <vector>

// 192.168.0.*    -> scan all IPs in range
bool is_valid_wildcard_format(const std::string& input);
std::vector<std::string> expand_wildcard_ip(const std::string& input);

// 192.168.0.1-10 -> scan IPs in range 192.168.0.1 - 192.168.0.10 (10 values)
bool is_valid_ip(const std::string& ip);
bool is_valid_range(const std::string& range);
bool is_valid_range_format(const std::string& input);
bool is_valid_octet(int octet);
std::vector<std::string> get_ips_from_range(const std::string& input);

// 192.168.0.10 192.168.0.20 -> scan just 2 IPs 
std::vector<std::string> get_two_ips(const std::string& input);
