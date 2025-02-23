
#include "resolver.h"
#include <regex>

bool is_valid_wildcard_format(const std::string& input) 
{
    std::regex pattern(R"(^((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}\*$)");
    return std::regex_match(input, pattern);
}

std::vector<std::string> expand_wildcard_ip(const std::string& input) 
{
    std::vector<std::string> ipList;

    std::string base_ip = input.substr(0, input.rfind('.')); 

    for (int i = 0; i <= 255; i++) 
    {
        ipList.push_back(base_ip + "." + std::to_string(i));
    }

    return ipList;
}

bool is_valid_octet(int octet) 
{
    return (octet >= 0 && octet <= 255);
}

bool is_valid_range(const std::string& range) 
{
    size_t dashPos = range.find('-');
    if (dashPos == std::string::npos) return false;

    std::string start_str = range.substr(0, dashPos);
    std::string end_str = range.substr(dashPos + 1);
    int start = std::stoi(start_str);
    int end = std::stoi(end_str);

    return (start < end && start < 256 && end < 256);
}

bool is_valid_ip(const std::string& ip) 
{
    std::regex ip_pattern(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    std::smatch match;
    if (std::regex_match(ip, match, ip_pattern)) 
    {
        for (int i = 1; i <= 4; ++i) 
        {
            int octet = std::stoi(match[i].str());
            if (!is_valid_octet(octet)) 
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool is_valid_range_format(const std::string& input) 
{
    size_t last_dot = input.rfind('.'); // Son noktayı bul
    
    if (last_dot == std::string::npos) 
    {
        return false; // Geçerli IP formatı yoksa çık
    }
    
    std::string ip_base = input.substr(0, last_dot); // "192.168.25" kısmı
    std::string last_part = input.substr(last_dot + 1); // "10-25" kısmı
    
    size_t dash_pos = last_part.find('-'); // Şimdi son oktette "-" var mı kontrol et
    if (dash_pos == std::string::npos) 
    {
        return false;
    }
    
    std::string start_str = last_part.substr(0, dash_pos);
    std::string end_str = last_part.substr(dash_pos + 1);

    if (start_str.empty() || end_str.empty()) 
    {
        return false;
    }
    int start = std::stoi(start_str);
    int end = std::stoi(end_str);

    // IP kısmını ve aralığı kontrol et
    return is_valid_ip(ip_base + ".0") && is_valid_range(start_str + "-" + end_str);
}


std::vector<std::string> get_ips_from_range(const std::string& input) 
{
    std::vector<std::string> result;
    
    size_t last_dot = input.rfind('.'); // Son noktayı bul
    if (last_dot == std::string::npos) return result;

    std::string ip_base = input.substr(0, last_dot); // "192.168.25" kısmı
    std::string last_part = input.substr(last_dot + 1); // "10-25" kısmı

    size_t dash_pos = last_part.find('-');
    if (dash_pos == std::string::npos) return result; // Eğer "-" yoksa geçersiz
    
    int start = std::stoi(last_part.substr(0, dash_pos));
    int end = std::stoi(last_part.substr(dash_pos + 1));

    // Geçerli aralık mı kontrol et
    if (start > end || !is_valid_octet(start) || !is_valid_octet(end)) return result;

    for (int i = start; i <= end; ++i) 
    {
        result.push_back(ip_base + "." + std::to_string(i));
    }

    return result;
}

std::vector<std::string> get_two_ips(const std::string& input) 
{
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string ip;

    while (ss >> ip)
    {
        if (is_valid_ip(ip)) 
        {
            result.push_back(ip);
        } 
        else 
        {
            std::cerr << "Geçersiz IP adresi: " << ip << std::endl;
            return {};
        }
    }

    if (result.size() != 2) 
    {
        return {};
    }

    return result;
}
