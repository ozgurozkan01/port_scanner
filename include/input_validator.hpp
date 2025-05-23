#include <iostream>
#include <vector>
#include <set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <algorithm>

#define IP_V4_PORTION_COUNT 4
#define MIN_PORT 1
#define MAX_PORT 65535

bool is_CIDR_valid(const std::string& target)
{
    if (target.length() < 2) 
    {
        std::cerr << "CIDR lenght has to be longer than 2 characters !!\n";
        return false;
    }

    if (target[0] != '/') 
    {
        std::cerr << "First character of CIDR has to be slash (/) !!\n";
        return false;
    }

    std::string number_part = target.substr(1);

    for (char c : number_part) 
    {
        if (!std::isdigit(c)) 
        {
            std::cerr << "Number part can have only digit values (0-9) !!\n";
            return false;
        }
    }

    try 
    {
        int CIDR_value = std::stoi(number_part);
        if (CIDR_value < 0 || CIDR_value > 32) 
        {
            std::cerr << "CIDR can have only numbers between 0-32 !!\n";
            return false;
        }
    } 
    catch (const std::invalid_argument& e) 
    {
        std::cerr << "Invalid Argument by checking CIDR : " << e.what() << "\n";
    }

    
    return true;
}

bool is_target_ip_v4(const std::string& target)
{
    struct sockaddr_in socket_addr;
    if (inet_pton(AF_INET, target.c_str(), &(socket_addr.sin_addr)) != 1) 
    {
        std::cerr << "IP V4 Format must have numbers between 0-255 : " << target << "\n";
        return false;    
    }

    std::stringstream ss(target);
    std::string segment;
    std::vector<std::string> segments;
    uint8_t segment_count = 0;

    while(std::getline(ss, segment, '.')) 
    {
        segments.push_back(segment);
        segment_count++;
    }

    if (segment_count != IP_V4_PORTION_COUNT)
    {
        throw std::invalid_argument("Target does not have enough IPV4 portion !!\n");
    }
    
    for(const auto octet : segments)
    {
        if (!std::all_of(octet.begin(), octet.end(), ::isdigit)) 
        {
            throw std::invalid_argument("Portions do not consist of digits !!\n");
        }

        if (octet.length() > 1 && octet[0] == '0') 
        {
            throw std::invalid_argument("Portions cannot have 0 on left side !!\n");
        }
    }

    return true;
}

bool is_target_domainname(const std::string& target, const int& CIDR)
{
    if (CIDR != 32)
    {
        std::cerr << "Your target is a domain name but CIDR is not 32 : " << CIDR << "\n";
        return false;
    }
    
    
    if (target.front() == '.' || target.back() == '.')
    {
        // Hostnames does not include dot at the beginning or end
        // Instances : 
        // .google.com (x)
        // google.com. (x)
        // google.com  (/)
        std::cerr << "Hostnames does not include dot at the beginning or ending !!\n";
        return false;
    }

    std::stringstream ss(target);
    std::string label;
    bool contains_alpha = false;
    bool first_label = true;

    while (std::getline(ss, label, '.'))
    {
        if (label.empty())
        {
            std::cerr << "Invalid format!!\n";
            return false;
        }
        
        if (label.front() == '-' || label.back() == '-') 
        {
            std::cerr << "Label does not include at the beginning or end!!\n";
            return false;
        }

        if (label.length() > 63) 
        {
            std::cerr << "Label cannot be longer than 63 characters!!\n";
            return false;
        }
        
        for (char c : label) 
        {
            if (!std::isalnum(c) && c != '-') { return false; }
            if (std::isalpha(c)) { contains_alpha = true; }
        }

        first_label = false;
    }

    if (first_label && !target.empty()) 
    {
        const std::string& single_label = target;
     
        if (single_label.length() > 63) return false;
        if (single_label.front() == '-' || single_label.back() == '-') return false;
     
        for (char c : single_label) 
        {
            if (!std::isalnum(c) && c != '-') return false;
            if (std::isalpha(c)) contains_alpha = true;
        }
    }
    
    if (!contains_alpha && target != "localhost") 
    {
        bool all_digits_or_hyphen = true;
        
        for(char c : target) 
        {
            if (c != '.' && c != '-' && !std::isdigit(c)) 
            {
                all_digits_or_hyphen = false;
                break;
            }
        }

        if(all_digits_or_hyphen && target.find('.') == std::string::npos) 
        {
            return false;
        }
    }

    return true;
}

bool is_string_numeric_exclusive(const std::string& s) 
{
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(), ::isdigit);
}

std::vector<uint16_t> parse_comma_format(const std::string& ports_to_scan) 
{
    std::set<uint16_t> parsed_ports_set;
    
    std::stringstream main_ss(ports_to_scan);
    std::string segment;
    int segment_count = 0;
    
    while (std::getline(main_ss, segment, ','))
     {
        segment_count++;
        if (segment.empty() || !is_string_numeric_exclusive(segment))
        {
            std::cerr << "Invalid Port Format : " + segment;
            exit(1);
        }
        
        try 
        {
            int port = std::stoi(segment);
            if (port < MIN_PORT || port > MAX_PORT)
            {
                throw std::out_of_range("Port is not in the correct range : " + segment);
            }
            parsed_ports_set.insert(port);
        } 
        catch (const std::invalid_argument& e)
        {
            std::cerr << "Invalid Port Format: " + segment;
        } 
        catch (const std::out_of_range& e) 
        {
            std::cerr << "Port is not in the correct range : " + segment;
        }
    }
    if (segment_count > 0 && parsed_ports_set.empty())
    {
        std::cerr << "Could not split in to portions : '" + ports_to_scan + "'";
        exit(1);
    }
    else if (segment_count == 0 && !ports_to_scan.empty())
    {
        std::cerr << "Invalid List Format : '" + ports_to_scan + "'";
        exit(1);
    }

    if (parsed_ports_set.empty() && !ports_to_scan.empty()) 
    {
        std::cerr << "Could not split port number properly : '" + ports_to_scan + "'";
        exit(1);
    }

    return std::vector<uint16_t>(parsed_ports_set.begin(), parsed_ports_set.end());
}

std::vector<uint16_t> parse_dash_format(const std::string& ports_to_scan) 
{
    std::set<uint16_t> parsed_ports_set;

    size_t dash_pos = ports_to_scan.find('-');
    std::string start_str = ports_to_scan.substr(0, dash_pos);
    std::string end_str = ports_to_scan.substr(dash_pos + 1);

    if (start_str.empty() || end_str.empty() || !is_string_numeric_exclusive(start_str) || !is_string_numeric_exclusive(end_str))
    {
        std::cerr << "Invalid Format : '" + ports_to_scan + "'";
        exit(1);
    }

    try
    {
        int start_port = std::stoi(start_str);
        int end_port = std::stoi(end_str);

        if (start_port < MIN_PORT || start_port > MAX_PORT || end_port < MIN_PORT || end_port > MAX_PORT)
        {
            throw std::out_of_range("Invalid Port Number In Range : '" + ports_to_scan + "'");
        }
        if (start_port > end_port) 
        {
            throw std::invalid_argument("Starting Port Cannot Be Bigger Than Ending Port: '" + ports_to_scan + "'");
        }

        for (int port = start_port; port <= end_port; ++port) 
        {
            parsed_ports_set.insert(port);
        }
    } 
    
    catch (const std::invalid_argument& e) 
    {
        std::cerr << e.what();
    }
    catch (const std::out_of_range& e) 
    {
        std::cerr << e.what();
    }

    if (parsed_ports_set.empty() && !ports_to_scan.empty()) 
    {
        std::cerr << "Could not split port number properly : '" + ports_to_scan + "'";
        exit(1);
    }

    return std::vector<uint16_t>(parsed_ports_set.begin(), parsed_ports_set.end());
}

std::vector<uint16_t> parse_single_format(const std::string& ports_to_scan) 
{
    std::set<uint16_t> parsed_ports_set;

    if (!is_string_numeric_exclusive(ports_to_scan)) 
    {
        std::cerr << "Invalid Format (Not Number): '" + ports_to_scan + "'";
        exit(1);
    }
    try 
    {
        int port = std::stoi(ports_to_scan);
        if (port < MIN_PORT || port > MAX_PORT)
        {
            throw std::out_of_range("Invalid Port Number : '" + ports_to_scan + "'");
        }

        parsed_ports_set.insert(port);
    } 
    
    catch (const std::invalid_argument& e)
    {
        std::cerr << e.what();
    } 
    catch (const std::out_of_range& e) 
    { 
        std::cerr << e.what();
    }

    if (parsed_ports_set.empty() && !ports_to_scan.empty()) 
    {
        std::cerr << "Could not split port number properly : '" + ports_to_scan + "'";
        exit(1);
    }

    return std::vector<uint16_t>(parsed_ports_set.begin(), parsed_ports_set.end());
}

std::vector<uint16_t>parse_ports_string_to_list(const std::string& ports_to_scan)
{
    bool has_comma = (ports_to_scan.find(',') != std::string::npos); // 22,80,443 -> 3 ports
    bool has_dash = (ports_to_scan.find('-') != std::string::npos);  // 22-80     -> ports in range

    if (has_comma && !has_dash) // 22,80,443
    {
        return parse_comma_format(ports_to_scan);
    }
    else if (!has_comma && has_dash) // 22-80
    {
        return parse_dash_format(ports_to_scan);
    }
    else if (!has_comma && !has_dash)// just 1 port 
    {
        return parse_single_format(ports_to_scan);
    }

    std::cout << "Invalid Port Format !!\n";
    exit(1);
}

scan_type get_scan_type(const std::string& scan_type_string)
{
    if (scan_type_string == "-tc") { return scan_type::tcp_connect; }
    if (scan_type_string == "-ts") { return scan_type::tcp_syn; }
    if (scan_type_string == "-ta") { return scan_type::tcp_ack; }
    if (scan_type_string == "-tf") { return scan_type::tcp_fin; }
    if (scan_type_string == "-u")  { return scan_type::udp; }

    std::cerr << "Specified invalid scan type !!\n";
    return scan_type::invalid;
}