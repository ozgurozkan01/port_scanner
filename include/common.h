#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <stdexcept>
#include <utility>

namespace scanner_common {

enum class port_state : uint8_t {
    unknown,
    sent,
    open,
    closed,
    filtered,
    unfiltered,
    open_filtered,
    error
};

enum class scan_type : uint8_t {
    tcp_connect,
    tcp_syn,
    tcp_fin,
    tcp_xmas,
    tcp_null,
    tcp_ack,
    tcp_window,
    tcp_maimon,
    udp,
    sctp_init,
    sctp_cookie_echo,
    ip_protocol,
    idle,
    none
};

enum class operating_system_type {
    linux_os,
    mac_os,
    windows_os,
};

enum class error_code {
    success = 0,
    unknown_error,
    permission_denied,
    invalid_argument,
    invalid_target,
    invalid_port_spec,
    socket_create_failed,
    socket_option_failed,
    socket_bind_failed,
    send_failed,
    recv_timeout,
    recv_failed,
    packet_craft_failed,
    host_unreachable,
    network_error
};

enum class protocol_type : uint8_t {
    tcp,
    udp,
    sctp,
    icmp,
    ip,
    unknown
};


constexpr size_t MAX_IP_PACKET_SIZE = 1500;
constexpr size_t MIN_IP_HEADER_LEN = 20;
constexpr size_t MIN_TCP_HEADER_LEN = 20;
constexpr size_t MIN_UDP_HEADER_LEN = 8;
constexpr size_t MIN_ICMP_HEADER_LEN = 8;

constexpr std::chrono::milliseconds DEFAULT_TCP_TIMEOUT{1000};
constexpr std::chrono::milliseconds DEFAULT_UDP_TIMEOUT{2000};
constexpr std::chrono::milliseconds DEFAULT_HOST_TIMEOUT{5000};

constexpr uint16_t DEFAULT_SOURCE_PORT = 0;

struct port_result {
    int port = 0;
    protocol_type protocol = protocol_type::unknown; // "tcp", "udp", "sctp", "icmp" etc.
    port_state state = port_state::unknown;
    std::string reason = "";        // Durumun nedeni (örn., "syn-ack", "rst", "port-unreach", "timeout")
    std::string service_name = "";  // Tespit edilen servis (örn., "http", "ssh")
    std::string service_version = ""; // Servis versiyonu (örn., "Apache/2.4.41", "OpenSSH_8.2p1")
    std::chrono::milliseconds rtt = std::chrono::milliseconds::zero(); // Gidiş-dönüş süresi (varsa)

    std::string to_string() const {
        return std::to_string(port) + "/" + protocol_type_to_string(protocol) + " - State: " + port_state_to_string(state) + " (" + reason + ") Service: [" + service_name + " " + service_version + "]";
    }

    static std::string port_state_to_string(port_state s);
    static std::string protocol_type_to_string(protocol_type p);
};

struct target_info {
    std::string input_spec;
    std::string ip_address;
    std::string hostname;
    std::string mac_address; 
    operating_system_type type;
};

using port_list = std::vector<int>;
using target_list = std::vector<std::string>;
using resolved_target_list = std::vector<target_info>;
using port_result_map = std::map<int, port_result>;
using scan_result = std::map<std::pair<int, std::string>, port_result>;

uint8_t get_outgoing_ttl_for_os(operating_system_type os_type);
std::string port_state_to_string(port_state state);
std::string scan_type_to_string(scan_type type);
std::string error_code_to_string(error_code code);
std::string protocol_type_to_string(protocol_type protocol);
}

#endif