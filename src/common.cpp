#include "../include/common.h"

namespace scanner_common
{
    uint8_t get_outgoing_ttl_for_os(operating_system_type os_type) {
        switch (os_type){
            case operating_system_type::linux_os:
            case operating_system_type::mac_os:
                return 64;
            case operating_system_type::windows_os:
                return 128;
            default:
                return 64;
        }
    }

    std::string port_state_to_string(port_state state) {
        switch (state) {
            case port_state::unknown:       return "Unknown";
            case port_state::sent:          return "Sent";
            case port_state::open:          return "Open";
            case port_state::closed:        return "Closed";
            case port_state::filtered:      return "Filtered";
            case port_state::unfiltered:    return "Unfiltered";
            case port_state::open_filtered: return "Open|Filtered";
            case port_state::error:         return "Error";
            default:                        return "Invalid State";
        }
    }

    std::string scan_type_to_string(scan_type type) {
        switch (type) {
            case scan_type::tcp_connect:       return "TCP Connect";
            case scan_type::tcp_syn:           return "TCP SYN";
            case scan_type::tcp_fin:           return "TCP FIN";
            case scan_type::tcp_xmas:          return "TCP XMAS";
            case scan_type::tcp_null:          return "TCP NULL";
            case scan_type::tcp_ack:           return "TCP ACK";
            case scan_type::tcp_window:        return "TCP Window";
            case scan_type::tcp_maimon:        return "TCP Maimon";
            case scan_type::udp:               return "UDP";
            case scan_type::sctp_init:         return "SCTP INIT";
            case scan_type::sctp_cookie_echo:  return "SCTP COOKIE-ECHO";
            case scan_type::ip_protocol:       return "IP Protocol";
            case scan_type::idle:              return "Idle";
            case scan_type::none:              return "None";
            default:                           return "Unknown";
        }
    }

    std::string error_code_to_string(error_code code) {
        switch (code) {
            case error_code::success:              return "Success";
            case error_code::unknown_error:        return "Unknown error";
            case error_code::permission_denied:    return "Permission denied";
            case error_code::invalid_argument:     return "Invalid argument";
            case error_code::invalid_target:       return "Invalid target";
            case error_code::invalid_port_spec:    return "Invalid port specification";
            case error_code::socket_create_failed: return "Socket creation failed";
            case error_code::socket_option_failed: return "Socket option failed";
            case error_code::socket_bind_failed:   return "Socket bind failed";
            case error_code::send_failed:          return "Send failed";
            case error_code::recv_timeout:         return "Receive timeout";
            case error_code::recv_failed:          return "Receive failed";
            case error_code::packet_craft_failed:  return "Packet crafting failed";
            case error_code::host_unreachable:     return "Host unreachable";
            case error_code::network_error:        return "Network error";
            default:                               return "Unrecognized error code";
        }
    }

    std::string protocol_type_to_string(protocol_type protocol) {
        switch (protocol) {
            case protocol_type::tcp: return "tcp";
            case protocol_type::udp: return "udp";
            case protocol_type::sctp: return "sctp";
            case protocol_type::icmp: return "icmp";
            case protocol_type::ip:   return "ip";
            case protocol_type::unknown: return "unknown";
            default: return "invalid";
        }
    }
}