#ifndef IPV4_PACKET_H
#define IPV4_PACKET_H
#include <stddef.h>
#include <stdint.h>

#define IP_PKT_VERSION_4             4u
#define IP_PKT_VERSION_6             6u

#define IP_PKT_OFFSET_VER_IHL        0u   // VER 4 bits high, IHL 4 bits low
#define IP_PKT_OFFSET_DSCP_ECN       1u   // DSCP 6 bits high, ECN 2 bits low
#define IP_PKT_OFFSET_TOTAL_LEN      2u   // 16 bits
#define IP_PKT_OFFSET_IDENTIFICATION 4u   // 16 bits
#define IP_PKT_OFFSET_FLAGS_FRAGMENT 6u   // FLAG 3 bits high, FRAGMENT 13 bits low
#define IP_PKT_OFFSET_TTL            8u   // 8 bits
#define IP_PKT_OFFSET_PROTOCOL       9u   // 8 bits
#define IP_PKT_OFFSET_CHECKSUM       10u  // 16 bits
#define IP_PKT_OFFSET_SRC_IP         12u  // 32 bits
#define IP_PKT_OFFSET_DST_IP         16u  // 32 bits
#define IP_PKT_OFFSET_OPTIONS        20u  // (ONLY IF IHL > 5)
#define IP_PKT_V4_HEADER_LEN         20u  // default IPv4 header length
#define IP_PKT_V6_HEADER_LEN         40u  // default IPv6 header length

#define IP_PKT_MASK_VER              (uint8_t)0xf0
#define IP_PKT_MASK_IHL              (uint8_t)0x0f
#define IP_PKT_MASK_DSCP             (uint8_t)0xfc
#define IP_PKT_MASK_ECN              (uint8_t)0x03
#define IP_PKT_MASK_FLAGS            (uint8_t)0xe0
#define IP_PKT_MASK_FRAGMENT_HI      (uint8_t)0x1f
#define IP_PKT_MASK_FRAGMENT_LOW     (uint8_t)0xff

#define IP_PROTOCOL_ICMP             (uint8_t)1
#define IP_PROTOCOL_IGMP             (uint8_t)2
#define IP_PROTOCOL_TCP              (uint8_t)6
#define IP_PROTOCOL_UDP              (uint8_t)17
#define IP_PROTOCOL_ENCAP            (uint8_t)41
#define IP_PROTOCOL_OSPF             (uint8_t)89
#define IP_PROTOCOL_SCTP             (uint8_t)132

/* UDP Datagram */
#define UDP_DGRM_SRC_PORT   0u  //  16 bits
#define UDP_DGRM_DST_PORT   2u  //  16 bits
#define UDP_DGRM_LENGTH     4u  //  16 bits
#define UDP_DGRM_CHECKSUM   6u  //  16 bits
#define UDP_DGRM_DATA       8u  //  n  bits
#define UDP_DGRM_HEADER_LEN 8u  // fixed length

typedef struct ipv4_packet {
    uint8_t  version : 4;  // Version
    uint8_t  ihl     : 4;  // Internet Header Length [5, 15], default 5, unit 32bit word
    uint8_t  dscp    : 6;  // Differentiated Services Code Point
    uint8_t  ecn     : 2;  // Explicit Congestion Notification
    uint16_t total_len;    // Total Length
    uint16_t identification;
    uint16_t flags    : 3;   // bit 0: Reserved as 0, bit 1: DF, bit 2: MF
    uint16_t fragment : 13;  // Fragment Offset, units 8 bytes
    uint8_t  ttl;            // TIme to Live
    uint8_t  protocol;       // IANA list IP protocol numbers
    uint16_t checksum;       // Internet Checksum
    uint32_t src_addr;       // Source IPv4 address
    uint32_t dst_addr;       // Destination IPv4 Address
    uint8_t* options;        // Vary in size, rarely used
    uint8_t* data;
} ipv4_packet_t;

typedef struct ipv6_packet {
    uint32_t    version       : 4;
    uint32_t    traffic_class : 8;   // DSCP(6 bit) + ECN(2 bit)
    uint32_t    flow_label    : 20;  // A flow is a group of packets.
    uint16_t    payload_len;         // Length of the data in bytes
    uint8_t     next_header;         // similar as IPv4 Protocol
    uint8_t     hop_limit;           // similar as IPv4 TTL
    __uint128_t src_addr;
    __uint128_t dst_addr;
    uint8_t*    data;  //
} ipv6_packet_t;

typedef enum ip_packet_error {
    IP_PKT_ERR_SUCCESS = 0,
    IP_PKT_ERR_BAD_MEMORY_ALLOC,
    IP_PKT_ERR_BAD_VERSION,
    IP_PKT_ERR_BAD_IHL
} IP_ERR;

IP_ERR ipv4_packet_create(ipv4_packet_t** ipv4_packet);
IP_ERR ipv4_packet_parse(const uint8_t* raw_data, ipv4_packet_t* ipv4_packet);
void   ipv4_packet_forwarder(const ipv4_packet_t* ipv4_packet);
void   ipv4_packet_free(ipv4_packet_t* ipv4_packet);

void on_arp_data_received(uint8_t* arp_raw_data);
void on_ipv4_data_received(uint8_t* ipv4_raw_data);
void on_ipv6_data_received(uint8_t* ipv6_raw_data);
void on_vlan_data_received(uint8_t* vlan_raw_data);

extern void on_udp_data_received(uint8_t* udp_raw_data);

#endif