#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define ETH_FRAME_OFFSET_DST_ADDR 0u   // 48 bits
#define ETH_FRAME_OFFSET_SRC_ADDR 6u   // 48 bits
#define ETH_FRAME_OFFSET_TYPE     12u  // 16 bits
#define ETH_FRAME_OFFSET_VLAN     2u   // when ETH_TYPE is 0x8100, 2 bytes to the right

#define ETH_FRAME_HEADER_LEN      14u  // default header length
#define ETH_FRAME_VLAN_HEADER_LEN 16u  // default header length
#define ETH_FRAME_TYPE_IPV4 \
    (uint8_t[2]) { (uint8_t)0x08, (uint8_t)0x00 }
#define ETH_FRAME_TYPE_ARP \
    (uint8_t[2]) { (uint8_t)0x08, (uint8_t)0x06 }
#define ETH_FRAME_TYPE_IPV6 \
    (uint8_t[2]) { (uint8_t)0x86, (uint8_t)0xdd }
#define ETH_FRAME_TYPE_VLAN \
    (uint8_t[2]) { (uint8_t)0x81, (uint8_t)0x00 }  // IEEE802.1Q Net

#define ETH_BUFFER_LEN 1600u

/* IPv4 Packet */
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
#define IP_PKT_HEADER_LEN            40u  // default IPv6 header length

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

int main(void) {
    unsigned char buffer[ETH_BUFFER_LEN];
    unsigned      break_flag = 0;

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("Socket Error");
        return 1;
    }
    while (1) {
        int rsize  = recvfrom(s, buffer, ETH_BUFFER_LEN, 0, NULL, NULL);
        break_flag = 0;
        
        if (rsize < 0) {
            printf("Recvfrom error\n");
            return 1;
        }
        // printf("Frame Length: %d\n", rsize);
        // printf("ethtype: %02x%02x\n", buffer[12], buffer[13]);

        if (*(uint16_t *)(buffer + ETH_FRAME_OFFSET_TYPE) == *(uint16_t *)ETH_FRAME_TYPE_VLAN) {
            printf("VLAN frame detected, remember to shift 2 bytes\n");
        } else if (*(uint16_t *)(buffer + ETH_FRAME_OFFSET_TYPE) ==
                   *(uint16_t *)ETH_FRAME_TYPE_IPV4) {
            // printf("type: IPv4 \n");
            uint8_t *ipv4_pkt      = buffer + ETH_FRAME_HEADER_LEN;
            uint16_t ip_header_len = (ipv4_pkt[IP_PKT_OFFSET_VER_IHL] & (uint8_t)0x0f) *
                                     4;  // 32bits word >>  8bits byte
            uint16_t ip_total_len = (uint16_t)(ipv4_pkt[IP_PKT_OFFSET_TOTAL_LEN] << 8) +
                                    (uint16_t)ipv4_pkt[IP_PKT_OFFSET_TOTAL_LEN + 1];
            uint16_t ip_data_len = ip_total_len - ip_header_len;

            switch (ipv4_pkt[IP_PKT_OFFSET_PROTOCOL]) {
                case IP_PROTOCOL_ICMP:
                    /* TBD */
                    break;
                case IP_PROTOCOL_TCP:
                    /* TBD */
                    break;
                case IP_PROTOCOL_UDP:
                    /* UPD */
                    uint8_t *udp_datagram = ipv4_pkt + ip_header_len;
                    uint8_t *udp_data     = udp_datagram + UDP_DGRM_HEADER_LEN;

                    if (udp_data[0] == 'g' && udp_data[1] == 'a' && udp_data[2] == 'o') {
                        printf("UPD detected:\n");
                        uint16_t port = (uint16_t)(udp_datagram[UDP_DGRM_DST_PORT] << 8) +
                                        (uint16_t)udp_datagram[UDP_DGRM_DST_PORT + 1];
                        printf("DST PORT: 0x%02x 0x%02x / 0d%u\n", udp_datagram[UDP_DGRM_DST_PORT],
                               udp_datagram[UDP_DGRM_DST_PORT + 1], port);
                    } else if (udp_data[0] == 'q') {
                        break_flag = 1;
                    }
                    break;
                default:
                    break;
            }
        }
        if (break_flag) {
            break;
        }
    }
    close(s);
}
