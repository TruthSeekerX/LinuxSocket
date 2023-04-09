#ifndef ETHERNET_FRAME_H
#define ETHERNET_FRAME_H

/* Ethernet frame header */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ETH_FRAME_OFFSET_DST_ADDR 0u   // 48 bits
#define ETH_FRAME_OFFSET_SRC_ADDR 6u   // 48 bits
#define ETH_FRAME_OFFSET_TYPE     12u  // 16 bits
#define ETH_FRAME_OFFSET_VLAN     2u   // when ETH_TYPE is 0x8100, 2 bytes to the right

#define ETH_FRAME_HEADER_LEN      14u  // default header length
#define ETH_FRAME_VLAN_HEADER_LEN 16u  // default header length

#define ETH_FRAME_TYPE_ARP        (uint16_t)0x0806
#define ETH_FRAME_TYPE_IPV4       (uint16_t)0x0800
#define ETH_FRAME_TYPE_IPV6       (uint16_t)0x86dd
#define ETH_FRAME_TYPE_VLAN       (uint16_t)0x8100  // IEEE802.1Q

#define ETH_BUFFER_LEN            1600u

typedef enum ETHERNET_FRAME_ERROR { ETH_ERR_SUCCESS = 0, ETH_ERR_BAD_MEMORY_ALLOC } ETH_ERR;

typedef struct ethernet_frame {
    uint64_t dst_addr : 48;
    uint64_t src_addr : 48;
    uint8_t  eth_vlan : 1;
    uint16_t eth_type;
    uint8_t* data;
} eth_frame_t;

ETH_ERR ethernet_frame_create(eth_frame_t** ethernet_frame);
ETH_ERR ethernet_frame_parse(const uint8_t* raw_data, const size_t frame_size,
                             eth_frame_t* ethernet_frame);
void    ethernet_frame_forwarder(const eth_frame_t* ethernet_frame);
void    ethernet_frame_free(eth_frame_t* eth_frame);
void    on_ethernet_frame_received(uint8_t* raw_ethernet_data, size_t frame_size);

extern void on_arp_data_received(uint8_t* arp_raw_data);
extern void on_ipv4_data_received(uint8_t* ipv4_raw_data);
extern void on_ipv6_data_received(uint8_t* ipv6_raw_data);
extern void on_vlan_data_received(uint8_t* vlan_raw_data);
#endif