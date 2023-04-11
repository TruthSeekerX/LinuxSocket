#include "ip_packet.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* debug_info[] = {"IP_PKT_ERR_SUCCESS", "IP_PKT_ERR_BAD_MEMORY_ALLOC",
                            "IP_PKT_ERR_BAD_VERSION", "IP_PKT_ERR_BAD_IHL"};

static bool ipv4_packet_copy_data(const uint8_t* data_src, const size_t data_len,
                                  uint8_t** data_dst);

IP_ERR ipv4_packet_create(ipv4_packet_t** ipv4_packet) {
    *ipv4_packet = (ipv4_packet_t*)calloc(sizeof(ipv4_packet_t), 1);
    if (*ipv4_packet == NULL) {
        return IP_PKT_ERR_BAD_MEMORY_ALLOC;
    } else {
        return IP_PKT_ERR_SUCCESS;
    }
}

IP_ERR ipv4_packet_parse(const uint8_t* raw_data, ipv4_packet_t* ipv4_packet) {
    ipv4_packet->version = (uint8_t)((raw_data[IP_PKT_OFFSET_VER_IHL]) & IP_PKT_MASK_VER) >> 4;
    if (ipv4_packet->version != 4) {
        return IP_PKT_ERR_BAD_VERSION;
    }
    ipv4_packet->ihl       = (uint8_t)raw_data[IP_PKT_OFFSET_VER_IHL] & IP_PKT_MASK_IHL;
    ipv4_packet->dscp      = (uint8_t)(raw_data[IP_PKT_OFFSET_DSCP_ECN] & IP_PKT_MASK_DSCP) >> 3;
    ipv4_packet->ecn       = (uint8_t)raw_data[IP_PKT_OFFSET_DSCP_ECN] & IP_PKT_MASK_ECN;
    ipv4_packet->total_len = ((uint16_t)raw_data[IP_PKT_OFFSET_TOTAL_LEN] << 8) +
                             ((uint16_t)raw_data[IP_PKT_OFFSET_TOTAL_LEN + 1] << 0);
    ipv4_packet->identification = ((uint16_t)raw_data[IP_PKT_OFFSET_IDENTIFICATION] << 8) +
                                  ((uint16_t)raw_data[IP_PKT_OFFSET_IDENTIFICATION + 1] << 0);
    ipv4_packet->flags = (raw_data[IP_PKT_OFFSET_FLAGS_FRAGMENT] & IP_PKT_MASK_FLAGS) >> 5;
    ipv4_packet->fragment =
        ((uint16_t)(raw_data[IP_PKT_OFFSET_FLAGS_FRAGMENT] & IP_PKT_MASK_FRAGMENT_HI) << 8) +
        ((uint16_t)(raw_data[IP_PKT_OFFSET_FLAGS_FRAGMENT + 1] & IP_PKT_MASK_FRAGMENT_LOW) << 0);
    ipv4_packet->ttl      = raw_data[IP_PKT_OFFSET_TTL];
    ipv4_packet->protocol = raw_data[IP_PKT_OFFSET_PROTOCOL];
    ipv4_packet->checksum = ((uint16_t)raw_data[IP_PKT_OFFSET_CHECKSUM] << 8) +
                            ((uint16_t)raw_data[IP_PKT_OFFSET_CHECKSUM + 1] << 0);
    ipv4_packet->src_addr = ((uint32_t)raw_data[IP_PKT_OFFSET_SRC_IP] << 24) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_SRC_IP + 1] << 16) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_SRC_IP + 2] << 8) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_SRC_IP + 3] << 0);
    ipv4_packet->dst_addr = ((uint32_t)raw_data[IP_PKT_OFFSET_DST_IP] << 24) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_DST_IP + 1] << 16) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_DST_IP + 2] << 8) +
                            ((uint32_t)raw_data[IP_PKT_OFFSET_DST_IP + 3] << 0);
    if (ipv4_packet->ihl < 5) {
        return IP_PKT_ERR_BAD_IHL;
    } else if (ipv4_packet->ihl == 5) {  // Default IPv4 packet
        size_t data_length = ipv4_packet->total_len - IP_PKT_V4_HEADER_LEN;

        ipv4_packet->options = NULL;
        bool result          = ipv4_packet_copy_data(raw_data + IP_PKT_V4_HEADER_LEN, data_length,
                                                     &(ipv4_packet->data));
        if (result == false) {
            return IP_PKT_ERR_BAD_MEMORY_ALLOC;
        } else {
            return IP_PKT_ERR_SUCCESS;
        }
    } else {  // Options available
        size_t header_length, options_length, data_length;

        header_length = ipv4_packet->ihl * 8;

        options_length = header_length - IP_PKT_V4_HEADER_LEN;
        bool result    = ipv4_packet_copy_data(raw_data + header_length, options_length,
                                               &(ipv4_packet->options));
        if (result == false) {
            return IP_PKT_ERR_BAD_MEMORY_ALLOC;
        } else {
            return IP_PKT_ERR_SUCCESS;
        }

        data_length = ipv4_packet->total_len - header_length;
        result = ipv4_packet_copy_data(raw_data + header_length, data_length, &(ipv4_packet->data));
        if (result == false) {
            return IP_PKT_ERR_BAD_MEMORY_ALLOC;
        } else {
            return IP_PKT_ERR_SUCCESS;
        }
    }
}

static bool ipv4_packet_copy_data(const uint8_t* data_src, const size_t data_len,
                                  uint8_t** data_dst) {
    *data_dst = (uint8_t*)malloc(data_len * sizeof(uint8_t));
    if (*data_dst == NULL) {
        // bad allocation, handle it
        return false;
    } else {
        // good
        memcpy(*data_dst, data_src, data_len);
        return true;
    }
}

void ipv4_packet_forwarder(const ipv4_packet_t* ipv4_packet) {
    switch (ipv4_packet->protocol) {
        case IP_PROTOCOL_ICMP:
            /* TBD */
            break;
        case IP_PROTOCOL_TCP:
            /* TBD */
            break;
        case IP_PROTOCOL_UDP:
            /* UPD */
            on_udp_data_received(ipv4_packet->data);
            break;
        default:
            break;
    }
}

void ipv4_packet_free(ipv4_packet_t* ipv4_packet) {
    if (ipv4_packet != NULL) {
        if (ipv4_packet->options != NULL) {
            free(ipv4_packet->options);
        }
        if (ipv4_packet->data != NULL) {
            free(ipv4_packet->data);
        }
        free(ipv4_packet);
    }
}

void on_ipv4_data_received(uint8_t* ipv4_raw_data) {
    ipv4_packet_t* ipv4_packet = NULL;
    IP_ERR         result;
    result = ipv4_packet_create(&ipv4_packet);
    if (IP_PKT_ERR_SUCCESS != result) {
        // ERROR
        printf("Error: %s\n", debug_info[result]);
        // exit(3);
    }

    result = ipv4_packet_parse(ipv4_raw_data, ipv4_packet);
    if (IP_PKT_ERR_SUCCESS != result) {
        // ERROR
        printf("Error: %s\n", debug_info[result]);
        // exit(4);
    }

    if (IP_PKT_ERR_SUCCESS == result) {
        ipv4_packet_forwarder(ipv4_packet);
    }
    ipv4_packet_free(ipv4_packet);
}

void on_arp_data_received(uint8_t* arp_raw_data) {}
void on_ipv6_data_received(uint8_t* ipv6_raw_data) {}
void on_vlan_data_received(uint8_t* vlan_raw_data) {}