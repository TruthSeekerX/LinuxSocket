#include "udp_datagram.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool udp_datagram_copy_data(const uint8_t* data_src, const size_t data_len,
                                   uint8_t** data_dst);

UDP_ERR udp_datagram_create(udp_dgrm_t** udp_datagram) {
    *udp_datagram = (udp_dgrm_t*)malloc(sizeof(udp_dgrm_t));
    if (*udp_datagram == NULL) {
        return UDP_DGRM_ERR_BAD_MEMORY_ALLOC;
    } else {
        return UDP_DGRM_ERR_SUCCESS;
    }
}

UDP_ERR udp_datagram_parse(const uint8_t* raw_udp_data, udp_dgrm_t* udp_datagram) {
    udp_datagram->src_port = (uint16_t)(raw_udp_data[UDP_DGRM_SRC_PORT] << 8) +
                             (uint16_t)(raw_udp_data[UDP_DGRM_SRC_PORT + 1] << 0);
    udp_datagram->dst_port = (uint16_t)(raw_udp_data[UDP_DGRM_DST_PORT] << 8) +
                             (uint16_t)(raw_udp_data[UDP_DGRM_DST_PORT + 1] << 0);
    udp_datagram->length = (uint16_t)(raw_udp_data[UDP_DGRM_LENGTH] << 8) +
                           (uint16_t)(raw_udp_data[UDP_DGRM_LENGTH + 1] << 0);
    udp_datagram->checksum = (uint16_t)(raw_udp_data[UDP_DGRM_CHECKSUM] << 8) +
                             (uint16_t)(raw_udp_data[UDP_DGRM_CHECKSUM + 1] << 0);
    bool result = udp_datagram_copy_data(raw_udp_data + UDP_DGRM_HEADER_LEN, UDP_DGRM_HEADER_LEN,
                                         &(udp_datagram->data));
    if (result == true) {
        return UDP_DGRM_ERR_SUCCESS;
    } else {
        return UDP_DGRM_ERR_BAD_MEMORY_ALLOC;
    }
}

static bool udp_datagram_copy_data(const uint8_t* data_src, const size_t data_len,
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

void udp_datagram_forwarder(const udp_dgrm_t* udp_datagram) {}

void udp_datagram_free(udp_dgrm_t* udp_datagram) {
    if (udp_datagram != NULL) {
        free(udp_datagram->data);
        free(udp_datagram);
    }
}

void on_udp_data_received(uint8_t* udp_raw_data) {
    udp_dgrm_t* udp_datagram = NULL;
    UDP_ERR     result;
    result = udp_datagram_create(&udp_datagram);
    if (UDP_DGRM_ERR_SUCCESS != result) {
        // ERROR
        exit(5);
    }

    result = udp_datagram_parse(udp_raw_data, udp_datagram);
    if (UDP_DGRM_ERR_SUCCESS != result) {
        // ERROR
        exit(6);
    }

    udp_data_payload_handler(udp_datagram);
    udp_datagram_free(udp_datagram);
}