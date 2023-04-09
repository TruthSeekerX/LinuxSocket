#ifndef UDP_DATAGRAM_H
#define UDP_DATAGRAM_H
#include <stddef.h>
#include <stdint.h>

/* UDP Datagram */
#define UDP_DGRM_SRC_PORT   0u  //  16 bits
#define UDP_DGRM_DST_PORT   2u  //  16 bits
#define UDP_DGRM_LENGTH     4u  //  16 bits
#define UDP_DGRM_CHECKSUM   6u  //  16 bits
#define UDP_DGRM_DATA       8u  //  n  bits
#define UDP_DGRM_HEADER_LEN 8u  // fixed length

typedef struct udp_datagram {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t* data;
} udp_dgrm_t;

typedef enum udp_datagram_error { UDP_DGRM_ERR_SUCCESS = 0, UDP_DGRM_ERR_BAD_MEMORY_ALLOC } UDP_ERR;

void    on_udp_data_received(uint8_t* udp_raw_data);
UDP_ERR udp_datagram_create(udp_dgrm_t** udp_datagram);
UDP_ERR udp_datagram_parse(const uint8_t* raw_data, udp_dgrm_t* udp_datagram);
void    udp_datagram_forwarder(const udp_dgrm_t* udp_datagram);
void    udp_datagram_free(udp_dgrm_t* udp_datagram);

extern void udp_data_payload_handler(udp_dgrm_t* udp_datagram);
#endif