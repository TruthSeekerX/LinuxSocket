#include "ethernet_frame.h"

#include <stdlib.h>
#include <string.h>

static bool ethernet_frame_copy_data(const uint8_t *data_src, const size_t data_len,
                                     uint8_t **data_dst);
/**
 * \author siyuan xu, e2101066@edu.vamk.fi, April.2023.
 * \brief Create/Allocate memory for an eth_frame_t object.
 * \param[out] ethernet_frame - The address of the eth_frame_t object.
 * \return ETH_SUCCESS when success, ETH_ERR_BAD_MEMORY when bad memory allocation.
 * \details eth_frame_t object has to be freed by ethernet_frame_free().
 */
ETH_ERR ethernet_frame_create(eth_frame_t **ethernet_frame) {
    *ethernet_frame = (eth_frame_t *)calloc(sizeof(eth_frame_t), 1);
    if (*ethernet_frame == NULL) {
        return ETH_ERR_BAD_MEMORY_ALLOC;
    } else {
        return ETH_ERR_SUCCESS;
    }
}

/**
 * \author siyuan xu, e2101066@edu.vamk.fi, April.2023.
 * \brief Parse the raw ethernet frame bytes data.
 * \param[in] raw_Data - The raw bytes data of an ethernet frame.
 * \param[in] frame_size - The size of the entire frame.
 * \param[out] ethernet_frame - The address of the eth_frame_t object.
 * \return ETH_SUCCESS when success, ETH_ERR_BAD_MEMORY when bad memory allocation
 * \details This function will dynamically allocate memory for ethernet_frame->data.
 * And it will be freed by ethernet_frame_free().
 */
ETH_ERR ethernet_frame_parse(const uint8_t *raw_data, const size_t frame_size,
                             eth_frame_t *ethernet_frame) {
    uint64_t dst_addr = ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 0] << 40) +
                        ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 1] << 32) +
                        ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 2] << 24) +
                        ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 3] << 16) +
                        ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 4] << 8) +
                        ((uint64_t)raw_data[ETH_FRAME_OFFSET_DST_ADDR + 5] << 0);

    ethernet_frame->dst_addr = dst_addr;

    ethernet_frame->src_addr = ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 0)) << 40) +
                               ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 1)) << 32) +
                               ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 2)) << 24) +
                               ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 3)) << 16) +
                               ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 4)) << 8) +
                               ((uint64_t)(*(raw_data + ETH_FRAME_OFFSET_SRC_ADDR + 5)) << 0);

    uint16_t type =
        (raw_data[ETH_FRAME_OFFSET_TYPE] << 8) + (raw_data[ETH_FRAME_OFFSET_TYPE + 1] << 0);

    if (type == ETH_FRAME_TYPE_VLAN) {
        ethernet_frame->eth_vlan = 1;
        ethernet_frame->eth_type =
            (*(raw_data + ETH_FRAME_OFFSET_TYPE + ETH_FRAME_OFFSET_VLAN) << 8) +
            (*(raw_data + ETH_FRAME_OFFSET_TYPE + ETH_FRAME_OFFSET_VLAN + 1) << 0);
        // ethernet_frame->data = raw_data + ETH_FRAME_VLAN_HEADER_LEN;
        bool result = ethernet_frame_copy_data(raw_data + ETH_FRAME_VLAN_HEADER_LEN,
                                               frame_size - ETH_FRAME_VLAN_HEADER_LEN,
                                               &(ethernet_frame->data));
        if (result == false) {
            return ETH_ERR_BAD_MEMORY_ALLOC;
        } else {
            return ETH_ERR_SUCCESS;
        }
    } else {
        ethernet_frame->eth_vlan = 0;
        ethernet_frame->eth_type = type;
        // ethernet_frame->data = ethernet_frame->data = raw_data + ETH_FRAME_VLAN_HEADER_LEN;
        bool result =
            ethernet_frame_copy_data(raw_data + ETH_FRAME_HEADER_LEN,
                                     frame_size - ETH_FRAME_HEADER_LEN, &(ethernet_frame->data));
        if (result == false) {
            return ETH_ERR_BAD_MEMORY_ALLOC;
        } else {
            return ETH_ERR_SUCCESS;
        }
    }
}

/**
 * \author siyuan xu, e2101066@edu.vamk.fi, April.2023.
 * \brief Create/Allocate memory for an eth_frame_t object.
 * \param[in]  data_src - The address of the data source.
 * \param[in]  data_len - The number of bytes to be copied.
 * \param[out] data_dst - The address of the data destination.
 * \return true when success, false when fail.
 * \details eth_frame_t object has to be freed by ethernet_frame_free().
 */
static bool ethernet_frame_copy_data(const uint8_t *data_src, const size_t data_len,
                                     uint8_t **data_dst) {
    *data_dst = (uint8_t *)malloc(data_len * sizeof(uint8_t));
    if (*data_dst == NULL) {
        // bad allocation, handle it
        return false;
    } else {
        // good
        memcpy(*data_dst, data_src, data_len);
        return true;
    }
}

void ethernet_frame_forwarder(const eth_frame_t *ethernet_frame) {
    if (ethernet_frame->eth_vlan == 1) {
        // do VLAN routines
        on_vlan_data_received(ethernet_frame->data);
    } else {
        switch (ethernet_frame->eth_type) {
            case ETH_FRAME_TYPE_ARP:
                /* code */
                on_arp_data_received(ethernet_frame->data);
                break;
            case ETH_FRAME_TYPE_IPV4:
                /* code */
                on_ipv4_data_received(ethernet_frame->data);
                break;
            case ETH_FRAME_TYPE_IPV6:
                /* code */
                on_ipv6_data_received(ethernet_frame->data);
                break;
            default:
                break;
        }
    }
}

/**
 * \author siyuan xu, e2101066@edu.vamk.fi, April.2023
 * \brief Frees memory for an eth_frame_t object.
 * \param[in] ethernet_frame - The address of the eth_frame_t object.
 * \details eth_frame_t object has to be freed by this function. This function frees both
 * ethernet_frame->data and ethernet_frame.
 */
void ethernet_frame_free(eth_frame_t *ethernet_frame) {
    if (ethernet_frame != NULL) {
        if (ethernet_frame->data != NULL) {
            free(ethernet_frame->data);
        }
        free(ethernet_frame);
    }
}

void on_ethernet_frame_received(uint8_t *raw_ethernet_data, size_t frame_size) {
    eth_frame_t *ethernet_frame;
    ETH_ERR      eth_result;
    eth_result = ethernet_frame_create(&ethernet_frame);
    if (ETH_ERR_SUCCESS != eth_result) {
        // ERROR
        exit(1);
    }
    eth_result = ethernet_frame_parse(raw_ethernet_data, frame_size, ethernet_frame);
    if (ETH_ERR_SUCCESS != eth_result) {
        // ERROR
        exit(2);
    }
    ethernet_frame_forwarder(ethernet_frame);
    ethernet_frame_free(ethernet_frame);
}