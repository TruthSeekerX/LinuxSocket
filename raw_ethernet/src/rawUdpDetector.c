#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "ethernet_frame.h"
#include "udp_datagram.h"

int kill_flag = 0;
// TCP DUMP GITHUB
void udp_data_payload_handler(udp_dgrm_t* udp_datagram);
void signal_handler(int signal);

int main(void) {
    unsigned char buffer[ETH_BUFFER_LEN];

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("Socket Error");
        return 1;
    }
    while (1) {
        kill_flag  = 0;
        memset(buffer, 0, ETH_BUFFER_LEN);
        int rsize  = recvfrom(s, buffer, ETH_BUFFER_LEN, 0, NULL, NULL);

        if (rsize < 0) {
            printf("Recvfrom error\n");
            return 1;
        }

        on_ethernet_frame_received(buffer, rsize);

        if (kill_flag) {
            break;
        }
    }
    close(s);
    return 0;
}

void udp_data_payload_handler(udp_dgrm_t* udp_datagram) {
    uint8_t* udp_payload = udp_datagram->data;

    if (udp_payload[0] == 'g' && udp_payload[1] == 'a' && udp_payload[2] == 'o') {
        printf("UPD with 'gao'detected:\n");
        printf("Source Port: %u\n", udp_datagram->src_port);
        printf("Destination Port: %u\n", udp_datagram->dst_port);
    } else if (udp_payload[0] == 'q') {
        // TO-DO
        // send signal to close the socket and exit the program.
        signal(SIGINT, signal_handler);
    } else {
        // Do nothing, ignore the rest
    }
}

void signal_handler(int signal) {
    if (signal == SIGINT) {
        // kill_flag = 1;
        printf("SIGINT received!\n");
    }
}