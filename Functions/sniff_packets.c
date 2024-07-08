#include "sniff_packets.h"
#include "../Transport/tcp_parser.h"

/**
 * @brief Sniffs a specified number of packets and prints the details to the terminal.
 *
 * This function captures packets from a raw socket, parses them, and prints
 * the details of each packet to the terminal. It also counts the number of
 * loopback, TCP, and UDP packets.
 *
 * @param num The number of packets to sniff.
 */
void sniff_packets_to_terminal(int num) {
    unsigned char buffer[FRAME_PARSER_MAX_FRAME_SIZE];

    int socket_id = create_socket();
    int loopback_counter = 0, tcp_counter = 0, udp_counter = 0;

    for(int i = 0; i < num; i++) {
        if (recvfrom(socket_id, buffer, sizeof(buffer), 0, NULL, NULL) == -1) {
            perror("recvfrom");
            exit(1);
        }
        // Checking for loopback
        if (buffer[0] == 0) {
            loopback_counter++;
        } else {
            // Packet header print
            printf("==========Packet %d==========\n\n", i + 1);
            frame_header_t *frame = (frame_header_t *)malloc(sizeof(frame_header_t));
            if (!frame) {
                exit(1);
            }

            parse_frame(frame, buffer);

            // Calling the print function
            print_frame(frame);

            switch (ntohs(frame->ether_type)) {
                case FRAME_PARSER_ID_IDENTF_IPV4: { // IPv4
                    ipv4_packet_t *ipv4 = (ipv4_packet_t *)malloc(sizeof(ipv4_packet_t));
                    if (!ipv4) {
                        free(frame); // Free frame before exiting
                        exit(1);
                    }
                    parse_ipv4(ipv4, buffer);

                    // Calling the print function
                    print_ipv4(ipv4);

                    // UDP/TCP
                    if (ipv4->protocol == UDP_PARSER_PROTOCOL_UDP_NUM) {
                        udp_hdr_t *udp = (udp_hdr_t *)malloc(sizeof(udp_hdr_t));
                        if (!udp) {
                            free(ipv4); // Free ipv4 before exiting
                            free(frame); // Free frame before exiting
                            exit(1);
                        }
                        parse_udp(udp, buffer, sizeof(ipv4));

                        // Calling the print function
                        print_udp(udp);
                        udp_counter++;

                        free(udp); // Free udp after use
                    } else {
                        tcp_parser_t *tcp = (tcp_parser_t *)malloc(sizeof(tcp_parser_t));
                        if (!tcp) {
                            free(ipv4); // Free ipv4 before exiting
                            free(frame); // Free frame before exiting
                            exit(1);
                        }

                        parse_tcp(tcp, buffer, sizeof(ipv4));

                        // Calling the print function
                        print_tcp(tcp);
                        tcp_counter++;

                        free(tcp); // Free tcp after use
                    }

                    free(ipv4); // Free ipv4 after use
                    break;
                }
                case FRAME_PARSER_ID_IDENTF_IPV6: { // IPv6
                    ipv6_packet_t *ipv6 = (ipv6_packet_t *)malloc(sizeof(ipv6_packet_t));
                    if (!ipv6) {
                        free(frame); // Free frame before exiting
                        exit(1);
                    }

                    parse_ipv6(ipv6, buffer);

                    // Calling the print function
                    print_ipv6(ipv6);

                    // UDP/TTCP
                    if (ipv6->next_hdr == UDP_PARSER_PROTOCOL_UDP_NUM) {
                        udp_hdr_t *udp = (udp_hdr_t *)malloc(sizeof(udp_hdr_t));
                        if (!udp) {
                            free(ipv6); // Free ipv6 before exiting
                            free(frame); // Free frame before exiting
                            exit(1);
                        }
                        parse_udp(udp, buffer, sizeof(ipv6));

                        // Calling the print function
                        print_udp(udp);
                        udp_counter++;

                        free(udp); // Free udp after use
                    } else {
                        tcp_parser_t *tcp = (tcp_parser_t *)malloc(sizeof(tcp_parser_t));
                        if (!tcp) {
                            free(ipv6); // Free ipv6 before exiting
                            free(frame); // Free frame before exiting
                            exit(1);
                        }

                        parse_tcp(tcp, buffer, sizeof(ipv6));

                        // Calling the print function
                        print_tcp(tcp);
                        tcp_counter++;

                        free(tcp); // Free tcp after use
                    }

                    free(ipv6); // Free ipv6 after use
                    break;
                }
                default:
                    perror("Other ether type packet");
                printf("\n\n");
            }

            free(frame); // Free frame after use
        }
    }
    printf("\n\n");
    printf("Amount of loopbacks caught: %d\n", loopback_counter);
    printf("TCP Counter: %d\n", tcp_counter);
    printf("UDP Counter: %d\n\n", udp_counter);

    close(socket_id); // Close the socket after use
}

/**
 * @brief Sniffs a specified number of packets and saves the details to a file.
 *
 * This function captures packets from a raw socket, parses them, and saves
 * the details of each packet to a file. Implementation is pending.
 *
 * @param num The number of packets to sniff.
 */
void sniff_packets_to_file(int num) {
    // Implementation pending
}
