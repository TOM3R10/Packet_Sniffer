#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include <string.h>
#define UDP_PARSER_PROTOCOL_UDP_NUM 17
#include <stdint.h>

/**
 * @brief Structure representing a UDP header.
 *
 * This structure holds the various fields of a UDP header, including
 * source port, destination port, length, and checksum.
 */
struct udp_hdr {
    uint16_t source_port; /**< Source port */
    uint16_t dest_port;   /**< Destination port */
    uint16_t length;      /**< Length */
    uint16_t checksum;    /**< Checksum */
}typedef udp_hdr_t;

/**
 * @brief Parses a UDP packet from the given buffer.
 *
 * This function takes a buffer containing the frame data and fills the provided
 * udp_hdr structure with the parsed UDP packet data. The IP header size
 * is also taken into account to correctly locate the UDP header.
 *
 * @param udp Pointer to the udp_hdr structure to be filled.
 * @param buffer Buffer containing the frame data.
 * @param ip_size Size of the IP header.
 */
void parse_udp(udp_hdr_t *udp, unsigned char* buffer, int ip_size);

/**
 * @brief Prints the details of the UDP packet.
 *
 * This function prints the various fields of the provided udp_hdr structure
 * including source port, destination port, length, and checksum.
 *
 * @param udp_packet Pointer to the udp_hdr structure containing the UDP packet details.
 */
void print_udp(udp_hdr_t *udp_packet);

#endif // UDP_PARSER_H
