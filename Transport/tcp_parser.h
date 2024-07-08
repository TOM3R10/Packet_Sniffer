#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdint.h>

#define FRAME_SIZE 14

/**
 * @brief Structure representing a TCP packet.
 *
 * This structure holds the various fields of a TCP packet, including
 * source port, destination port, sequence number, acknowledgment number,
 * data offset, reserved and flags, window size, checksum, and urgent pointer.
 */
struct tcp_parser {
    uint16_t source_port;   /**< Source port */
    uint16_t destination_port; /**< Destination port */
    uint64_t sequence_number;          /**< Sequence number */
    uint64_t acknowledgment_number;    /**< Acknowledgment number */
    uint16_t data_offset_and_reserved_and_flags; /**< Data offset, reserved, and flags */
    uint16_t window_size;   /**< Window size */
    uint16_t checksum;      /**< Checksum */
    uint16_t urgent_pointer; /**< Urgent pointer */
}typedef tcp_parser_t;

/**
 * @brief Parses a TCP packet from the given buffer.
 *
 * This function takes a buffer containing the frame data and fills the provided
 * tcp_parser structure with the parsed TCP packet data. The IP header size
 * is also taken into account to correctly locate the TCP header.
 *
 * @param tcp_parser Pointer to the tcp_parser structure to be filled.
 * @param buffer Buffer containing the frame data.
 * @param ip_size Size of the IP header.
 */
void parse_tcp(tcp_parser_t *tcp_parser, unsigned char *buffer, int ip_size);

/**
 * @brief Prints the details of the TCP packet.
 *
 * This function prints the various fields of the provided tcp_parser structure
 * including source port, destination port, sequence number, acknowledgment number,
 * data offset, reserved and flags, window size, checksum, and urgent pointer.
 *
 * @param tcp_parser Pointer to the tcp_parser structure containing the TCP packet details.
 */
void print_tcp(tcp_parser_t *tcp_parser);

#endif // TCP_PARSER_H
