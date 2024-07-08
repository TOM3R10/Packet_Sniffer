#ifndef FRAME_PARSER_H
#define FRAME_PARSER_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define FRAME_PARSER_MAX_FRAME_SIZE 1518
#define FRAME_PARSER_MAC_ADDRESS_LENGTH 6
#define FRAME_PARSER_ID_IDENTF_IPV4 0x0800
#define FRAME_PARSER_ID_IDENTF_IPV6 0x86DD
/**
 * @brief Structure representing the frame header.
 *
 * This structure holds the destination MAC address, source MAC address,
 * and Ether type for a network frame.
 */
struct frame_header {
    unsigned char dest_mac[FRAME_PARSER_MAC_ADDRESS_LENGTH];   /**< Destination MAC address */
    unsigned char src_mac[FRAME_PARSER_MAC_ADDRESS_LENGTH];    /**< Source MAC address */
    uint16_t ether_type;   /**< Ether type field */
}typedef frame_header_t;

/**
 * @brief Parses a frame from a buffer and fills the frame header structure.
 *
 * This function takes a buffer containing the frame data and fills the provided
 * frame header structure with the parsed data.
 *
 * @param frame_header Pointer to the frame_header structure to be filled.
 * @param buffer Buffer containing the frame data.
 */
void parse_frame(frame_header_t *frame_header, unsigned char* buffer);

/**
 * @brief Prints the details of the frame header.
 *
 * This function prints the source IP, destination IP, and Ether type
 * from the provided frame header structure.
 *
 * @param frame_header Pointer to the frame_header structure containing the frame details.
 */
void print_frame(frame_header_t *frame_header);

#endif // FRAME_PARSER_H
