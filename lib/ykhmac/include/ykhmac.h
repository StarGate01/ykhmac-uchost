/**
 * @file ykhmac.h
 * @author Christoph Honal
 * @brief Defines the Yubikey HMAC-SHA1 logic
 * @version 0.1
 * @date 2021-12-17
 */

#ifndef YKHMAC_H
#define YKHMAC_H

#include <inttypes.h>

// Hardware limits
#define HW_BUF_SIZE 64
#define SEND_BUF_SIZE (HW_BUF_SIZE - 2)
#define RECV_BUF_SIZE (HW_BUF_SIZE - 8)

// Response codes
#define E_SUCCESS 0
#define E_UNEXPECTED 1
#define E_CARD_NOT_AUTHENTICATED 2
#define E_FILE_NOT_FOUND 3

// APDU field definitions
#define CLA_ISO 0x00
#define INS_SELECT 0xA4
#define SEL_APP_AID 0x04
#define INS_API_REQ 0x01
#define INS_STATUS 0x03
#define CMD_GET_SERIAL 0x10
#define CMD_HMAC_1 0x30
#define CMD_HMAC_2 0x38
#define SW_OK_HIGH 0x90
#define SW_OK_LOW 0x00
#define SW_PRECOND_HIGH 0x69
#define SW_PRECOND_LOW 0x85
#define SW_NOTFOUND_HIGH 0x6A
#define SW_NOTFOUND_LOW 0x82
#define SW_UNSUP_HIGH 0x6D

// AIDs
#define AID_LENGTH_MAX 32
#define YUBIKEY_AID_LENGTH 7
#define YUBIKEY_AID { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01 }
#define FIDESMO_AID_LENGTH 11
#define FIDESMO_AID { 0xA0, 0x00, 0x00, 0x06, 0x17, 0x00, 0x07, 0x53, 0x4E, 0xAF, 0x01 }

// Functions
extern bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length,
    uint8_t* response_buffer, uint8_t* response_length);

bool ykhmac_select(const uint8_t* aid, const uint8_t aid_size);



#endif