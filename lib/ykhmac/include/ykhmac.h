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
#include <aes.hpp>

// Helpers
#define MAX(x, y)               (((x) > (y)) ? (x) : (y)) //!< Maximum of two numbers
#define MIN(x, y)               (((x) < (y)) ? (x) : (y)) //!< Minimum of two numbers

// Hardware limits
#ifndef HW_BUF_SIZE
    #define HW_BUF_SIZE         64                              //!< Size of the transfer buffer of the NFC controller used
#endif
#ifndef SEND_BUF_OVERH
    #define SEND_BUF_OVERH      2                               //!< Overhead of the send buffer in bytes
#endif
#define SEND_BUF_SIZE           (HW_BUF_SIZE - SEND_BUF_OVERH)  //!< Usable space of the transfer buffer for sending
#ifndef RECV_BUF_OVERH
    #define RECV_BUF_OVERH      8                               //!< Overhead of the send buffer in bytes
#endif
#define RECV_BUF_SIZE           (HW_BUF_SIZE - RECV_BUF_OVERH)  //!< Usable space of the transfer buffer for receiving
#define ARG_BUF_SIZE_MAX        (SEND_BUF_SIZE - 5)             //!< Maximum size of an ADPU without header
#ifndef RESP_BUF_SIZE
    #define RESP_BUF_SIZE       20                              //!< Size of the response buffer (inherent to SHA1)
#endif
#ifndef SECRET_KEY_SIZE
    #define SECRET_KEY_SIZE     20                              //!< Size of the secret key
#endif
#define SECRET_KEY_SIZE_PAD     (((SECRET_KEY_SIZE / AES_BLOCKLEN) + 1) * AES_BLOCKLEN) //!< Size of the secret key, padded for AES

// Response codess
#define E_SUCCESS                   0 //!< Operation was successfull 
#define E_UNEXPECTED                1 //!< Unexpected error occurred (protocol violation)
#define E_CARD_NOT_AUTHENTICATED    2 //!< Token requires user interaction / unlocking
#define E_FILE_NOT_FOUND            3 //!< The applet with the specified AID was not found

// Slot IDs
#define SLOT_1 1 //!< Configuration slot 1
#define SLOT_2 2 //!< Configuration slot 2

// APDU definitions
#define CLA_ISO             0x00 //!< Default ISO command class
#define INS_SELECT          0xA4 //!< Select applet instruction
#define SEL_APP_AID         0x04 //!< Select by AID parameter
#define INS_STATUS          0x03 //!< Status request instruction
#define INS_API_REQ         0x01 //!< API request instruction
#define CMD_GET_SERIAL      0x10 //!< Read serial number API command
#define CMD_HMAC_1          0x30 //!< Compute HMAC on slot 1 API command
#define CMD_HMAC_2          0x38 //!< Compute HMAC on slot 2 API command

#define SW_OK_HIGH          0x90 //!< Successfull response code, high byte
#define SW_OK_LOW           0x00 //!< Successfull response code, low byte
#define SW_PRECOND_HIGH     0x69 //!< Precondition failed error response code, high byte
#define SW_PRECOND_LOW      0x85 //!< Precondition failed error response code, low byte
#define SW_NOTFOUND_HIGH    0x6A //!< Not found error response code, high byte
#define SW_NOTFOUND_LOW     0x82 //!< Not found error response code, low byte
#define SW_UNSUP_HIGH       0x6D //!< Unsupported operation error response code, high byte

// AIDs
#define YUBIKEY_AID_LENGTH  7 //!< Size of the official Yubico applet AID
#define YUBIKEY_AID         { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01 } //!< Official Yubico applet AID
#define FIDESMO_AID_LENGTH  11 //!< Size of a Fidesmo development applet AID
#define FIDESMO_AID         { 0xA0, 0x00, 0x00, 0x06, 0x17, 0x00, 0x07, 0x53, 0x4E, 0xAF, 0x01 } //!< Fidesmo development applet AID


/**
 * @brief Prototype declaration of NFC hardware interfacing function
 * 
 * @param send_buffer Buffer to be sent to the target
 * @param send_length Amount of bytes to be sent
 * @param response_buffer Buffer to be read from the target
 * @param response_length Amount of bytes to be read
 * @return true on success
 */
extern bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length,
    uint8_t* response_buffer, uint8_t* response_length);

/**
 * @brief Prototype declaration of random number generator
 * 
 * @return Random byte
 */
extern uint8_t ykhmac_random();

/**
 * @brief Prototype declaration of a persistent write function
 * 
 * @param data  Buffer to be written from
 * @param size Amount of bytes to be written
 * @param offset Where to write the bytes to
 * @return true on success
 */
extern bool ykhmac_presistent_write(const uint8_t *data, const size_t size, const size_t offset);

/**
 * @brief Prototype declaration of a persistent read function
 * 
 * @param data  Buffer to be read into
 * @param size Amount of bytes to be read
 * @param offset Where to read the bytes from
 * @return true on success
 */
extern bool ykhmac_presistent_read(uint8_t *data, const size_t size, const size_t offset);

/**
 * @brief Selects an applet by its AID
 * 
 * @param aid The AID of the applet
 * @param aid_size The length of the AID in bytes
 * @return true on success
 */
bool ykhmac_select(const uint8_t* aid, const uint8_t aid_size);

/**
 * @brief Reads the serial number of the target
 * 
 * @param serial The serial number
 * @return true on success
 */
bool ykhmac_read_serial(uint32_t* serial);

/**
 * @brief Reads the firmware version of the target
 * 
 * @param version The firmware version
 * @return true on success
 */
bool ykhmac_read_version(uint8_t version[3]);

/**
 * @brief Performs a HMAC-SHA1 challenge-response exchange with the target
 * 
 * @param slot Which slot to use, either SLOT_1 or SLOT_2
 * @param challenge Input buffer, contains challenge
 * @param challenge_length Size of the input buffer in bytes, max. ARG_BUF_SIZE_MAX
 * @param response Output buffer, contains response. May be nullptr to discard response
 * @return true on success
 */
bool ykhmac_exchange_hmac(const uint8_t slot, const uint8_t* challenge, 
    const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE] = nullptr);

/**
 * @brief Tests both slots of the target for valid configurations
 * 
 * @return SLOT_1 | SLOT_2
 */
uint8_t ykhmac_find_slots();

/**
 * @brief Enrolls a secret key into encrypted persistent memory
 * 
 * @param secret_key The secret key to be enrolled
 * @return true on success
 */
bool ykhmac_enroll_key(uint8_t secret_key[SECRET_KEY_SIZE]);

/**
 * @brief tries to authenticate a target against the stored secret key
 * 
 * In addition, this function will advance the stored secret key.
 * 
 * @param slot Which slot to use, either SLOT_1 or SLOT_2
 * 
 * @return true on successful authentication
 */
bool ykhmac_authenticate(const uint8_t slot);

/**
 * @brief Computes a HMAC-SHA1 response using a secret key and challenge
 * 
 * @param key Secret key buffer, size must be at least SECRET_KEY_SIZE
 * @param challenge Input buffer, contains challenge
 * @param challenge_length Size of the input buffer in bytes, max. ARG_BUF_SIZE_MAX
 * @param response Output buffer, contains response. Must be at least RESP_BUF_SIZE
 * @return true on success
 */
bool ykhmac_compute_hmac(const uint8_t* key, const uint8_t* challenge, 
    const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE]);

#endif