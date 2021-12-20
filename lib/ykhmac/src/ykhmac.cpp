/**
 * @file ykhmac.cpp
 * @author Christoph Honal
 * @brief Implements the definitions from ykhmac.h
 * @version 0.1
 * @date 2021-12-17
 */

#include "ykhmac.h"

#include <sha/sha1.h>
#include <aes.hpp>

#include <Arduino.h>
extern void print_array(const uint8_t *data, const size_t size);

// Decode APDU response code
uint8_t ykhmac_response_code(const uint8_t *recv_buffer, const uint8_t recv_length)
{
    if (recv_length < 2)
    {
        return E_UNEXPECTED;
    }

    if (recv_buffer[recv_length - 2] == SW_OK_HIGH &&
        recv_buffer[recv_length - 1] == SW_OK_LOW)
    {
        return E_SUCCESS;
    }

    if (recv_buffer[recv_length - 2] == SW_PRECOND_HIGH &&
        recv_buffer[recv_length - 1] == SW_PRECOND_LOW)
    {
        return E_CARD_NOT_AUTHENTICATED;
    }

    if (recv_buffer[recv_length - 2] == SW_NOTFOUND_HIGH &&
        recv_buffer[recv_length - 1] == SW_NOTFOUND_LOW)
    {
        return E_FILE_NOT_FOUND;
    }

    return E_UNEXPECTED;
}

// APDU exchanges
bool ykhmac_select(const uint8_t *aid, const uint8_t aid_size)
{
    if (aid_size > ARG_BUF_SIZE_MAX) return false;

    // Communication buffers
    uint8_t send_buffer[5 + aid_size];
    uint8_t recv_length = 12;
    uint8_t recv_buffer[recv_length];

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_SELECT;
    send_buffer[2] = SEL_APP_AID;
    send_buffer[3] = 0;
    send_buffer[4] = aid_size;
    memcpy(send_buffer + 5, aid, aid_size);

    // Perform transfer
    if (ykhmac_data_exchange(send_buffer, 5 + aid_size, recv_buffer, &recv_length))
    {
        return ykhmac_response_code(recv_buffer, recv_length) == E_SUCCESS;
    }

    return false;
}

bool ykhmac_read_serial(uint32_t *serial)
{
    // Communication buffers
    uint8_t send_buffer[5];
    uint8_t recv_length = 6;
    uint8_t recv_buffer[recv_length];

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_API_REQ;
    send_buffer[2] = CMD_GET_SERIAL;
    send_buffer[3] = 0;
    send_buffer[4] = 6;

    // Perform transfer
    if (ykhmac_data_exchange(send_buffer, 5, recv_buffer, &recv_length))
    {
        if (ykhmac_response_code(recv_buffer, recv_length) == E_SUCCESS && recv_length >= 4)
        {
            *serial = ((uint32_t)recv_buffer[0] << 24) + ((uint32_t)recv_buffer[1] << 16) +
                      ((uint32_t)recv_buffer[2] << 8) + recv_buffer[3];
            return true;
        }
    }

    return false;
}

bool ykhmac_read_version(uint8_t version[3])
{
    // Communication buffers
    uint8_t send_buffer[5];
    uint8_t recv_length = 8;
    uint8_t recv_buffer[recv_length];

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_STATUS;
    send_buffer[2] = 0;
    send_buffer[3] = 0;
    send_buffer[4] = 6;

    // Perform transfer
    if (ykhmac_data_exchange(send_buffer, 5, recv_buffer, &recv_length))
    {
        if (ykhmac_response_code(recv_buffer, recv_length) == E_SUCCESS && recv_length >= 3)
        {
            memcpy(version, recv_buffer, 3);
            return true;
        }
    }

    return false;
}

bool ykhmac_exchange_hmac(const uint8_t slot, const uint8_t *challenge,
                          const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE])
{
    if (challenge_length > ARG_BUF_SIZE_MAX)
        return false;

    uint8_t slot_cmd = 0;
    if (slot == SLOT_1)
        slot_cmd = CMD_HMAC_1;
    else if (slot == SLOT_2)
        slot_cmd = CMD_HMAC_2;
    else
        return false;

    // Communication buffers
    uint8_t send_buffer[challenge_length + 5];
    uint8_t recv_length = RESP_BUF_SIZE + 2;
    uint8_t recv_buffer[recv_length];

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_API_REQ;
    send_buffer[2] = slot_cmd;
    send_buffer[3] = 0;
    send_buffer[4] = challenge_length;
    memcpy(send_buffer + 5, challenge, challenge_length);

    // Perform transfer
    if (ykhmac_data_exchange(send_buffer, 5 + challenge_length, recv_buffer, &recv_length))
    {
        if (ykhmac_response_code(recv_buffer, recv_length) == E_SUCCESS 
            && recv_length >= RESP_BUF_SIZE)
        {
            if (response != nullptr) memcpy(response, recv_buffer, RESP_BUF_SIZE);
            return true;
        }
    }

    return false;
}

uint8_t ykhmac_find_slots()
{
    uint8_t slots = 0;

    // Perform dummy challenge agains both slots
    uint8_t challenge[8];
    memset(challenge, 0x42, 8);

    if (ykhmac_exchange_hmac(SLOT_1, challenge, 8, nullptr))
        slots |= SLOT_1;
    if (ykhmac_exchange_hmac(SLOT_2, challenge, 8, nullptr))
        slots |= SLOT_2;

    return slots;
}

// Common buffers to save RAM
struct sha1_hasher_s sha_context;
uint8_t challenge[CHALLENGE_SIZE];
uint8_t response[RESP_BUF_SIZE];
uint8_t iv[AES_BLOCKLEN];
uint8_t padded_secret_key[SECRET_KEY_SIZE_PAD];
struct AES_ctx aes_context;
uint8_t computed_response[RESP_BUF_SIZE];

void ykhmac_purge_buffers()
{
    // Purge data from RAM
    memset(challenge, 0, CHALLENGE_SIZE);
    memset(response, 0, RESP_BUF_SIZE);
    memset(iv, 0, AES_BLOCKLEN);
    memset(padded_secret_key, 0, SECRET_KEY_SIZE_PAD);
    memset(&aes_context, 0, sizeof(AES_ctx));
    memset(computed_response, 0, RESP_BUF_SIZE);
}

bool ykhmac_compute_hmac(const uint8_t *key, const uint8_t *challenge,
                         const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE])
{
    // Init hasher using key and data
    sha1_hasher_init_hmac(&sha_context, key, SECRET_KEY_SIZE);
    for (uint8_t i = 0; i < challenge_length; i++)
    {
        if (sha1_hasher_putc(&sha_context, challenge[i]) == EOF)
            return false;
    }

    // Compute and return hash
    uint8_t *result = sha1_hasher_gethmac(&sha_context);
    memcpy(response, result, RESP_BUF_SIZE);

    // Purge hasher RAM
    memset(&sha_context, 0, sizeof(struct sha1_hasher_s));

    return true;
}

bool ykhmac_enroll_key(uint8_t secret_key[SECRET_KEY_SIZE])
{
    Serial.println("Enrolling key");

    Serial.print("Using secret key:     ");
    print_array(secret_key, SECRET_KEY_SIZE);
    Serial.println();
    Serial.flush();

    bool result = false;

    // Generate random challenge
    for (uint8_t i; i < CHALLENGE_SIZE; i++) challenge[i] = ykhmac_random();
    Serial.print("Random challenge:     ");
    print_array(challenge, CHALLENGE_SIZE);
    Serial.println();
    Serial.flush();

    // Compute response
    if (ykhmac_compute_hmac(secret_key, challenge, CHALLENGE_SIZE, response))
    {
        Serial.print("Computed response:    ");
        print_array(response, RESP_BUF_SIZE);
        Serial.println();
        Serial.flush();

        // Pad secret key using zeros (fixed size)
        memset(padded_secret_key + SECRET_KEY_SIZE, 0, SECRET_KEY_SIZE_PAD - SECRET_KEY_SIZE_PAD);
        memcpy(padded_secret_key, secret_key, SECRET_KEY_SIZE);
        Serial.print("Padded secret key:    ");
        print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
        Serial.println();
        Serial.flush();

        // Encrypt secret key using response as encryption key
        for (uint8_t i; i < AES_BLOCKLEN; i++) iv[i] = ykhmac_random();
        Serial.print("Using IV:             ");
        print_array(iv, AES_BLOCKLEN);
        Serial.println();
        Serial.flush();
        AES_init_ctx_iv(&aes_context, response, iv);
        AES_CBC_encrypt_buffer(&aes_context, padded_secret_key, SECRET_KEY_SIZE_PAD);
        Serial.print("Encrypted secret key: ");
        print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
        Serial.println();
        Serial.flush();

        // Store challenge, IV and encrypted secret key
        if (ykhmac_presistent_write(challenge, CHALLENGE_SIZE, 0) 
            && ykhmac_presistent_write(iv, AES_BLOCKLEN, CHALLENGE_SIZE) 
            && ykhmac_presistent_write(padded_secret_key, SECRET_KEY_SIZE_PAD, 
                CHALLENGE_SIZE + AES_BLOCKLEN))
        {
            result = true;
        }
    }

    ykhmac_purge_buffers();

    if (result)
        Serial.println("Successfully enrolled key");
    else
        Serial.println("Failed to enroll key");

    return result;
}

bool ykhmac_authenticate(const uint8_t slot)
{
    Serial.println("Authenticating key");

    bool result = false;

    // Load stored challenge
    if (ykhmac_presistent_read(challenge, CHALLENGE_SIZE, 0))
    {
        Serial.print("Loaded challenge:     ");
        print_array(challenge, CHALLENGE_SIZE);
        Serial.println();
        Serial.flush();

        // Perform challenge-response exchange
        if (ykhmac_exchange_hmac(slot, challenge, CHALLENGE_SIZE, response))
        {
            Serial.print("Exchanged response:   ");
            print_array(response, RESP_BUF_SIZE);
            Serial.println();
            Serial.flush();

            // Load IV and secret key
            if (ykhmac_presistent_read(iv, AES_BLOCKLEN, CHALLENGE_SIZE) 
                && ykhmac_presistent_read(padded_secret_key, SECRET_KEY_SIZE_PAD,
                    CHALLENGE_SIZE + AES_BLOCKLEN))
            {
                Serial.print("Loaded IV:            ");
                print_array(iv, AES_BLOCKLEN);
                Serial.println();
                Serial.flush();
                Serial.print("Loaded secret key:    ");
                print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
                Serial.println();
                Serial.flush();

                // Decrypt secret key
                AES_init_ctx_iv(&aes_context, response, iv);
                AES_CBC_decrypt_buffer(&aes_context, padded_secret_key, SECRET_KEY_SIZE_PAD);
                Serial.print("Decrypted secret key: ");
                print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
                Serial.println();
                Serial.flush();

                // Compute response using secret key
                if (ykhmac_compute_hmac(padded_secret_key, challenge, CHALLENGE_SIZE, computed_response))
                {
                    Serial.print("Computed response:    ");
                    print_array(computed_response, RESP_BUF_SIZE);
                    Serial.println();
                    Serial.flush();

                    // Check response
                    if (memcmp(response, computed_response, RESP_BUF_SIZE) == 0)
                    {
                        Serial.println("Responses match");

                        // Perform re-enrollment and re-encryption of the secret using a new challenge
                        result = ykhmac_enroll_key(padded_secret_key);
                    }
                    else
                    {
                        Serial.println("Responses do not match");
                    }
                }
            }
        }
    }

    ykhmac_purge_buffers();

    if (result)
        Serial.println("Successfully authenticated token");
    else
        Serial.println("Failed to authenticate token");

    return result;
}