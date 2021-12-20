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


// Communication buffers
uint8_t send_buffer[SEND_BUF_SIZE];
uint8_t recv_buffer[RECV_BUF_SIZE];
uint8_t recv_length;

#include <Arduino.h>
extern void print_array(const uint8_t* data, const size_t size);

// Decode APDU response code
uint8_t ykhmac_response_code()
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
bool ykhmac_select(const uint8_t* aid, const uint8_t aid_size)
{
    if (aid_size > ARG_BUF_SIZE_MAX) return false;

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_SELECT;
    send_buffer[2] = SEL_APP_AID;
    send_buffer[3] = 0;
    send_buffer[4] = aid_size;
    memcpy(send_buffer + 5, aid, aid_size);
    recv_length = RECV_BUF_SIZE;

    // Perform transfer
    if(ykhmac_data_exchange(send_buffer, 5 + aid_size, recv_buffer, &recv_length))
    {
        return ykhmac_response_code() == E_SUCCESS;
    }
    
    return false;
}

bool ykhmac_read_serial(uint32_t* serial)
{
    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_API_REQ;
    send_buffer[2] = CMD_GET_SERIAL;
    send_buffer[3] = 0;
    send_buffer[4] = 6;
    recv_length = RECV_BUF_SIZE;

    // Perform transfer
    if(ykhmac_data_exchange(send_buffer, 5, recv_buffer, &recv_length))
    {
        if(ykhmac_response_code() == E_SUCCESS && recv_length >= 4)
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
    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_STATUS;
    send_buffer[2] = 0;
    send_buffer[3] = 0;
    send_buffer[4] = 6;
    recv_length = RECV_BUF_SIZE;

    // Perform transfer
    if(ykhmac_data_exchange(send_buffer, 5, recv_buffer, &recv_length))
    {
        if(ykhmac_response_code() == E_SUCCESS && recv_length >= 3)
        {
            memcpy(version, recv_buffer, 3);
            return true;
        }
    }
    
    return false;
}

bool ykhmac_exchange_hmac(const uint8_t slot, const uint8_t* challenge, 
    const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE])
{
    if (challenge_length > ARG_BUF_SIZE_MAX) return false;

    uint8_t slot_cmd = 0;
    if (slot == SLOT_1) slot_cmd = CMD_HMAC_1;
    else if (slot == SLOT_2) slot_cmd = CMD_HMAC_2;
    else return false;

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_API_REQ;
    send_buffer[2] = slot_cmd;
    send_buffer[3] = 0;
    send_buffer[4] = challenge_length;
    memcpy(send_buffer + 5, challenge, challenge_length);
    recv_length = RECV_BUF_SIZE;

    // Perform transfer
    if(ykhmac_data_exchange(send_buffer, 5 + challenge_length, recv_buffer, &recv_length))
    {
        if(ykhmac_response_code() == E_SUCCESS && recv_length >= RESP_BUF_SIZE)
        {
            if(response != nullptr) memcpy(response, recv_buffer, RESP_BUF_SIZE);
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

    if(ykhmac_exchange_hmac(SLOT_1, challenge, 8, nullptr)) slots |= SLOT_1;
    if(ykhmac_exchange_hmac(SLOT_2, challenge, 8, nullptr)) slots |= SLOT_2;

    return slots;
}

bool ykhmac_compute_hmac(const uint8_t* key, const uint8_t* challenge, 
    const uint8_t challenge_length, uint8_t response[RESP_BUF_SIZE])
{
    // Init hasher using key and data
    sha1_hasher_t hasher = sha1_hasher_new();
    sha1_hasher_init_hmac (hasher, key, SECRET_KEY_SIZE);
    for(uint8_t i=0; i<challenge_length; i++) 
    {
        if(sha1_hasher_putc(hasher, challenge[i]) == EOF) return false;
    }

    // Compute and return hash
    uint8_t* result = sha1_hasher_gethmac(hasher);
    memcpy(response, result, RESP_BUF_SIZE);
    sha1_hasher_del(hasher);

    return true;
}

bool ykhmac_enroll_key(uint8_t secret_key[SECRET_KEY_SIZE])
{
    Serial.println("Enrolling key");
    Serial.print("Using secret key:     ");
    print_array(secret_key, SECRET_KEY_SIZE);
    Serial.println();

    // Generate random challenge
    uint8_t challenge[ARG_BUF_SIZE_MAX];
    for(uint8_t i; i<ARG_BUF_SIZE_MAX; i++) challenge[i] = ykhmac_random();
    Serial.print("Random challenge:     ");
    print_array(challenge, ARG_BUF_SIZE_MAX);
    Serial.println();

    // Compute response
    uint8_t response[RESP_BUF_SIZE];
    if(!ykhmac_compute_hmac(secret_key, challenge, ARG_BUF_SIZE_MAX, response)) return false;
    Serial.print("Computed response:    ");
    print_array(response, RESP_BUF_SIZE);
    Serial.println();

    // Pad secret key using zeros (fixed size)
    uint8_t padded_secret_key[SECRET_KEY_SIZE_PAD] = { 0 };
    memcpy(padded_secret_key, secret_key, SECRET_KEY_SIZE);
    Serial.print("Padded secret key:    ");
    print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
    Serial.println();

    // Encrypt secret key using response as encryption key
    uint8_t iv[AES_BLOCKLEN];
    for(uint8_t i; i<AES_BLOCKLEN; i++) iv[i] = ykhmac_random();
    Serial.print("Using IV:             ");
    print_array(iv, AES_BLOCKLEN);
    Serial.println();
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, response, iv);
    AES_CBC_encrypt_buffer(&ctx, padded_secret_key, SECRET_KEY_SIZE_PAD);
    Serial.print("Encrypted secret key: ");
    print_array(padded_secret_key, SECRET_KEY_SIZE_PAD);
    Serial.println();

    // Store challenge, iv and encrypted secret key
    if(!ykhmac_presistent_write(challenge, ARG_BUF_SIZE_MAX, 0)) return false;
    if(!ykhmac_presistent_write(iv, AES_BLOCKLEN, ARG_BUF_SIZE_MAX)) return false;
    if(!ykhmac_presistent_write(padded_secret_key, SECRET_KEY_SIZE_PAD, ARG_BUF_SIZE_MAX + AES_BLOCKLEN)) return false;

    // Purge data from RAM
    memset(challenge, 0, ARG_BUF_SIZE_MAX);
    memset(response, 0, RESP_BUF_SIZE);
    memset(iv, 0, AES_BLOCKLEN);
    memset(padded_secret_key, 0, SECRET_KEY_SIZE_PAD);
    memset(&ctx, 0, sizeof(AES_ctx));

    Serial.println("Successfully enrolled key");
    return true;
}