/**
 * @file ykhmac.cpp
 * @author Christoph Honal
 * @brief Implements the definitions from ykhmac.h
 * @version 0.1
 * @date 2021-12-17
 */

#include "ykhmac.h"

#include <sha/sha1.h>

// Communication buffers
uint8_t send_buffer[SEND_BUF_SIZE];
uint8_t recv_buffer[RECV_BUF_SIZE];
uint8_t recv_length;

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

bool ykhmac_compute_hmac(const uint8_t slot, const uint8_t* input, 
    const uint8_t input_length, uint8_t* output)
{
    if (input_length > ARG_BUF_SIZE_MAX || 
        input_length > CHALL_BUF_SIZE_MAX) return false;

    uint8_t slot_cmd = 0;
    if (slot == SLOT_1) slot_cmd = CMD_HMAC_1;
    else if (slot == SLOT_2) slot_cmd = CMD_HMAC_2;
    else return false;

    // Setup command buffers
    send_buffer[0] = CLA_ISO;
    send_buffer[1] = INS_API_REQ;
    send_buffer[2] = slot_cmd;
    send_buffer[3] = 0;
    send_buffer[4] = input_length;
    memcpy(send_buffer + 5, input, input_length);
    recv_length = RECV_BUF_SIZE;

    // Perform transfer
    if(ykhmac_data_exchange(send_buffer, 5 + input_length, recv_buffer, &recv_length))
    {
        if(ykhmac_response_code() == E_SUCCESS && recv_length >= RESP_BUF_SIZE)
        {
            if(output != nullptr) memcpy(output, recv_buffer, RESP_BUF_SIZE);
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

    if(ykhmac_compute_hmac(SLOT_1, challenge, 8, nullptr)) slots |= SLOT_1;
    if(ykhmac_compute_hmac(SLOT_2, challenge, 8, nullptr)) slots |= SLOT_2;

    return slots;
}