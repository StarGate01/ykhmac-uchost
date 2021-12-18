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
    if (aid_size > AID_LENGTH_MAX) return false;

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
