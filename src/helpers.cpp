/**
 * @file helpers.cpp
 * @author Christoph Honal
 * @brief Implements the functionality defined in helpers.h, as well as functions required by the ykhmac library
 * @version 0.1
 * @date 2021-12-17
 */

#include <EEPROM.h>
#include <Adafruit_PN532.h>

#include "helpers.h"


// Prints a byte array to the serial output
void print_array(const uint8_t* data, const size_t size)
{
    char hxdig[4] = {0};
    for (size_t i = 0; i < size; i++)
    {
        sprintf(hxdig, "%02x ", data[i]);
        Serial.print(hxdig);
    }
}

// Reads a 20 byte key from the serial input
void input_secret_key(uint8_t secret_key[SECRET_KEY_SIZE])
{
    Serial.print("Enter secret key (max. ");
    Serial.print(SECRET_KEY_SIZE * 2);
    Serial.print(" hexadecimal characters): ");
   
    // Read string from serial
    uint8_t data_len = 0;
    char data[SECRET_KEY_SIZE * 2];
    while (true)
    {
        delay(1);
        if (!Serial.available()) continue;
        char c = Serial.read();
        if (c == '\r') continue;
        if (c == '\n') break;
        if (data_len < SECRET_KEY_SIZE * 2)
        {
            data[data_len] = c;
            data_len++;
            Serial.print(c);
        }
    }
    Serial.print("\n");

    // Convert string to byte array
    memset(secret_key, 0, SECRET_KEY_SIZE);
    char substr[3] = { 0 };
    for (uint8_t i=0; i<data_len; i+=2)
    {
        memcpy(substr, data + i, 2);
        long b = strtol(substr, nullptr, 16);
        secret_key[i / 2] = (uint8_t)b;
    }
}


// Specific implementations of interface methods
bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length,
    uint8_t* response_buffer, uint8_t* response_length) 
{
    return nfc.inDataExchange(send_buffer, send_length, response_buffer, response_length);
}

uint8_t ykhmac_random()
{
    return (uint8_t)random(0, 255);
}

bool ykhmac_presistent_write(const uint8_t *data, const size_t size, const size_t offset)
{
    for(size_t i = 0; i<size; i++) 
    {
        EEPROM.write(i + offset + 1, data[i]);
    }

    //Read-back test
    for(size_t i = 0; i<size; i++) 
    {
        if (EEPROM.read(i + offset + 1) != data[i]) return false;
    }

    return true;
}

bool ykhmac_presistent_read(uint8_t *data, const size_t size, const size_t offset)
{
    for(size_t i = 0; i<size; i++) 
    {
        data[i] = EEPROM.read(i + offset + 1);
    }

    return true;
}

void ykhmac_debug_print(const __FlashStringHelper* message)
{
    Serial.print(message);
}

void ykhmac_debug_print(const char* message)
{
    Serial.print(message);
}