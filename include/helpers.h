/**
 * @file helpers.h
 * @author Christoph Honal
 * @brief Declares some helper functions using in main.cpp
 * @version 0.1
 * @date 2021-12-17
 */

#ifndef HELPERS_H
#define HELPERS_H

#include <Arduino.h>
#include <ykhmac.h>

extern Adafruit_PN532 nfc; //!< NFC library, symbol from main.cpp

/**
 * @brief Prints an array to the serial output
 * 
 * @param data The array to print
 * @param size The amount of bytes in the array
 */
void print_array(const uint8_t* data, const size_t size);

/**
 * @brief Reads a SECRET_KEY_SIZE byte key from the serial input
 * 
 * @param secret_key Buffer to fill with the secret key
 */
void input_secret_key(uint8_t secret_key[SECRET_KEY_SIZE]);

#endif