#ifndef HELPERS_H
#define HELPERS_H

#include <Arduino.h>
#include <ykhmac.h>

// Prints a byte array to the serial output
void print_array(const uint8_t* data, const size_t size);

// Reads a 20 byte key from the serial input
void input_secret_key(uint8_t secret_key[SECRET_KEY_SIZE]);

#endif