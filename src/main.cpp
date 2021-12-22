#include <Adafruit_PN532.h>
#include <ykhmac.h>
#include <EEPROM.h>

#include "helpers.h"

#define FORGET_BTN 3
Adafruit_PN532 nfc(13, 12, 11, 10); // Use SPI

// AID of the yubikey hmac applet
const uint8_t aid[YUBIKEY_AID_LENGTH] = YUBIKEY_AID;


void setup(void)
{
    Serial.begin(115200);
    while (!Serial) delay(10);
    Serial.println(F("Starting"));

    // Initialize RNG using ADC noise
    randomSeed(analogRead(0));

    // Setup forget button
    pinMode(FORGET_BTN, INPUT_PULLUP);

    // Start module communication
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata)
    {
        Serial.print(F("Cannot find PN53x module, reconnect and reset"));
        while (1);
    }
    Serial.print(F("Found NFC module PN5"));
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print(F("Module firmware version "));
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);

    // Setup module
    nfc.setPassiveActivationRetries(0xFF);
    nfc.SAMConfig();

    Serial.flush();
}


// Example of just challenge-response with predefined slot
void simple_chalresp(uint8_t slot)
{
    const uint8_t secret_key[SECRET_KEY_SIZE] = { 0xb6, 0xe3, 0xf5, 
        0x55, 0x56, 0x2c, 0x89, 0x4b, 0x7a, 0xf1, 0x3b, 0x1d, 
        0xb3, 0x7f, 0x28, 0xde, 0xff, 0x3e, 0xa8, 0x9b };
    uint8_t challenge[] = { 0x42, 0x13, 0x37, 0xCA, 0xFE };
    uint8_t response[RESP_BUF_SIZE] = { 0 };

    Serial.print("Challenge: ");
    print_array(challenge, 5);
    Serial.println();

    if(ykhmac_exchange_hmac(slot, challenge, 5, response))
    {
        Serial.print("Response: ");
        print_array(response, RESP_BUF_SIZE);
        Serial.println();
    }
    else Serial.println("Challenge-response error");

    memset(response, 0, RESP_BUF_SIZE); // sanity check
    if(ykhmac_compute_hmac(secret_key, challenge, 5, response))
    {
        Serial.print("Computed: ");
        print_array(response, RESP_BUF_SIZE);
        Serial.println();
    }
    else Serial.println("Challenge computation error");
}

// Example of the token interfacing functions
void full_scan()
{
    uint32_t serial = 0;

    if (ykhmac_read_serial(&serial))
    {
        Serial.print(F("Serial number: "));
        Serial.println(serial);

        uint8_t version[3] = {0};

        if (ykhmac_read_version(version))
        {
            Serial.print(F("Firmware version: "));
            Serial.print(version[0]);
            Serial.print(".");
            Serial.print(version[1]);
            Serial.print(".");
            Serial.println(version[2]);

            // Test slots
            uint8_t slots = ykhmac_find_slots();
            if (slots != 0) 
            {
                // Perform challenge-response for each slot found
                for(uint8_t i = SLOT_1; i <= SLOT_2; i++)
                {
                    if (slots & i)
                    {
                        Serial.print(F("Slot "));
                        Serial.print(i);
                        Serial.println(F(" configured"));

                        simple_chalresp(i);
                    }
                }
            }
            else Serial.println(F("No slots configured"));
        }
        else Serial.println(F("Read version error"));
    }
    else Serial.println(F("Read serial error"));
}


void loop(void)
{
    // First byte in EEPROM is used to mark enrollment status
    if(EEPROM.read(0) != 1)
    {
        // Enroll key
        uint8_t secret_key[SECRET_KEY_SIZE];
        input_secret_key(secret_key);
        Serial.flush();
        if(ykhmac_enroll_key(secret_key)) EEPROM.write(0, 1);

        // Purge key from RAM
        memset(secret_key, 0, SECRET_KEY_SIZE);
        Serial.println();
    }
    else
    {
        // When the forget pin is connected to ground,
        // the enrollment is invalidated
        if(digitalRead(FORGET_BTN) == LOW)
        {
            Serial.println(F("Invalidating enrollment"));
            EEPROM.write(0, 0);
            return;
        }

        // Block until a token arrives
        if (nfc.inListPassiveTarget())
        {
            Serial.println(F("Found token"));
            
            // Applet has to be selected
            if (ykhmac_select(aid, YUBIKEY_AID_LENGTH))
            {
                Serial.println(F("Select OK"));

                // Perform authentication
                if(ykhmac_authenticate(SLOT_1))
                {
                    Serial.println(F("Access granted :)"));
                }
                else
                {
                    Serial.println(F("Communication error or access denied :("));
                }

                // full_scan();
                // simple_chalresp();
            }
            else Serial.println(F("Select error"));
            Serial.println();
        }
    }
}