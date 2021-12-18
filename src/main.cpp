#include <Wire.h>
#include <Adafruit_PN532.h>
#include <ykhmac.h>

#define PN532_IRQ (2)
#define PN532_RESET (3)
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET); // Use I2C


void setup(void)
{
    Serial.begin(115200);
    while (!Serial) delay(10);
    Serial.println("Starting");

    // Start module communication
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata)
    {
        Serial.print("Cannot find PN53x module, reconnect and reset");
        while (1);
    }
    Serial.print("Found chip PN5");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Firmware ver. ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);

    // Setup module
    nfc.setPassiveActivationRetries(0xFF);
    nfc.SAMConfig();
}


const uint8_t aid[YUBIKEY_AID_LENGTH] = YUBIKEY_AID;

bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length,
    uint8_t* response_buffer, uint8_t* response_length) 
{
    return nfc.inDataExchange(send_buffer, send_length, response_buffer, response_length);
}

void loop(void)
{
    Serial.println("\nWaiting for token...");
    if (nfc.inListPassiveTarget())
    {
        Serial.println("Found token");
        
        if (ykhmac_select(aid, YUBIKEY_AID_LENGTH))
        {
            Serial.println("Select OK");
        }
        else
        {
            Serial.println("Select error");
        }
    }
}