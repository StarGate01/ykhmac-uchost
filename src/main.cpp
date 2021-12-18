#include <Wire.h>
#include <Adafruit_PN532.h>
#include <EEPROM.h>
#include <ykhmac.h>

#define PN532_IRQ (2)
#define PN532_RESET (3)
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET); // Use I2C


void setup(void)
{
    Serial.begin(115200);
    while (!Serial) delay(10);
    Serial.println("Starting");

    // Initialize RNG, better than nothing
    randomSeed(analogRead(0));

    // Start module communication
    nfc.begin();
    uint32_t versiondata = nfc.getFirmwareVersion();
    if (!versiondata)
    {
        Serial.print("Cannot find PN53x module, reconnect and reset");
        while (1);
    }
    Serial.print("Found NFC module PN5");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Module firmware version ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);

    // Setup module
    nfc.setPassiveActivationRetries(0xFF);
    nfc.SAMConfig();
}

void print_array(const uint8_t* data, const size_t size)
{
    char hxdig[4] = {0};
    for (size_t i = 0; i < size; i++)
    {
        sprintf(hxdig, "%02x:", data[i]);
        Serial.print(hxdig);
    }
}


// Specific implementations of interface methods
bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length,
    uint8_t* response_buffer, uint8_t* response_length) 
{
    return nfc.inDataExchange(send_buffer, send_length, response_buffer, response_length);
}

int32_t ykhmac_random()
{
    return random();
}

bool ykhmac_presistent_write(const uint8_t *data, const uint8_t size)
{
    for(uint8_t i = 0; i<size; i++) EEPROM.write(i, data[i]);
    return true;
}

bool ykhmac_presistent_read(uint8_t *data, const uint8_t size)
{
    for(uint8_t i = 0; i<size; i++) data[i] = EEPROM.read(i);
    return true;
}


// AID of the yubikey hmac applet
const uint8_t aid[YUBIKEY_AID_LENGTH] = YUBIKEY_AID;

// Example of the token interfacing functions
void full_scan()
{
    uint32_t serial = 0;

    if (ykhmac_read_serial(&serial))
    {
        Serial.print("Serial number: ");
        Serial.println(serial);

        uint8_t version[3] = {0};

        if (ykhmac_read_version(version))
        {
            Serial.print("Firmware version: ");
            Serial.print(version[0]);
            Serial.print(".");
            Serial.print(version[1]);
            Serial.print(".");
            Serial.println(version[2]);

            uint8_t challenge[] = { 0x42, 0x13, 0x37, 0xCA, 0xFE };
            uint8_t response[RESP_BUF_SIZE] = { 0 };

            // Test slots
            uint8_t slots = ykhmac_find_slots();
            if (slots != 0) 
            {
                // Perform challenge-response for each slot found
                for(uint8_t i = SLOT_1; i <= SLOT_2; i++)
                {
                    if (slots & i)
                    {
                        Serial.print("Slot ");
                        Serial.print(i);
                        Serial.println(" configured");

                        if(ykhmac_compute_hmac(i, challenge, 5, response))
                        {
                            Serial.print("  Challenge: ");
                            print_array(challenge, 5);
                            Serial.println();

                            Serial.print("  Response: ");
                            print_array(response, RESP_BUF_SIZE);
                            Serial.println();
                        }
                        else Serial.println("Challenge-response error");
                    }
                }
            }
            else Serial.println("No slots configured");
        }
        else Serial.println("Read version error");
    }
    else Serial.println("Read serial error");
}


// Example of just challenge-response with predefined slot
void simple_chalresp()
{
    uint8_t challenge[] = { 0x42, 0x13, 0x37, 0xCA, 0xFE };
    uint8_t response[RESP_BUF_SIZE] = { 0 };
    
    if(ykhmac_compute_hmac(SLOT_1, challenge, 5, response))
    {
        Serial.print("Challenge: ");
        print_array(challenge, 5);
        Serial.println();

        Serial.print("Response: ");
        print_array(response, RESP_BUF_SIZE);
        Serial.println();
    }
    else Serial.println("Challenge-response error");
}

// Enrolls a key into the persistent storage
void enroll()
{
    
}


void loop(void)
{
    // Block until a token arrives
    Serial.println("\nWaiting for token...");
    if (nfc.inListPassiveTarget())
    {
        Serial.println("Found token");
        
        // Applet has to be selected
        if (ykhmac_select(aid, YUBIKEY_AID_LENGTH))
        {
            Serial.println("Select OK");

            //full_scan();
            simple_chalresp();
        }
        else Serial.println("Select error");
    }
}