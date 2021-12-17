#include <Arduino.h>
#include <sha/sha1.h>

void setup(void) 
{
    Serial.begin(115200);
    while (!Serial) delay(10);
    Serial.print("Ready\n\n");
}

#define DATA_LEN_MAX 64
char data[DATA_LEN_MAX + 1];
short data_len;

void loop()
{
    Serial.print("Enter text (max. 64 chars): ");
   
    data_len = 0;
    while (true)
    {
        delay(1);
        if (!Serial.available())  continue;
        char c = Serial.read();
        if (c == '\r') continue;
        if (c == '\n') 
        {
            data[data_len] = '\0';
            break;
        }
        if (data_len < DATA_LEN_MAX)
        {
            data[data_len] = c;
            data_len++;
            Serial.print(c);
        }
    }
    Serial.print("\n");

    sha1_hasher_t hasher = sha1_hasher_new();
    sha1_hasher_init(hasher);
	sha1_hasher_write(hasher, data, data_len);
    uint8_t* result = sha1_hasher_gethash(hasher);
    
    Serial.print("Hash: ");
    char hxdig[2];
    for (int i = 0; i < SHA1_HASH_LEN; i++)
    {
        sprintf(hxdig, "%02x", result[i]);
        Serial.print(hxdig);
    }
    Serial.print("\n\n");

    sha1_hasher_del(hasher);
}