# ykhmac-uchost

Yubikey **HMAC-SHA1 challenge-response** authentication via **NFC** for embedded host systems.

Tested target hardware:
 - [Yubikey 5 NFC](https://www.yubico.com/de/product/yubikey-5-nfc/) version 5.4.3
 - Yubikey 5 NFC version 5.2.6
 - [Fidesmo card 2.0](https://shop.fidesmo.com/products/fidesmo-card-2-0) running [vk-ykhmac](https://github.com/StarGate01/vk-ykhmac)
 - [Generic NXP P71](https://www.nxp.com/products/security-and-authentication/security-controllers/smartmx3-p71d321-secure-and-flexible-microcontroller:SMARTMX3-P71D321) running vk-ykhmac

Tested host hardware:
 - [Arduino Uno](https://store.arduino.cc/products/arduino-uno-rev3/) R3

### Development

Download [Visual Studio Code](https://code.visualstudio.com/) and [PlatformIO](https://platformio.org/) to load and compile this project. The example code is configured to build for Arduino.

### Standalone library

The `ykhmac` library is available on PlatformIO at (TBA). It requires the [cryptosuite2](https://github.com/daknuett/cryptosuite2) and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) libraries. Both the library and its dependencies are agnostic of any frameworks or hardware platforms. The recommendated compilation flags for those libraries are `-DSHA1_DISABLE_WRAPPER -DSHA256_DISABLE_WRAPPER -DSHA256_DISABLED -DECB=0 -DCTR=0` to minify the code size.

This repository contains forks of both dependencies as submodules, which contains a few adjustments for PlatformIO and AVR. Most changes have been upstreamed, however e.g. the `__attribute__((__progmem__))` attribute for the AES lookup tables are AVR specific and are special to this fork.

The user is required to implement various interfaces:

<details>
    <summary>A data exchange function using the correct driver library for the NFC hardware used</summary>

```cpp
/**
 * @brief Declaration of NFC hardware interfacing function
 * 
 * @param send_buffer Buffer to be sent to the target
 * @param send_length Amount of bytes to be sent
 * @param response_buffer Buffer to be read from the target
 * @param response_length Amount of bytes to be read
 * @return true on success
 */
bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length, uint8_t* response_buffer, uint8_t* response_length);
```

</details>

<details>
    <summary>A sufficiently secure random number generator (hardware RNG, CPRNG, ...)</summary>

```cpp
/**
 * @brief Declaration of random number generator
 * 
 * @return Random byte
 */
uint8_t ykhmac_random();
```

</details>

<details>
    <summary>A method to read and write a challenge buffer persistently</summary>

Use Flash, EEPROM, ..., to enable rolling keys. At least `(HW_BUF_SIZE - SEND_BUF_OVERH - 5) + AES_BLOCKLEN + (((SECRET_KEY_SIZE / AES_BLOCKLEN) + 1) * AES_BLOCKLEN)` bytes are required. Using the default configuration, this comes out at `(64 - 2 - 5) + 16 + (((20 / 16 ) + 1) * 16) = 109`.

```cpp
/**
 * @brief Declaration of a persistent write function
 * 
 * @param data  Buffer to be written from
 * @param size Amount of bytes to be written
 * @param offset Where to write the bytes to
 * @return true on success
 */
bool ykhmac_presistent_write(const uint8_t *data, const size_t size, const size_t offset);

/**
 * @brief Declaration of a persistent read function
 * 
 * @param data  Buffer to be read into
 * @param size Amount of bytes to be read
 * @param offset Where to read the bytes from
 * @return true on success
 */
bool ykhmac_presistent_read(uint8_t *data, const size_t size, const size_t offset);
```

</details>

For example implementations, see the file `helpers.cpp`.

In addition, the preprocessor constant `HW_BUF_SIZE` may be defined (default `64`) to specify the size of the internal transfer buffer of the NFC chip used. The library ensures that no transfer exceeds the specified buffer size. It assumes specific protocol overheads (i.e. non-useable bytes in the transfer buffer), these can be changed by defining the constants `SEND_BUF_OVERH` (default `2`) and `RECV_BUF_OVERH` (default `8`).

The size of the challenge buffer may be `HW_BUF_SIZE - SEND_BUF_OVERH - 5` bytes at maximum. Using the default values, the challenge may be `57` bytes long at maximum. The size of the generated challenges can be configured by defining `CHALLENGE_SIZE` (default `32` due to memory constraints).

Pay attention to the challenge padding behavior of the Yubikey: It considers the last byte as padding if and only if the challenge size is `64` bytes long (its maximum), but then also all preceding bytes of the same value.

The size of the the response buffer is `20` bytes, this is inherent to SHA1 but can by changed by defining `RESP_BUF_SIZE` depending on your token. The size of the secret key can be changed by defining `SECRET_KEY_SIZE` (default `ARG_BUF_SIZE_MAX`).

Before you can use the token, the select procedure with the correct AID has to be called.

For documentation of the library, read the header file and look at the example, it implement the enrollment and authentication flow. Also see the `full_scan`, `simple_chalresp` example functions. The example code implements support for the `PN532` NFC module (via SPI, as I2C is not recommended due to buffer limitations) on the `Arduino` platform.

#### Debugging

You can define the macro `YKHMAC_DEBUG`, which will cause the library to print all used keys and buffer transformations to the serial output. This should obviously **not be used in production**. 

<details>
    <summary>You have to implement some printing functions</summary>

```cpp
/**
 * @brief Prints a zero-terminated string to a debug output
 * 
 * @param message The message to print
 */
void ykhmac_debug_print(const char* message);

```

On Arduino AVR platforms, the library will move all debug string to the EEPROM, for this you have to define an additional printing function:

```cpp
/**
 * @brief Prints a Arduino PROGMEM string to a debug output
 * 
 * @param message The message to print
 */
void ykhmac_debug_print(const __FlashStringHelper* message);
```

</details>

For example implementations, see the file `helpers.cpp`.

### Authentication scheme

To understand how the authentication algorithm works, read [my blog post](https://chrz.de/?p=542), *"Method 4: Challenge-Response, Without Reusing Challenges but with Encrypted Keys"*. It is also documented [here](http://www.average.org/chal-resp-auth/).

<details>
    <summary>Successful authentication debug log</summary>

```
Tag number: 1
Found token
Select OK
Authenticating key
Loaded challenge:     f5 84 18 36 ba 34 f3 ef 8e d2 75 35 bd 64 0c 21 78 77 d4 d7 39 dd 6f 6d 28 16 d0 8d d9 25 89 99 
Exchanged response:   76 dd e8 8d 8e 6c dc 5a d8 22 8c 14 4e 9a 06 00 b8 a9 d5 bc 
Loaded IV:            11 ad 0c 25 15 a2 e1 17 79 5b c7 42 26 9a fb 56 
Loaded secret key:    45 d0 60 c2 5f c8 4e 1a 14 cf 74 c6 8a c4 65 26 37 40 8c c1 5f a7 f4 c4 88 a8 ce 94 97 5d f7 d4 
Decrypted secret key: b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 00 00 00 00 00 00 00 00 00 00 00 00 
Computed response:    76 dd e8 8d 8e 6c dc 5a d8 22 8c 14 4e 9a 06 00 b8 a9 d5 bc 
Responses match
Enrolling key
Using secret key:     b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 
Random challenge:     c7 2b 56 03 9a 40 d8 79 88 ae e6 56 0b c2 d8 c0 16 16 96 40 bf 57 55 ae 35 ba cc 05 43 23 7a 0b 
Computed response:    ea 3a dc d0 09 11 cc 8c 75 a5 b5 73 bc fe 32 23 65 b2 30 94 
Padded secret key:    b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 00 00 00 00 00 00 00 00 00 00 00 00 
Using IV:             33 e8 da ab 2d c1 7c 9b a5 ab 6a 5e dd 95 b9 77 
Encrypted secret key: c7 2e cb c8 f3 9f 9d a0 94 5a ca d8 86 31 08 07 30 34 ac 67 8f 4c e9 ad 37 e9 3a 40 65 6f 97 98 
Wrote data to persistent storage
Successfully enrolled key
Successfully authenticated token
Access granted :)
```

</details>

<details>
    <summary>Unsuccessful authentication debug log</summary>

```
Tag number: 1
Found token
Select OK
Authenticating key
Loaded challenge:     c7 2b 56 03 9a 40 d8 79 88 ae e6 56 0b c2 d8 c0 16 16 96 40 bf 57 55 ae 35 ba cc 05 43 23 7a 0b 
Exchanged response:   cb bd 95 6d 08 90 a7 98 4e 15 ab 47 37 6e 7a df 31 2b 0e b3 
Loaded IV:            33 e8 da ab 2d c1 7c 9b a5 ab 6a 5e dd 95 b9 77 
Loaded secret key:    c7 2e cb c8 f3 9f 9d a0 94 5a ca d8 86 31 08 07 30 34 ac 67 8f 4c e9 ad 37 e9 3a 40 65 6f 97 98 
Decrypted secret key: 26 58 66 a5 30 b3 52 21 0f 7b d5 30 8a fa bd 2a 79 3a 9c 00 ee ef a5 7c a9 ac f6 de d4 4d 2b 7c 
Computed response:    7c 8e 90 62 96 27 8e ef af f5 ea b1 7a bb 03 eb 5c 31 44 fe 
Responses do not match
Failed to authenticate token
Communication error or access denied :(
```

</details>

## Thanks to / Sources

- http://www.average.org/chal-resp-auth/
- https://github.com/arekinath/yktool
- https://github.com/keepassxreboot/keepassxc

### Third-party libraries

- [Arduino](https://www.arduino.cc/)
- [Adafruit BusIO](https://platformio.org/lib/show/6214/Adafruit%20BusIO)
- [Adafruit PN532](https://platformio.org/lib/show/29/Adafruit%20PN532)
- [Cryptosuite2](https://platformio.org/lib/show/5829/cryptosuite2)
- [tiny-AES-c](https://platformio.org/lib/show/5421/tiny-AES-c)