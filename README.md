# ykhmac-uchost

Yubikey **HMAC-SHA1 challenge-response** authentication via **NFC** for embedded host systems.

[Blog post for more details](https://chrz.de/2021/12/22/nfc-hacking-part-1-authentication-systems-security/).

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

The `ykhmac` library is available on [PlatformIO here](https://platformio.org/lib/show/13310/ykhmac/). It requires the [cryptosuite2](https://github.com/daknuett/cryptosuite2) and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) libraries. Both the library and its dependencies are agnostic of any frameworks or hardware platforms. The recommendated compilation flags for those libraries are `-DSHA1_DISABLE_WRAPPER -DSHA256_DISABLE_WRAPPER -DSHA256_DISABLED -DECB=0 -DCTR=0` to minify the code size.

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

The size of the challenge buffer may be `HW_BUF_SIZE - SEND_BUF_OVERH - 5 = ARG_BUF_SIZE_MAX` bytes at maximum. Using the default values, the challenge may be `57` bytes long at maximum. The size of the generated challenges can be configured by defining `CHALLENGE_SIZE` (default `ARG_BUF_SIZE_MAX`).

Pay attention to the challenge padding behavior of the Yubikey: It considers the last byte as padding if and only if the challenge size is `64` bytes long (its maximum), but then also all preceding bytes of the same value.

The size of the the response buffer is `20` bytes, this is inherent to SHA1 but can by changed by defining `RESP_BUF_SIZE` depending on your token. The size of the secret key can be changed by defining `SECRET_KEY_SIZE` (default `20`).

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
    <summary>Key enrollment log</summary>

```
Starting
Found NFC module PN532
Module firmware version 1.6
Invalidating enrollment
Enter secret key (max. 40 hexadecimal characters): b6e3f555562c894b7af13b1db37f28deff3ea89b
Enrolling key
Using secret key:     b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 
Random challenge:     24 5e 5a 69 da a8 0f e6 14 f6 04 14 ef 06 3f 01 da d8 13 6f 33 64 0a 2c 9a 71 55 16 70 a6 98 a8 6e 72 bd 9e 7d 03 47 12 cc 0b a5 a6 6e 1f 3e 35 ab ca a9 93 55 4a e1 d2 a7 
Computed response:    f8 7b 62 6d 77 ad 56 46 5f 28 c0 01 67 c7 ae 96 73 af 96 f0 
Padded secret key:    b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 00 00 00 00 00 00 00 00 00 00 00 00 
Using IV:             dd 99 69 62 48 97 63 c4 17 d8 16 60 f3 89 2d fa 
Encrypted secret key: 27 19 ab 85 06 21 b6 d2 90 d2 a8 b4 1a 4a c6 7e 17 5b 57 80 8f 5e ee b9 3c 7e 16 c9 36 66 8d bd 
Wrote data to persistent storage
Successfully enrolled key
```

</details>

<details>
    <summary>Successful authentication debug log</summary>

```
Tag number: 1
Found token
Select OK
Authenticating key
Loaded challenge:     24 5e 5a 69 da a8 0f e6 14 f6 04 14 ef 06 3f 01 da d8 13 6f 33 64 0a 2c 9a 71 55 16 70 a6 98 a8 6e 72 bd 9e 7d 03 47 12 cc 0b a5 a6 6e 1f 3e 35 ab ca a9 93 55 4a e1 d2 a7 
Exchanged response:   f8 7b 62 6d 77 ad 56 46 5f 28 c0 01 67 c7 ae 96 73 af 96 f0 
Loaded IV:            dd 99 69 62 48 97 63 c4 17 d8 16 60 f3 89 2d fa 
Loaded secret key:    27 19 ab 85 06 21 b6 d2 90 d2 a8 b4 1a 4a c6 7e 17 5b 57 80 8f 5e ee b9 3c 7e 16 c9 36 66 8d bd 
Decrypted secret key: b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 00 00 00 00 00 00 00 00 00 00 00 00 
Computed response:    f8 7b 62 6d 77 ad 56 46 5f 28 c0 01 67 c7 ae 96 73 af 96 f0 
Responses match
Enrolling key
Using secret key:     b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 
Random challenge:     85 9d fc c0 e0 f7 8d 87 dc 35 6a 1e b4 cc 65 8b d2 cc 99 de 4d 75 f7 c9 09 eb d3 b1 2c 62 31 5d 8a 2d 94 3a c0 6c e8 c1 0e 59 57 48 5a 49 94 67 e9 c8 c8 33 2a 47 ae 33 91 
Computed response:    30 3f 05 8f 30 89 22 d6 e8 05 52 da 94 bb 41 5f 1a 1f 50 69 
Padded secret key:    b6 e3 f5 55 56 2c 89 4b 7a f1 3b 1d b3 7f 28 de ff 3e a8 9b 00 00 00 00 00 00 00 00 00 00 00 00 
Using IV:             c7 23 73 fa 5d 9e 53 9f 17 bb 24 45 25 f2 62 91 
Encrypted secret key: af 51 c3 a8 ec 6e 0a a7 93 79 54 52 4f 31 d1 a2 7f 85 42 0a 68 c3 ec 23 61 5b cb 8c f6 97 ad ba 
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
Loaded challenge:     85 9d fc c0 e0 f7 8d 87 dc 35 6a 1e b4 cc 65 8b d2 cc 99 de 4d 75 f7 c9 09 eb d3 b1 2c 62 31 5d 8a 2d 94 3a c0 6c e8 c1 0e 59 57 48 5a 49 94 67 e9 c8 c8 33 2a 47 ae 33 91 
Exchanged response:   f0 91 bb 96 bd 9b 44 07 d2 05 cd 45 cc ec 05 ed 22 3d bf 9b 
Loaded IV:            c7 23 73 fa 5d 9e 53 9f 17 bb 24 45 25 f2 62 91 
Loaded secret key:    af 51 c3 a8 ec 6e 0a a7 93 79 54 52 4f 31 d1 a2 7f 85 42 0a 68 c3 ec 23 61 5b cb 8c f6 97 ad ba 
Decrypted secret key: b3 e4 ac 12 ce 6d b5 61 18 64 49 1f de b4 30 3c c3 3e 3d 70 91 c8 54 45 f9 4c fb 49 9d a7 52 c8 
Computed response:    bc 15 bb bb 14 1c b5 03 35 6b 86 3d 15 39 88 7c e0 87 b3 72 
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
