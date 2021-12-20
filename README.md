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

The `ykhmac` library is available on PlatformIO at (TBA). It requires the [cryptosuite2](https://github.com/daknuett/cryptosuite2) and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) libraries. Both the library and its dependencies are agnostic of any frameworks or hardware platforms. 

This repository contains forks of both dependencies as submodules, which contains a few adjustments for PlatformIO and AVR. Most changes have been upstreamed, however e.g. the `__attribute__((__progmem__))` attribute for the AES lookup tables are AVR specific and are special to this fork.

The user is required to implement various interfaces:

A data exchange function using the correct driver library for the NFC hardware used.

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

A sufficiently secure random number generator (hardware RNG, CPRNG, ...).

```cpp
/**
 * @brief Declaration of random number generator
 * 
 * @return Random byte
 */
uint8_t ykhmac_random();
```

A method to read and write a challenge buffer persistently (Flash, EEPROM ...), to enable rolling keys. At least `(HW_BUF_SIZE - SEND_BUF_OVERH - 5) + AES_BLOCKLEN + (((SECRET_KEY_SIZE / AES_BLOCKLEN) + 1) * AES_BLOCKLEN)` bytes are required. Using the default configuration, this comes out at `(64 - 2 - 5) + 16 + (((20 / 16 ) + 1) * 16) = 109`.

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

In addition, the preprocessor constant `HW_BUF_SIZE` may be defined (default `64`) to specify the size of the internal transfer buffer of the NFC chip used. The library ensures that no transfer exceeds the specified buffer size. It assumes specific protocol overheads (i.e. non-useable bytes in the transfer buffer), these can be changed by defining the constants `SEND_BUF_OVERH` (default `2`) and `RECV_BUF_OVERH` (default `8`).

The size of the challenge buffer may be `HW_BUF_SIZE - SEND_BUF_OVERH - 5` bytes at maximum. Using the default values, the challenge may be `57` bytes long at maximum. The size of the generated challenges can be configured by defining `CHALLENGE_SIZE` (default `32` due to memory constraints).

Pay attention to the challenge padding behavior of the Yubikey: It considers the last byte as padding if and only if the challenge size is `64` bytes long (its maximum), but then also all preceding bytes of the same value.

The size of the the response buffer is `20` bytes, this is inherent to SHA1 but can by changed by defining `RESP_BUF_SIZE` depending on your token. The size of the secret key can be changed by defining `SECRET_KEY_SIZE` (default `ARG_BUF_SIZE_MAX`).

Before you can use the token, the select procedure with the correct AID has to be called.

For documentation of the library, read the header file and look at the examples (see the `full_scan`, `simple_chalresp` etc. functions). The example code implements support for the `PN532` NFC module (via SPI, as I2C is not recommended due to buffer limitations) on the `Arduino` platform.

### Authentication scheme

To understand how the authentication algorithm works, read [my blog post](https://chrz.de/?p=542), *"Method 4: Challenge-Response, Without Reusing Challenges but with Encrypted Keys"*. It is also documented [here](http://www.average.org/chal-resp-auth/).

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