# ykhmac-uchost

Yubikey **HMAC-SHA1 challenge-response** authentication via **NFC** for embedded host systems.

Tested target hardware:
 - [Yubikey 5 NFC](https://www.yubico.com/de/product/yubikey-5-nfc/) version 5.4.3
 - Yubikey 5 NFC version 5.2.6
 - [Fidesmo card 2.0](https://shop.fidesmo.com/products/fidesmo-card-2-0) running [vk-ykhmac](https://github.com/StarGate01/vk-ykhmac)
 - [Generic NXP P71](https://www.nxp.com/products/security-and-authentication/security-controllers/smartmx3-p71d321-secure-and-flexible-microcontroller:SMARTMX3-P71D321) running vk-ykhmac

### Development

Download [Visual Studio Code](https://code.visualstudio.com/) and [PlatformIO](https://platformio.org/) to load and compile this project. The example code is configured to build for Arduino.

### Standalone library

The `ykhmac` library is available on PlatformIO at (TBA). It requires the [cryptosuite2](https://github.com/daknuett/cryptosuite2) and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) libraries. Both the library and its dependencies are agnostic of any frameworks or hardware platforms. Instead, the user is required to implement various interfaces.

A data exchange function using the correct driver library for the NFC hardware used:

```cpp
/**
 * @param send_buffer Buffer to be sent to the target
 * @param send_length Amount of bytes to be sent
 * @param response_buffer Buffer to be read from the target
 * @param response_length Amount of bytes to be read
 * @return true on success
 */
bool ykhmac_data_exchange(uint8_t *send_buffer, uint8_t send_length, uint8_t* response_buffer, uint8_t* response_length)
```

A sufficiently secure random number generator (hardware RNG, CPRNG, ...):

```cpp
/**
 * @return Random 32 bit signed integer
 */
int32_t ykhmac_random()
```

A method to read and write a challenge buffer persistently (Flash, EEPROM ...), to enable rolling keys:

```cpp
/**
 * @param data  Buffer to be written from
 * @param size Amount of bytes to be written
 * @return true on success
 */
bool ykhmac_presistent_write(const uint8_t *data, const uint8_t size)

/**
 * @param data  Buffer to be read into
 * @param size Amount of bytes to be read
 * @return true on success
 */
bool ykhmac_presistent_read(uint8_t *data, const uint8_t size)
```

In addition, the preprocessor constant `HW_BUF_SIZE` may be defined (default `64`) to specify the size of the internal transfer buffer of the NFC chip used. The library ensures that no transfer exceeds the specified buffer size. It assumes specific protocol overheads (i.e. non-useable bytes in the transfer buffer), these can be changed by defining the constants `SEND_BUF_OVERH` (default `2`) and `RECV_BUF_OVERH` (default `8`).

The size of the challenge buffer may be `min(HW_BUF_SIZE - SEND_BUF_OVERH - 5, CHALL_BUF_SIZE_MAX)` bytes at maximum. You can change the maximum length of the challenge which the token can handle by defining `CHALL_BUF_SIZE_MAX` (default `64`). Using the default values, the challenge may be `57` bytes long at maximum.

Pay attention to the challenge padding behavior of the Yubikey: It considers the last byte as padding if and only if the challenge size is `64` bytes long (its maximum), but then also all preceding bytes of the same value.

The size of the the response buffer is `20` bytes, this can by changed by defining `RESP_BUF_SIZE` depending on your token.

For documentation of the library, read the header file and look at the example (see the `full_scan`, `simple_chalresp` etc. functions). The example code implements support for the `PN532` NFC module (via I2C) on the `Arduino` platform.

### Authentication modes

Three modes of authentication are implemented.

**Static secret key**: Both the host and the target store the secret key. The host validates the target by sending a challenge and performing 

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