# ykhmac-uchost

Yubikey HMAC-SHA1 challenge-response authentication on Arduino.

This project was developed using the **PN532 NFC** module, however the library logic is generic and should work with any NFC module and driver.

### Development

Download [Visual Studio Code](https://code.visualstudio.com/) and [PlatformIO](https://platformio.org/) to load and compile this project. 

### Standalone library

The `ykhmac` library is available on PlatformIO at (TBA). It requires my fork of the *Cryptosuite2* library.

## Thanks to / Sources

- http://www.average.org/chal-resp-auth/
- https://github.com/arekinath/yktool
- https://github.com/keepassxreboot/keepassxc

### Third-party libraries

- [Arduino](https://www.arduino.cc/)
- [Adafruit BusIO](https://platformio.org/lib/show/6214/Adafruit%20BusIO)
- [Adafruit PN532](https://platformio.org/lib/show/29/Adafruit%20PN532)
- [Cryptosuite2](https://platformio.org/lib/show/5829/cryptosuite2) (fork at https://github.com/StarGate01/cryptosuite2)

