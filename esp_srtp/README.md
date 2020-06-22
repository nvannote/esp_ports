# ESP32/FreeRTOS Cisco SRTP Component Build

Test Build/Run

Cisco SRTP v2.3.0; ESP-IDF v4.0.1; ESP32 (ESP32-D0WDQ6) Rev 1

* Place the Cisco SRTP repository directory (or a symbolic link to it) in the "esp_srtp/components/srtp" directory.
* idf.py build
* idf.py flash monitor

It will run a very simple AES-256 test derived from the original Cisco unit tests.
