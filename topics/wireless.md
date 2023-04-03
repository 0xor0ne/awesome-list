# Wireless Stuff

## Content

* [802.11](#802.11)
* [802.15.4](#802.15.4)
* [Bluetooth](#bluetooth)
* [Linux](#linux)
* [Misc](#Misc)
* [Radio Controllers](#radio-controllers)
* [SDR](#sdr-and-sdp)

## 802.11

* Tools
  * [aircrack-ng][16]: complete suite of tools to assess WiFi network security.
    * [GitHub][17]: WiFi security auditing tools suite
  * [airpwn-ng][46]: Packet injection for wifi.
  * [bettercap][18]: Swiss Army knife for WiFi, Bluetooth Low Energy, wireless
    HID hijacking.
    * [GitHub][19]: source code repository.
  * [ESP32 802.11 TX][41]: Send arbitrary IEEE 802.11 frames with Espressif's
    ESP32.
  * [ESP32 ESP8266 attacks][38]: Proof of Concept of ESP32/8266 Wi-Fi
    vulnerabilties.
  * [ESP32 Marauder][43]: suite of WiFi/Bluetooth offensive and defensive tools
    for the ESP32.
  * [Kismet][14]: Wi-Fi, Bluetooth, RF, and more
    * [GitHub][15]: Kismet and related tools and libraries for wireless
      monitoring, transmitting, and auditing.
  * [libwifi][48]: an 802.11 (WiFi) Frame Generation and Parsing Library in C.
    * [github repo][47]: libwifi github repository
  * [libwifi (nukesor)][49]: rust library for parsing IEE 802.11 frames.
  * [libwifi (vanhoefm)][50]: python and scapy scripts for Wi-Fi.
  * [nexmon][20]: The C-based Firmware Patching Framework for Broadcom/Cypress
    WiFi Chips.
  * [pawnagotchi][42]:  A2C-based “AI” powered by bettercap and running on a
    Raspberry Pi Zero W that learns from its surrounding WiFi environment in
    order to maximize the crackable WPA key material it captures/
  * [wifijammer][28]: Continuously jam all wifi clients/routers.
  * [wifiphisher][27]: The Rogue Access Point Framework.
  * [wifipumpkin3][29]: Powerful framework for rogue access point attack.
* [esp-wifi][45]: WIP / POC for using the ESP32-C3, ESP32-S3 and ESP32 wifi
  drivers in bare-metal Rust.
* [USB-WiFi][24]: USB WiFi Adapter Information for Linux

## 802.15.4

* [KillerBee][31]: IEEE 802.15.4/ZigBee Security Research Toolkit.

## Bluetooth

* [Awesome bluetooth security][33]: useful references for anyone working with
  Bluetooth BR/EDR/LE or Mesh security.
* [BLE Security Attack Defence][34]: Unveiling zero day vulnerabilities and
  security flaws in modern Bluetooth LE stacks.
* Tools
  * [BTLE][52]: Bluetooth Low Energy (BLE) packet sniffer and transmitter for
    both standard and non standard (raw bit) based on Software Defined Radio
    (SDR).
  * [btlejack][44]: Bluetooth Low Energy Swiss-army knife.
  * [ESP32 bluetooth classic sniffer][37]: Active Bluetooth BR/EDR Sniffer/Injector
    as cheap as any ESP32 board can get.
  * [ice9-bluetooth-sniffer][51]: Wireshark Bluetooth sniffer for HackRF,
    BladeRF, and USRP.
  * [internalblue][26]: About Bluetooth experimentation framework for Broadcom
    and Cypress chips.
  * [Injectable firmware][35]: Custom firmware for nrf52840-dongle.
  * [nRF sniffer][40]: Bluetooth LE sniffer from nordic.
  * [Sniffle][21]: A sniffer for Bluetooth 5 and 4.x LE

## linux

* [Linux Wireless wiki][0]: Documentation for the Linux wireless (IEEE-802.11)
  subsystem.
* Realtek drivers:
  * [RTL88x2BU][25]: Linux Driver for USB WiFi Adapters that are based on the
    RTL8812BU and RTL8822BU Chipset.

## Misc

* [Awesome CTS][54]: curated list of Capture The Signal CTF related stuff.
* [cts.ninja][39]: CTF focused on radio signal reverse engineering
* [Mirage][36]: powerful and modular framework dedicated to the security
  analysis of wireless communications.

## Radio Controllers

## SDR and SDP

* Hardware
  * [BladeRF][1]: 2x2 MIMO, 47MHz to 6GHz frequency range
    * [GitHub][2]: bladeRF USB 3.0 Superspeed Software Defined Radio Source
      Code.
  * [HackRF One][5]: oftware Defined Radio peripheral capable of transmission or
    reception of radio signals from 1 MHz to 6 GHz.
    * [GitHub][6]: low cost software radio platform.
  * [LimeSDR][3]: low cost, open source, apps-enabled software defined radio (SDR).
    * [GitHub][4]: LimeSdr software
* Libraries
  * [FISSURE][53]: RF and reverse engineering framework for everyone.
  * [GNU Radio][10]: development toolkit that provides signal processing blocks
    to implement software radios.
    * [GitHub][11]: the Free and Open Software Radio Ecosystem.
  * [LiquidSDR][12]: free and open-source signal processing library for
    software-defined radios.
    * [liquid-dsp][13]: digital signal processing library for software-defined
      radios.
  * [OpenOFDM][30]: Sythesizable, modular Verilog implementation of 802.11 OFDM
    decoder.
* Theory
  * [dspguide][23]: The Scientist and Engineer's Guide to Digital Signal
    Processing.
  * [pysdr][22]: A Guide to SDR and DSP using Python.
  * [sdre][30]: Software-Defined Radio for Engineers.
* Tools
  * [sdrangel][8]: SDR Rx/Tx software
  * [SDRPlusPlusA][7]: Cross-Platform SDR Software
  * [urh][9]: Universal Radio Hacker


[0]: https://wireless.wiki.kernel.org/
[1]: https://www.nuand.com/bladerf-2-0-micro/
[2]: https://github.com/Nuand/bladeRF
[3]: https://limemicro.com/products/boards/limesdr/
[4]: https://github.com/myriadrf
[5]: https://greatscottgadgets.com/hackrf/one/
[6]: https://github.com/greatscottgadgets/hackrf
[7]: https://github.com/AlexandreRouma/SDRPlusPlus
[8]: https://github.com/f4exb/sdrangel
[9]: https://github.com/jopohl/urh
[10]: https://www.gnuradio.org/
[11]: https://github.com/gnuradio/gnuradio
[12]: https://liquidsdr.org/
[13]: https://github.com/jgaeddert/liquid-dsp
[14]: https://www.kismetwireless.net/
[15]: https://github.com/kismetwireless
[16]: https://www.aircrack-ng.org/
[17]: https://github.com/aircrack-ng/aircrack-ng
[18]: https://www.bettercap.org/
[19]: https://github.com/bettercap/bettercap
[20]: https://github.com/seemoo-lab/nexmon
[21]: https://github.com/nccgroup/Sniffle
[22]: https://pysdr.org/
[23]: http://www.dspguide.com/
[24]: https://github.com/morrownr/USB-WiFi
[25]: https://github.com/morrownr/88x2bu
[26]: https://github.com/seemoo-lab/internalblue
[27]: https://github.com/wifiphisher/wifiphisher
[28]: https://github.com/DanMcInerney/wifijammer
[29]: https://github.com/P0cL4bs/wifipumpkin3
[30]: https://www.analog.com/en/education/education-library/software-defined-radio-for-engineers.html
[31]: https://github.com/jhshi/openofdm
[32]: https://github.com/riverloopsec/killerbee
[33]: https://github.com/engn33r/awesome-bluetooth-security
[34]: https://github.com/Charmve/BLE-Security-Attack-Defence
[35]: https://github.com/RCayre/injectable-firmware
[36]: https://github.com/RCayre/mirage
[37]: https://github.com/Matheus-Garbelini/esp32_bluetooth_classic_sniffer
[38]: https://github.com/Matheus-Garbelini/esp32_esp8266_attacks
[39]: https://cts.ninja/
[40]: https://infocenter.nordicsemi.com/index.jsp?topic=%2Fug_sniffer_ble%2FUG%2Fsniffer_ble%2Fintro.html
[41]: https://github.com/Jeija/esp32-80211-tx
[42]: https://pwnagotchi.ai/
[43]: https://github.com/justcallmekoko/ESP32Marauder
[44]: https://github.com/virtualabs/btlejack
[45]: https://github.com/esp-rs/esp-wifi
[46]: https://github.com/ICSec/airpwn-ng
[47]: https://github.com/libwifi/libwifi
[48]: https://libwifi.so/
[49]: https://github.com/Nukesor/libwifi
[50]: https://github.com/vanhoefm/libwifi
[51]: https://github.com/mikeryan/ice9-bluetooth-sniffer
[52]: https://github.com/JiaoXianjun/BTLE
[53]: https://github.com/ainfosec/FISSURE
[54]: https://github.com/BlackVS/Awesome-CTS
