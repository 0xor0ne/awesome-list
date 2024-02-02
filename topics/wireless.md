# Wireless Stuff

## Content

* [3GPP](#3gpp)
* [802.11](#802.11)
* [802.15.4](#802.15.4)
* [Bluetooth](#bluetooth)
* [IoT](#iot)
* [Linux](#linux)
* [Microcontrollers Vendors](#microcontrollers-vendors)
* [Misc](#Misc)
* [Radio Controllers](#radio-controllers)
* [SDR](#sdr-and-sdp)
* [Z-Wave](#z-wave)

## 3GPP

* [Specifications][71]

## 802.11

* [Wi-Fi Alliance][66]
  * [Specification][67]
* Attacks:
  * KRACK attack:
    * [paper][57]: Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2
    * [scripts][58]: scripts to test if clients or access points (APs) are
      affected by the KRACK attack.
    * [website][56]: Key Reinstallation Attacks
  * [ICMP redirects][62]: Man-in-the-Middle Attacks without Rogue AP: When WPAs
    Meet ICMP Redirects.
  * MacStealer:
    * [paper][59]: Framing Frames: Bypassing Wi-Fi Encryption by Manipulating
      Transmit Queues.
    * [repository][61]: est Wi-Fi networks for client isolation bypasses.
    * [wifi-framing][60]: Repository for the Framing Frames publication
* [IEEE]:
  * [Working Group][98]
* Tools
  * [aircrack-ng][16]: complete suite of tools to assess WiFi network security.
    * [GitHub][17]: WiFi security auditing tools suite
  * [airgorah][119]: WiFi auditing software that can perform deauth attacks and
  passwords cracking.
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
  * [esp32-wifi-penetration-tool][104]: Exploring possibilities of ESP32
    platform to attack on nearby Wi-Fi networks.
  * [FreeRADIUS][99]: open source RADIUS server.
  * [hostapd][100]: user space daemon for access points.
  * [Kismet][14]: Wi-Fi, Bluetooth, RF, and more
    * [GitHub][15]: Kismet and related tools and libraries for wireless
      monitoring, transmitting, and auditing.
  * [iw][101]: nl80211 based CLI configuration utility for wireless devices.
  * [libwifi][48]: an 802.11 (WiFi) Frame Generation and Parsing Library in C.
    * [github repo][47]: libwifi github repository
  * [libwifi (nukesor)][49]: rust library for parsing IEE 802.11 frames.
  * [libwifi (vanhoefm)][50]: python and scapy scripts for Wi-Fi.
  * [nexmon][20]: The C-based Firmware Patching Framework for Broadcom/Cypress
    WiFi Chips.
  * [pawnagotchi][42]:  A2C-based “AI” powered by bettercap and running on a
    Raspberry Pi Zero W that learns from its surrounding WiFi environment in
    order to maximize the crackable WPA key material it captures/
  * [pi-pwnbox-rogueap][103]: Rogue AP based on Raspberry Pi
  * [WEF][106]: Wi-Fi Exploitation Framework.
  * [wifi-arsenal][122]: links to projects related to wifi security.
  * [wifi-cracking][105]: Crack WPA/WPA2 Wi-Fi Routers with Airodump-ng and
    Aircrack-ng/Hashcat.
  * [wifijammer][28]: Continuously jam all wifi clients/routers.
  * [wifiphisher][27]: The Rogue Access Point Framework.
  * [WiFiManager][121]: ESP8266 WiFi Connection manager with web captive portal.
  * [wifipumpkin3][29]: Powerful framework for rogue access point attack.
  * [wifite2][102]: script for auditing wireless networks.
  * [wiphisher][120]: The Rogue Access Point Framework.
  * [wpa_supplicant][100]: supplicant for 802.11
* [esp-wifi][45]: WIP / POC for using the ESP32-C3, ESP32-S3 and ESP32 wifi
  drivers in bare-metal Rust.
* [USB-WiFi][24]: USB WiFi Adapter Information for Linux

## 802.15.4

* [KillerBee][31]: IEEE 802.15.4/ZigBee Security Research Toolkit.

## Bluetooth

* [bluetooth.com][69]
  * [Specifications][70]
* [Awesome bluetooth security][33]: useful references for anyone working with
  Bluetooth BR/EDR/LE or Mesh security.
* [BLE Security Attack Defence][34]: Unveiling zero day vulnerabilities and
  security flaws in modern Bluetooth LE stacks.
* Stacks:
  * [bluez][118]: Bluetooth protocol stack for Linux
  * [BTStack][117]: Dual-mode Bluetooth stack, with small memory footprint
* Tools
  * [ble-fuzzing][107]: Stateful Black-Box Fuzzing of BLE Devices Using Automata
  Learning
  * [bluing][116]: intelligence gathering tool for hacking Bluetooth.
  * [BTLE][52]: Bluetooth Low Energy (BLE) packet sniffer and transmitter for
    both standard and non standard (raw bit) based on Software Defined Radio
    (SDR).
  * [btlejack][44]: Bluetooth Low Energy Swiss-army knife.
  * [btleplug][114]: Rust Cross-Platform Host-Side Bluetooth LE Access Library.
  * [ESP32 bluetooth classic sniffer][37]: Active Bluetooth BR/EDR Sniffer/Injector
    as cheap as any ESP32 board can get.
  * [gattacker][115]: BLE (Bluetooth Low Energy) security assessment
  * [ice9-bluetooth-sniffer][51]: Wireshark Bluetooth sniffer for HackRF,
    BladeRF, and USRP.
  * [internalblue][26]: About Bluetooth experimentation framework for Broadcom
    and Cypress chips.
  * [Injectable firmware][35]: Custom firmware for nrf52840-dongle.
  * [nRF sniffer][40]: Bluetooth LE sniffer from nordic.
  * [Sniffle][21]: A sniffer for Bluetooth 5 and 4.x LE

## IoT

* [csa-iot.org][72]: Connectivity Standards Alliance
  * [Specifications][74]
* [Home Assistant][97]: Open source home automation
* [Matter][73]
* [Thread][76]
  * [OpenThread][96]: open-source implementation of Thread
  * [Specifications][77]
* [ZigBee][75]

## linux

* [Linux Wireless wiki][0]: Documentation for the Linux wireless (IEEE-802.11)
  subsystem.
* Realtek drivers:
  * [RTL88x2BU][25]: Linux Driver for USB WiFi Adapters that are based on the
    RTL8812BU and RTL8822BU Chipset.

## Microcontrollers Vendors

* [Bouffalo Labs][94]
  * [GitHub][95]
* [Espressif][78] 
  * [Github][81]
* [Silicon Labs][82]
  * [GitHub][83]
* [Microchip][90]
  * [GitHub][91]
* [Nordic][79]
  * [GitHub][80]
* [NXP][84]
  * [GitHub][85]
* [Renesas][92]
  * [GitHub][93]
* [STMicroelectronics][88]
  * [GitHub][89]
* [Texas Instruments][86]
  * [GitHub][87]

## Misc

* [Awesome CTS][54]: curated list of Capture The Signal CTF related stuff.
* [cts.ninja][39]: CTF focused on radio signal reverse engineering
* FCC
  * [fccid.io]: Searchable FCC ID Database
  * [Official FCC ID][63] 
* [FlipperZero][108]
  * [Awesome][112]
  * [Firmware (original)][109]
  * [RogueMaster firmware][113]
  * [Unleashed-firmware][111]
  * [Xtreme-firmware][110]
* [Mirage][36]: powerful and modular framework dedicated to the security
  analysis of wireless communications.
* [Signal Identification Guide][55]: help identify radio signals through example
  sounds and waterfall images.

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
  * [rtl-sdr][65]: RTL-SDR (RTL2832U) and software defined radio news and
    projects.
  * [sdre][30]: Software-Defined Radio for Engineers.
* Tools
  * [sdrangel][8]: SDR Rx/Tx software
  * [SDRPlusPlusA][7]: Cross-Platform SDR Software
  * [urh][9]: Universal Radio Hacker

## Z-Wave

* [z-wave alliance][68]
* [z-wave.com][67]


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
[55]: https://www.sigidwiki.com/wiki/Signal_Identification_Guide
[56]: https://www.krackattacks.com
[57]: https://papers.mathyvanhoef.com/ccs2017.pdf
[58]: https://github.com/vanhoefm/krackattacks-scripts
[59]: https://papers.mathyvanhoef.com/usenix2023-wifi.pdf
[60]: https://github.com/domienschepers/wifi-framing
[61]: https://github.com/vanhoefm/macstealer
[62]: https://csis.gmu.edu/ksun/publications/WiFi_Interception_SP23.pdf
[63]: https://www.fcc.gov/oet/ea/fccid
[64]: https://fccid.io
[65]: https://www.rtl-sdr.com
[66]: https://www.wi-fi.org
[67]: https://www.wi-fi.org/discover-wi-fi/specifications
[68]: https://z-wavealliance.org
[69]: https://www.bluetooth.com
[70]: https://www.bluetooth.com/specifications/specs/
[71]: https://www.3gpp.org/specifications-technologies
[72]: https://csa-iot.org
[73]: https://csa-iot.org/all-solutions/matter/
[74]: https://csa-iot.org/developer-resource/specifications-download-request/
[75]: https://csa-iot.org/all-solutions/zigbee/
[76]: https://www.threadgroup.org
[77]: https://www.threadgroup.org/support#specifications
[78]: https://www.espressif.com/en
[79]: https://www.nordicsemi.com
[80]: https://github.com/NordicSemiconductor
[81]: https://github.com/espressif
[82]: https://www.silabs.com
[83]: https://github.com/SiliconLabs
[84]: https://www.nxp.com
[85]: https://github.com/NXP
[86]: https://www.ti.com
[87]: https://github.com/TexasInstruments
[88]: https://www.st.com/content/st_com/en.html
[89]: https://github.com/STMicroelectronics
[90]: https://www.microchip.com
[91]: https://github.com/MicrochipTech
[92]: https://www.renesas.com/us/en
[93]: https://github.com/renesas
[94]: https://www.bouffalolab.com
[95]: https://github.com/bouffalolab
[96]: https://openthread.io
[97]: https://www.home-assistant.io/
[98]: https://www.ieee802.org/11/
[99]: https://freeradius.org
[100]: https://w1.fi/cgit/hostap/
[101]: https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git
[102]: https://github.com/derv82/wifite2
[103]: https://github.com/koutto/pi-pwnbox-rogueap
[104]: https://github.com/risinek/esp32-wifi-penetration-tool
[105]: https://github.com/brannondorsey/wifi-cracking
[106]: https://github.com/D3Ext/WEF
[107]: https://git.ist.tugraz.at/apferscher/ble-fuzzing
[108]: https://flipperzero.one
[109]: https://github.com/flipperdevices/flipperzero-firmware
[110]: https://github.com/Flipper-XFW/Xtreme-Firmware
[111]: https://github.com/DarkFlippers/unleashed-firmware
[112]: https://github.com/djsime1/awesome-flipperzero
[113]: https://github.com/RogueMaster/flipperzero-firmware-wPlugins
[114]: https://github.com/deviceplug/btleplug
[115]: https://github.com/securing/gattacker
[116]: https://github.com/fO-000/bluing
[117]: https://github.com/bluekitchen/btstack
[118]: https://github.com/bluez/bluez
[119]: https://github.com/martin-olivier/airgorah
[120]: https://github.com/wifiphisher/wifiphisher
[121]: https://github.com/tzapu/WiFiManager
[122]: https://github.com/0x90/wifi-arsenal
