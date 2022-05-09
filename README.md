# My Awesome List

My personal awesome list of interesting repos, libraries and tools.

## Contents

* [Awesome Lists](#awesome-lists)
* [Blogs](#blogs)
* [Compilers and Toolchains](#compilers-and-toolchains)
* [Debuggers](#debuggers)
* [eBPF](#ebpf)
* [Embedded and IoT](#embedded-and-iot)
* [Emulators And Dynamic Analysis](#emulators-and-dynamic-analysis)
* [Exploit Development](#exploit-development)
* [Fuzzing](#fuzzing)
* [Linux Kernel](#linux-kernel)
* [Network Scanners](#network-scanners)
* [Network Proxies and Traffic Manipulation](#network-proxies-and-traffic-manipulation)
* [Misc](#misc)
* [Programming Languages](#programming-languages)
* [Reverse Engineering](#reverse-engineering)
* [RTOS](#rtos)
* [Tracing, Hooking and Instrumentation](#tracing-hooking-and-instrumentation)
* [Trusted Execution Environment](#trusted-execution-environment)

## Awesome Lists

* [C][17]: A curated list of C good stuff.
* [eBPF][25]: curated list of awesome projects related to eBPF.
* [Docker][30]: curated list of Docker resources and projects.
* [Embedded][20]: curated list of awesome embedded programming.
* [Linux Kernel Exploitation][21]: collection of links related to Linux kernel
  security and exploitation.
* [Linux Rootkits][29]: list of rootkits for the Linux kernel.
* [Malware Analysis][34]: malware analysis tools and resources.
* [IoT][19]: st of great resources about IoT Framework, Library, OS, Platforms.
* [Raspberry Pi][33]: Raspberry Pi tools, projects, images and resources.
* [Reverse Engineering][35]: reversing resources.
* [Rust][18]: curated list of Rust code and resources.
* [Shell][31]: command-line frameworks, toolkits, guides and gizmos.
* [Vim][32]: all things vim.

## Blogs

* [ir0nstone][56]: binary exploitation notes.
* [Nightmare][13]: intro to binary exploitation / reverse engineering course
  based around ctf challenges.
* [Phrack][75]: e-zine written by and for hackers.
* [Rust OSDev][68]: rhis Month in Rust OSDev.
* [System Overlord][46]: security engineering, research, and general hacking.
* [tmp.out][76]: ELF research group.

## Compilers and Toolchains

* [clang][15]: C language family frontend for LLVM.
* [Cross-compilation toolchains (Bootlin)][16]: large number of ready-to-use
  cross-compilation toolchains, targetting the Linux operating system on a large
  number of architectures.
* [Dockcross][45]: cross compiling toolchains in Docker images.
* [gcc][14]: GNU Compiler Collection.

## Debuggers

* [GDB][26]: GNU Project Debugger.
  * [GEF][27]: plugin with set of commands to assis exploit developers and
    reverse-engineers.

## eBPF

* [epbf.io][66]: official website.

## Embedded and IoT

* [Flashrom][74]: utility for detecting, reading, writing, verifying and erasing
  flash chips.
* [Low level][48]: misc documentation about low level development.
* [NexMon][49]: C-based Firmware Patching Framework for Broadcom/Cypress WiFi
  Chips.

## Emulators and Dynamic Analysis

* [Avatar2][62]: target orchestration framework with focus on dynamic analysis
  of embedded devices' firmware!
* [EMUX][9]: Firmware Emulation Framework.
* [Firmadyne][63]: platform for emulation and dynamic analysis of Linux-based
  firmware.
* [QEMU][28]: open source machine emulator and virtualizer.
* [Panda][64]: platform for Architecture-Neutral Dynamic Analysis.
* [Qiling][10]: Qiling Advanced Binary Emulation Framework.
* [Triton][65]: dynamic binary analysis library.

## Exploit Development

* [how2heap][47]: repository for learning various heap exploitation techniques.
* [libc-database][69]: database of libc offsets to simplify exploitation.
* [one_gadget][70]: tool for finding one gadget RCE in libc.so.6.
* [pwntools][71]: framework and exploit development library.

## Fuzzing

* [AFLplusplus][38]: improved version of AFL.
* [Honggfuzz][39]: evolutionary, feedback-driven fuzzing based on code coverage.
* [Syzkaller][37]: unsupervised coverage-guided kernel fuzzer.

## Linux Kernel

* [Defence Map][22]: relationships between vulnerability classes, exploitation
  techniques, bug detection mechanisms, and defence technologies.
* [Kernel documentation][12]: official linux kernel documentation.
* [kernel.org][11]: linux kernel archives.
* [linux-insides][77]: a book about linux kernel and its insides.
* Rootkits:
  * [Awesome Linux Rootkits][29].
  * [Diamorphine][78]: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and
    ARM64.
  * [Pinkit][81]: LKM rootkit that executes a reverse TCP netcat shell with root
    privileges.
  * [Reptile][79]: LKM Linux rootkit.
  * [Research rootkit][84]: LibZeroEvil & the Research Rootkit project.
  * [Rootkit][83]: rootkit for Ubuntu 16.04 and 10.04 (Linux Kernels 4.4.0 and
    2.6.32), both i386 and amd64.
  * [Rootkit list download][82]: list of rootkits (includes also userspace
    rootkits).
  * [Sutekh][80]: rootkit that gives a userland process root permissions.
* Rust:
  * [Linux crate][86].
  * [knock-out][87]: example of a kernel module in Rust.
  * [Rust for Linux][85]: organization for adding support for the Rust language
    to the Linux kernel.

## Network Scanners

* [masscan][8]: TCP port scanner, spews SYN packets asynchronously.
* [nmap][4]: utility for network scanning and discovery and security auditing
* [RustScan][5]: quick port scanner implemented in rust.
* [skanuvaty][7]: fast DNS/network/port scanner.
* [ZMap][6]: fast single packet network scanner.

## Network Proxies and Traffic Manipulation

* [mitmproxy][40]: interactive HTTPS proxy.

## Reverse Engineering

* [CAPA][73]: tool to identify capabilities in executable files.
* [Diffware][52]: configurable tool providing a summary of the changes between
  two files or directories
  * [Diffoscope][53]: directory differ.
* [Radare2][1]: UNIX-like reverse engineering framework and command-line
  toolset.
  * [Cutter][3]: GUI based on [Rizin][2].
  * [Rizin][2]: radare2 fork.
* [Yara][72]: pattern matching swiss knife for malware researchers.

## Misc

* [OpenSK][67]: open-source implementation for security keys written in Rust.

## Programming Languages

* [C][57]: C reference
  * libc implementations:
    * [glibc][58]: GNU C library.
    * [musl][59]: C standard library.
    * [uclibc][60]: C library for developing embedded Linux systems.
    * [uclibc-ng][61]: small C library for developing embedded Linux systems.
* [Rust][41]: secure system programming language.
  * [Book][42]: introductory book about Rust.
  * [crates.io][44]: Rust community's crate registry.
  * [std][43]: standard library documentation.

## RTOS

* [Zephyr][50]: mall, scalable, real-time operating system (RTOS).
  * [Docs][51]: zephyt project documentation.

## Tracing, Hooking and Instrumentation

* [DynamoRIO][23]: runtime code manipulation system.
* [Frida][36]: instrumentation toolkit for developers, reverse-engineers, and
  security researchers.
* [Tracee][24]: Linux Runtime Security and Forensics using eBPF.

## Trusted Execution Environment

* [OP-TEE][54]: Open Portable Trusted Execution Environment.
  * [Docs][55]: official OP-TEE documentation.

[1]: https://github.com/radareorg/radare2
[2]: https://github.com/rizinorg/rizin
[3]: https://cutter.re/
[4]: https://nmap.org/
[5]: https://github.com/RustScan/RustScan
[6]: https://github.com/zmap/zmap
[7]: https://github.com/Esc4iCEscEsc/skanuvaty
[8]: https://github.com/robertdavidgraham/masscan
[9]: https://github.com/therealsaumil/emux
[10]: https://github.com/qilingframework/qiling
[11]: https://kernel.org/
[12]: https://www.kernel.org/doc/html/latest/index.html
[13]: https://guyinatuxedo.github.io/index.html
[14]: https://gcc.gnu.org/
[15]: https://clang.llvm.org/
[16]: https://toolchains.bootlin.com/
[17]: https://github.com/oz123/awesome-c
[18]: https://github.com/rust-unofficial/awesome-rust
[19]: https://github.com/phodal/awesome-iot
[20]: https://github.com/nhivp/Awesome-Embedded
[21]: https://github.com/xairy/linux-kernel-exploitation
[22]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[23]: https://github.com/DynamoRIO/dynamorio
[24]: https://github.com/aquasecurity/tracee
[25]: https://github.com/zoidbergwill/awesome-ebpf
[26]: https://www.sourceware.org/gdb/
[27]: https://github.com/hugsy/gef
[28]: https://www.qemu.org/
[29]: https://github.com/milabs/awesome-linux-rootkits
[30]: https://github.com/veggiemonk/awesome-docker
[31]: https://github.com/alebcay/awesome-shell
[32]: https://github.com/mhinz/vim-galore
[33]: https://github.com/thibmaek/awesome-raspberry-pi
[34]: https://github.com/rshipp/awesome-malware-analysis
[35]: https://github.com/tylerha97/awesome-reversing
[36]: https://github.com/frida/frida
[37]: https://github.com/google/syzkaller
[38]: https://github.com/AFLplusplus/AFLplusplus
[39]: https://github.com/google/honggfuzz
[40]: https://mitmproxy.org/
[41]: https://www.rust-lang.org/
[42]: https://doc.rust-lang.org/book/
[43]: https://doc.rust-lang.org/std/
[44]: https://crates.io/
[45]: https://github.com/dockcross/dockcross
[46]: https://systemoverlord.com/
[47]: https://github.com/shellphish/how2heap
[48]: https://low-level.readthedocs.io/en/latest/
[49]: https://github.com/seemoo-lab/nexmon
[50]: https://www.zephyrproject.org/
[51]: https://docs.zephyrproject.org/latest/
[52]: https://github.com/airbus-seclab/diffware
[53]: https://salsa.debian.org/reproducible-builds/diffoscope
[54]: https://github.com/OP-TEE/optee_os
[55]: https://optee.readthedocs.io/en/latest/index.html
[56]: https://ir0nstone.gitbook.io/notes/
[57]: https://en.cppreference.com/w/c
[58]: https://sourceware.org/git/?p=glibc.git
[59]: https://git.musl-libc.org/cgit/musl
[60]: https://www.uclibc.org/
[61]: https://cgit.uclibc-ng.org/cgi/cgit/uclibc-ng.git/
[62]: https://github.com/avatartwo/avatar2
[63]: https://github.com/firmadyne/firmadyne
[64]: https://github.com/panda-re/panda
[65]: https://github.com/JonathanSalwan/Triton
[66]: https://ebpf.io/
[67]: https://github.com/google/OpenSK
[68]: https://rust-osdev.com/
[69]: https://github.com/niklasb/libc-database
[70]: https://github.com/david942j/one_gadget
[71]: https://github.com/Gallopsled/pwntools
[72]: https://virustotal.github.io/yara/
[73]: https://github.com/mandiant/capa
[74]: https://github.com/flashrom/flashrom
[75]: http://www.phrack.org/
[76]: https://tmpout.sh/#
[77]: https://0xax.gitbooks.io/linux-insides/content/
[78]: https://github.com/m0nad/Diamorphine
[79]: https://github.com/f0rb1dd3n/Reptile
[80]: https://github.com/PinkP4nther/Sutekh
[81]: https://github.com/PinkP4nther/Pinkit
[82]: https://github.com/d30sa1/RootKits-List-Download
[83]: https://github.com/nurupo/rootkit
[84]: https://github.com/NoviceLive/research-rootkit
[85]: https://github.com/Rust-for-Linux
[86]: https://crates.io/crates/linux
[87]: https://github.com/jbaublitz/knock-out
