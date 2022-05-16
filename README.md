# My Awesome List

My personal awesome list of interesting repos, libraries and tools.

## Contents

* [Awesome Lists](#awesome-lists)
* [Blogs](#blogs)
* [Compilers and Toolchains](#compilers-and-toolchains)
* [Databases](#databases)
* [Debuggers](#debuggers)
* [eBPF](#ebpf)
* [Embedded and IoT](#embedded-and-iot)
* [Emulators And Dynamic Analysis](#emulators-and-dynamic-analysis)
* [Exploit Development](#exploit-development)
* [Fuzzing](#fuzzing)
* [Linux Kernel](#linux-kernel)
* [Malwares](#malwares)
* [Misc](#misc)
* [Networking](#networking)
* [Penetration Testing](#penetration-testing)
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
* [IoT][19]: list of great resources about IoT Framework, Library, OS, Platforms.
* [Golang][105]: curated list of awesome Go frameworks, libraries and software.
* [Raspberry Pi][33]: Raspberry Pi tools, projects, images and resources.
* [RAT][162]: RAT And C&C Resources.
* [Reverse Engineering][35]: reversing resources.
* [Rust][18]: curated list of Rust code and resources.
* [Shell][31]: command-line frameworks, toolkits, guides and gizmos.
* [Vim][32]: all things vim.

## Blogs

* [GitHub Security Lab][137]: GitHub security research.
* [ir0nstone][56]: binary exploitation notes.
* [malwareMustDie][116]: white-hat security research workgroup.
* [Malware traffic analysis][157]: source for packet capture (pcap) files and
  malware samples.
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

## Databases

* [ExploitDB][112]: the exploit database.
* [iot-malware][117]: source code of samples leaked online.
* [MalwareBazaar][111]: sharing malware samples with the infosec community.
* [SeeBug][114]: exploit database.
* [Sploitus][113]: exploit database.
* [vx-underground][115]: malware collections.

## Debuggers

* [GDB][26]: GNU Project Debugger.
  * [GEF][27]: plugin with set of commands to assis exploit developers and
    reverse-engineers.
* [Scout][110]: instruction based research debugger.

## eBPF

* [BumbleBee][173]: simplifies building eBPF tools and allows you to package,
  distribute, and run them anywhere.
* [epbf.io][66]: official website.
* [Cilium ebpf][172]: Pure-Go library to read, modify and load eBPF programs.
* [tetragon][171]: eBPF-based Security Observability and Runtime Enforcement.

## Embedded and IoT

* [FACT][100]: Firmware Analysis and Comparison Tool.
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
* [Renode][138]: virtual development framework for complex embedded systems.
* [Triton][65]: dynamic binary analysis library.

## Exploit Development

* [cwe_ckecker][101]: finds vulnerable patterns in binary executables.
* [how2heap][47]: repository for learning various heap exploitation techniques.
* [libc-database][69]: database of libc offsets to simplify exploitation.
* [one_gadget][70]: tool for finding one gadget RCE in libc.so.6.
* [pwntools][71]: framework and exploit development library.
* [ROPGadget][159]: search your gadgets on your binaries to facilitate your ROP
  exploitation.
* [Ropper][160]: find gadgets to build rop chains for different architectures.

## Fuzzing

* [AFLplusplus][38]: improved version of AFL.
* [boofuzz][89]: fork and successor of the Sulley Fuzzing Framework.
* [difuze][90]: fuzzer for Linux Kernel Drivers.
* [halfempty][91]: fast, parallel test case minimization tool.
* [Honggfuzz][39]: evolutionary, feedback-driven fuzzing based on code coverage.
* [krf][92]: kernelspace syscall interceptor and randomized faulter.
* [LibAFL][95]: fuzzing library.
* [Syzkaller][37]: unsupervised coverage-guided kernel fuzzer.
  * [Syzbot][94]: continuously fuzzes main Linux kernel branches and
    automatically reports found bugs

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
* [ltp][93]: Linux Test Project.
* Rust:
  * [Linux crate][86].
  * [knock-out][87]: example of a kernel module in Rust.
  * [Rust for Linux][85]: organization for adding support for the Rust language
    to the Linux kernel.

## Malwares

* Packers:
  * [UPC][154]: free, portable, extendable, high-performance executable packer.
* [Pafish][97]: testing tool that uses different techniques to detect virtual
  machines and malware analysis environments.

## Misc

* [OpenSK][67]: open-source implementation for security keys written in Rust.

## Networking

* File Transfer:
  * [croc][167]: easily and securely send things from one computer to another.
  * [pcp][166]: peer-to-peer data transfer tool based on libp2p.
* Misc:
  * [nebula][122]: scalable overlay networking tool.
* Network Scanners:
  * [masscan][8]: TCP port scanner, spews SYN packets asynchronously.
  * [nmap][4]: utility for network scanning and discovery and security auditing
  * [RustScan][5]: quick port scanner implemented in rust.
  * [skanuvaty][7]: fast DNS/network/port scanner.
  * [ZMap][6]: fast single packet network scanner.
* Proxies:
  * [frp][169]: fast reverse proxy.
  * [leaf][132]: versatile and efficient proxy framework.
  * [mitmproxy][40]: interactive HTTPS proxy.
  * [ngrok][170]: introspected tunnels to localhost.
  * [socat][134]: relay for bidirectional data transfer.
* Remote/Reverse Shells:
  * [GTRS][142]: Google Translator Reverse Shell.
  * [hershell][141]: multiplatform reverse shell generator.
  * [icmpsh][136]: reverse ICMP shell.
  * [Platypus][144]: modern multiple reverse shell sessions manager written in
    go.
  * [rsg][146]: tool to generate various ways to do a reverse shell.
  * [tunshell][121]: remote shell into ephemeral environments.
  * [wash][131]: a cloud-native shell for bringing remote infrastructure to your
    terminal.
* Tunnelling:
  * [clash][164]: rule-based tunnel in Go.
  * [gost][165]: a simple tunnel written in golang.
  * [gsocket][130]: connect like there is no firewall. Securely.
  * [ssf][133]: Secure Socket Funneling.

## Penetration testing

* [BDF][145]: The Backdoor Factory.
* [GTFOBins][147]: curated list of Unix binaries that can be used to bypass
  local security restrictions.
* [traitor][168]: automatic Linux privesc via exploitation of low-hanging fruit.
* [PayloadAllTheThings][123]: list of useful payloads and bypass for Web
  Application Security and Pentest/CTF.
* Post-exploitation:
  * [Emp3r0r][163]: Linux/Windows post-exploitation framework made by linux
    user.
  * [pupy][135]: cross-platform remote administration and post-exploitation
    tool.
  * [pwncat][143]: reverse and bind shell handler.
  * [Stitch][161]: python Remote Administration Tool.

## Programming Languages

* Assembly:
  * ARM:
    * [Docs][124]: official documentation.
    * [Instructions Reference][125]: official instruction reference.
  * MIPS:
    * [Manuals][128]: official manuals.
  * RISC-V:
    * [Manuals][129]: official specifications.
  * x86:
    * [felixcloutier.com][126]: instructions reference.
    * [Software Developer Manuals][127]: official manuals.
* [C][57]: C reference
  * libc implementations:
    * [glibc][58]: GNU C library.
    * [musl][59]: C standard library.
    * [uclibc][60]: C library for developing embedded Linux systems.
    * [uclibc-ng][61]: small C library for developing embedded Linux systems.
  * Libraries:
    * [libaco][104]: blazing fast and lightweight C asymmetric coroutine
      library.
* [Go][106]: open source programming language supported by Google.
  * [Docs][107]: official documentation.
  * [pkg.go.dev][108]: packages documentation.
* [Rust][41]: secure system programming language.
  * [Book][42]: introductory book about Rust.
  * [Cargo Book][129]: official cargo book.
  * [crates.io][44]: Rust community's crate registry.
  * [Embedded Rust Book][153]: introductory book about using the Rust
    Programming Language on "Bare Metal" embedded systems.
  * [Rustonomicon][150]: awful details that you need to understand when writing
    Unsafe Rust programs.
  * [Rust Reference][151]: primary reference for the Rust programming language.
  * [rustup][152]: installer for the systems programming language Rust.
  * [std][43]: standard library documentation.
  * [This Week In Rust][148]: handpicked Rust updates, delivered to your inbox.
  * Libraries:
    * [Goblin][99]: cross-platform binary parsing crate, written in Rust.
    * [redbpf][119]: Rust library for building and running BPF/eBPF modules.
    * [redhook][96]: dynamic function call interposition / hooking (LD_PRELOAD)
      for Rust.

## Reverse Engineering

* [Angr][109]: user-friendly binary analysis platform.
* [CAPA][73]: tool to identify capabilities in executable files.
  * [lancelot-flirt][103]: library for parsing, compiling, and matching Fast
    Library Identification and Recognition Technology (FLIRT) signatures.
* [CyberChef][155]: web app for encryption, encoding, compression and data
  analysis.
* [Diffware][52]: configurable tool providing a summary of the changes between
  two files or directories
  * [Diffoscope][53]: directory differ.
* {ELFKickers][156]: collection of programs that access and manipulate ELF
  files.
* [FLOSS][102]: FLARE Obfuscated String Solver.
* [Radare2][1]: UNIX-like reverse engineering framework and command-line
  toolset.
  * [Book][98]: radare2 official book.
  * [Cutter][3]: GUI based on [Rizin][2].
  * [Rizin][2]: radare2 fork.
* [Yara][72]: pattern matching swiss knife for malware researchers.

## RTOS

* [FreeRTOS][140]: open source, real-time operating system for microcontrollers.
* [MangooseOS][139]: IoT operating system and networking library.
* [Zephyr][50]: mall, scalable, real-time operating system (RTOS).
  * [Docs][51]: zephyt project documentation.

## Tracing, Hooking and Instrumentation

* [bcc][118]: rools for BPF-based Linux IO analysis, networking, monitoring, and
  more.
* [bpftrace][120]: high-level tracing language for Linux eBPF.
* [DynamoRIO][23]: runtime code manipulation system.
* [Frida][36]: instrumentation toolkit for developers, reverse-engineers, and
  security researchers.
* [LIEF][158]: library to Instrument Executable Formats.
* [QDBI][88]: a Dynamic Binary Instrumentation framework based on LLVM.
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
[88]: https://github.com/QBDI/QBDI
[89]: https://github.com/jtpereyda/boofuzz
[90]: https://github.com/ucsb-seclab/difuze
[91]: https://github.com/googleprojectzero/halfempty
[92]: https://github.com/trailofbits/krf
[93]: https://github.com/linux-test-project/ltp
[94]: https://syzkaller.appspot.com/upstream
[95]: https://github.com/AFLplusplus/LibAFL
[96]: https://github.com/geofft/redhook
[97]: https://github.com/a0rtega/pafish
[98]: https://book.rada.re/
[99]: https://github.com/m4b/goblin
[100]: https://github.com/fkie-cad/FACT_core
[101]: https://github.com/fkie-cad/cwe_checker
[102]: https://github.com/mandiant/flare-floss/
[103]: https://crates.io/crates/lancelot-flirt
[104]: https://github.com/hnes/libaco
[105]: https://github.com/avelino/awesome-go
[106]: https://go.dev/
[107]: https://go.dev/doc/
[108]: https://pkg.go.dev/
[109]: https://github.com/angr/angr
[110]: https://github.com/CheckPointSW/Scout
[111]: https://bazaar.abuse.ch/
[112]: https://www.exploit-db.com/
[113]: https://sploitus.com/
[114]: https://www.seebug.org/
[115]: https://www.vx-underground.org/
[116]: https://www.malwaremustdie.org/
[117]: https://github.com/ifding/iot-malware
[118]: https://github.com/iovisor/bcc
[119]: https://github.com/foniod/redbpf
[120]: https://github.com/iovisor/bpftrace
[121]: https://github.com/TimeToogo/tunshell
[122]: https://github.com/slackhq/nebula
[123]: https://github.com/swisskyrepo/PayloadsAllTheThings
[124]: https://developer.arm.com/documentation/
[125]: https://developer.arm.com/documentation/dui0068/b/ARM-Instruction-Reference
[126]: https://www.felixcloutier.com/x86/
[127]: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[128]: https://www.mips.com/downloads/
[129]: https://github.com/riscv
[130]: https://github.com/hackerschoice/gsocket
[131]: https://github.com/puppetlabs/wash
[132]: https://github.com/eycorsican/leaf
[133]: https://github.com/securesocketfunneling/ssf
[134]: https://repo.or.cz/socat.git
[135]: https://github.com/n1nj4sec/pupy
[136]: https://github.com/bdamele/icmpsh
[137]: https://github.blog/tag/github-security-lab/
[138]: https://github.com/renode/renode
[139]: https://mongoose-os.com/
[140]: https://aws.amazon.com/freertos/
[141]: https://github.com/lesnuages/hershell
[142]: https://github.com/mthbernardes/GTRS
[143]: https://github.com/calebstewart/pwncat
[144]: https://github.com/WangYihang/Platypus
[145]: https://github.com/secretsquirrel/the-backdoor-factory
[146]: https://github.com/mthbernardes/rsg
[147]: https://gtfobins.github.io/
[148]: https://this-week-in-rust.org/
[149]: https://doc.rust-lang.org/cargo/
[150]: https://doc.rust-lang.org/nomicon/
[151]: https://doc.rust-lang.org/stable/reference/
[152]: https://rustup.rs/
[153]: https://docs.rust-embedded.org/book/
[154]: https://upx.github.io/
[155]: https://github.com/gchq/CyberChef
[156]: https://github.com/BR903/ELFkickers
[157]: https://www.malware-traffic-analysis.net/
[158]: https://github.com/lief-project/LIEF
[159]: https://github.com/JonathanSalwan/ROPgadget
[160]: https://github.com/sashs/Ropper
[161]: https://github.com/nathanlopez/Stitch
[162]: https://github.com/alphaSeclab/awesome-rat/blob/master/Readme_en.md
[163]: https://github.com/jm33-m0/emp3r0r
[164]: https://github.com/Dreamacro/clash
[165]: https://github.com/ginuerzh/gost
[166]: https://github.com/dennis-tra/pcp
[167]: https://github.com/schollz/croc
[168]: https://github.com/liamg/traitor
[169]: https://github.com/fatedier/frp
[170]: https://github.com/inconshreveable/ngrok
[171]: https://github.com/cilium/tetragon
[172]: https://github.com/cilium/ebpf
[173]: https://bumblebee.io/EN
