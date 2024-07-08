# My Awesome List

My personal awesome list of interesting repos, libraries and tools.

See also the following lists dedicated to specifics sub-topics:

* [Cybersecurity](topics/cybersec.md): links to blog posts, writeups and papers
  dedicated to cybersecurity
* [Exploitation](topics/exploitation.md): resources dedicated to the world of
  binary exploitation
* [Linux Kernel](topics/linux_kernel.md): collection of resources dedicated to
  Linux kernel (internals)
* [Wireless](topics/wireless.md): resources dedicated to wireless technologies
  and security

# Content

* [Awesome Lists](#awesome-lists)
* [Blogs ad Tutorials](#blogs-and-tutorials)
* [Compilers and Toolchains](#compilers-and-toolchains)
* [Databases](#databases)
* [Debuggers](#debuggers)
* [eBPF](#ebpf)
* [Embedded and IoT](#embedded-and-iot)
* [Emulators And Dynamic Analysis](#emulators-and-dynamic-analysis)
* [Exploit Development](#exploit-development)
* [Fuzzing and Vulnerability Research](#fuzzing-and-vulnerability-research)
* [Misc](#misc)
* [Networking](#networking)
* [Programming Languages](#programming-languages)
* [Reverse Engineering](#reverse-engineering)
* [RTOS](#rtos)
* [Sandboxing](#sandboxing)
* [Tools](#tools)
* [Tracing, Hooking and Instrumentation](#tracing-hooking-and-instrumentation)
* [Trusted Execution Environment](#trusted-execution-environment)

* [Other lists](#other-lists)

## Awesome Lists

* [Analysis Tools (dynamic)][372]: curated list of dynamic analysis tools for all
  programming languages.
* [Analysis Tools (static)][371]: curated list of static analysis (SAST) tools.
* [Bash][491]: curated list of delightful Bash scripts and resources
* [Bash OneLiners][494]: collection of handy Bash One-Liners.
* [Bash Handbook][495]: for those who wanna learn Bash.
* [BSK][362]: the book of secret knowledge.
* [C][17]: A curated list of C good stuff.
* [C Preprocessor][658]: C preprocessor stuff
* [ChatGPT prompts][480]: ChatGPT prompt curation to use ChatGPT better.
* [eBPF][25]: curated list of awesome projects related to eBPF.
* [Docker][30]: curated list of Docker resources and projects.
* [ELF][310]: awesome ELF resources by tmp.out.
* [Embedded][20]: curated list of awesome embedded programming.
* [Embedded and IoT][209]: curated list of awesome embedded and IoT security
  resources.
* [Embedded fuzzing][448]: A list of resources (papers, books, talks,
  frameworks, tools) for understanding fuzzing for IoT/embedded devices.
* [Embedded Rust][211]: list of resources for Embedded and Low-level development
  in the Rust programming language.
* [Executable Packing][284]: curated list of awesome resources related to
  executable packing.
* [Firmware Security][437]: curated list of platform firmware resources
* [FlipperZero][438]: awesome resources for the Flipper Zero device.
* [Fuzzing][388]: curated list of fuzzing resources.
* [Fuzzing paper collection][397]: papers related to fuzzing, binary analysis,
  and exploit dev.
* [Golang][105]: curated list of awesome Go frameworks, libraries and software.
* [Hacking][361]: collection of awesome lists for hackers, pentesters & security
  researchers.
* [ICS Security][374]: tools, tips, tricks, and more for exploring ICS Security.
* [IoT Security 101][273]: curated list of IoT Security Resources.
* [IoT][19]: list of great resources about IoT Framework, Library, OS, Platforms.
* [Linux-Bash-Commands][624]: list of Linux bash commands, cheatsheets and resources.
* [Malware Analysis][34]: malware analysis tools and resources.
* [Modern Unix][493]: collection of modern/faster/saner alternatives to common
  unix commands.
* [NeoVim][497]: collections of awesome neovim plugins.
* [Network stuff][281]: resources about network security.
* [Prompt Engineering][481]: hand-curated resources for Prompt Engineering.
* [Prompt Engineering Guides][482]: guides, papers, lecture, notebooks and
  resources for prompt engineering.
* [Pure Bash][492]: collection of pure bash alternatives to external processes.
* [Raspberry Pi][33]: Raspberry Pi tools, projects, images and resources.
* [RAT][162]: RAT And C&C Resources.
* [Reverse Engineering][35]: reversing resources.
* [Reverse Engineering (alphaSeclab)][614]: Reverse Engineering Resources About All Platforms.
* [Reverse Engineering (onethawt)][616]: Reverse Engineering articles, books, and papers
* [Reverse Engineering (wtsxDev)][615]: reverse engineering resources
* [Rust][18]: curated list of Rust code and resources.
* [rust security][376]:  list of awesome projects and resources related to Rust
  and computer security.
* [Search engines][339]: list of search engines useful during Penetration
  testing, Vulnerability assessments, Red Team operations, Bug Bounty and more.
* [Secure a Linux server][365]: evolving how-to guide for securing a Linux server.
* [Shell][31]: command-line frameworks, toolkits, guides and gizmos.
* [System Design][400]: learn how to design systems at scale.
* [Tech Interview][401]: curated coding interview preparation materials.
* [The Art of Command Line][496]: Master the command line.
* [tmux][644]: awesome resources for tmux
* [Tunneling][181]: ngrok alternatives and other ngrok-like tunneling software
  and services.
* [Vim][32]: all things vim.
* [WAF][317]: everything about web-application firewalls (WAF).
* [You-Dont-Need-GUI][623]: list some common tasks that you might be tempted to do in GUI.

## Blogs and Tutorials

* [0x00sec][236]: malware, Reverse Engineering, and Computer Science.
* [0x434b][235]: low level adventures.
* [a13xp0p0v][197]: exploit development and vulnerability research (mostly
  Linux).
* [Alex Plaskett][288]: Random Security Research.
* [Andrey Konovalov][297]: uzzers, exploits, and mitigations for Linux and
  Android kernels.
* [apps3c][435]: cybersecurity research focused on offensive security.
* [Arch Wiki][217]: official Arch wiki.
* [Connof McGarr][196]: exploit development and vulnerability research (mostly
  Windows).
* [CS6038/CS5138 Malware Analysis][451]: Introduction to Malware Analysis and
  Reverse Engineering.
  * [blog.malware.re][559]: reverse engineering related blog.
* [CVE North Star][428]: CVEs as North Stars in vulnerability discovery and
  comprehension.
* [Dmitry.gr]: reverse engineering, embedded and hardware.
* [epi052][439]: epi's personal blog.
* [Gentoo Wiki][216]: official Gentoo wiki.
* [GitHub Security Lab][137]: GitHub security research.
* [Google Security Blog][291]: latest news and insights from Google on security.
* [Google Security Research][295]: ecurity advisories and their accompanying
  proof-of-concepts related to research conducted at Google.
* [grsecurity blog][296]: blog from GRSecurity.
* [Grapl Security Blog][289]: blog from Grapl security.
* [How to exploit a double free][272]:  exploit a double free vulnerability in
  2021.
* [ir0nstone][56]: binary exploitation notes.
* [Linux From Scratch][215]: with step-by-step instructions for building your
  own custom Linux system.
* [malwareMustDie][116]: white-hat security research workgroup.
* [Malware traffic analysis][157]: source for packet capture (pcap) files and
  malware samples.
* [maxwelldulin][533]: exploitation blog posts (heap)
* [n1ght-w0lf][456]: Malware Analysis & Reverse Engineering Adventures.
* [Nightmare][13]: intro to binary exploitation / reverse engineering course
  based around ctf challenges.
* [Outflux][355]: @kees_cook's blog.
* [OWASP CSS][364]: OWASP Cheat Sheet Series Project.
* [Pawnyable][395]: middle to advance binary exploitation.
* [Phrack][75]: e-zine written by and for hackers.
* [Project Zero][198]: news and updates from the Project Zero team at Google.
* [Rust OSDev][68]: rhis Month in Rust OSDev.
* [Sam4k][298]: linux, security, games and other nerdery.
* [School of SRE][366]: school of Sire Reliability Engineers.
* [System Overlord][46]: security engineering, research, and general hacking.
* [ThePhd][423]: (c) programming.
* [tmp.out][76]: ELF research group.
* [Will's Root][290]: Pentesting, CTFs and Writeups.
* [xilokar][426]: embedded development.
* [Zero Day Initiative][220]: encourage the reporting of 0-day vulnerabilities
  privately to the affected vendors.

## Compilers and Toolchains

* [clang][15]: C language family frontend for LLVM.
* [Cross-compilation toolchains (Bootlin)][16]: large number of ready-to-use
  cross-compilation toolchains, targetting the Linux operating system on a large
  number of architectures.
* [Dockcross][45]: cross compiling toolchains in Docker images.
* [gcc][14]: GNU Compiler Collection.

## Databases

* [0day.today][195]: exploits database.
* [CVE Details][185]: security vulnerability datasource.
* [ExploitAlert][194]: exploits found on the internet.
* [ExploitDB][112]: the exploit database.
* [iot-malware][117]: source code of samples leaked online.
* [MalwareBazaar][111]: sharing malware samples with the infosec community.
* [SeeBug][114]: exploit database.
* [Sploitus][113]: exploit database.
* [vx-underground][115]: malware collections.

## Debuggers

* [drgn][538]: Programmable debugger
* [GDB][26]: GNU Project Debugger.
  * [gdb-dashboard][229]: modular visual interface for GDB in Python.
  * [gdb-frontend][558]: easy, flexible and extensible gui debugger.
  * [gdbgui][230]: browser-based frontend to gdb.
  * [GEF][27]: plugin with set of commands to assis exploit developers and
    reverse-engineers.
  * [pwndbg][537]: Exploit Development and Reverse Engineering with GDB Made
  Easy.
* [lldb][554]: next generation, high-performance debugger.
  * [LLDB (DerekSelander)][585]: collection of LLDB aliases/regexes and Python scripts
* [llef][557]: plugin for LLDB to make it more useful for RE and VR.
* [rr][253]: Record and Replay Framework.
  * [rd][307]: reimplementation in rust.
* [Scout][110]: instruction based research debugger.
* [voltron][556]: hacky debugger UI for hackers.

## eBPF

* [BumbleBee][173]: simplifies building eBPF tools and allows you to package,
  distribute, and run them anywhere.
* [Cilium ebpf][172]: Pure-Go library to read, modify and load eBPF programs.
* [epbf.io][66]: official website.
* [pulsar][360]: runtime security framework for the IoT, powered by eBPF.
* [tetragon][171]: eBPF-based Security Observability and Runtime Enforcement.

## Embedded and IoT

* [Binwalk][208]: firmware Analysis Tool.
* [Buildroot][213]: simple, efficient and easy-to-use tool to generate embedded
  Linux systems through cross-compilation.
* [EMBA][224]: firmware security analyzer.
  * [Embark][488]:  firmware security scanning environment.
* [FACT][100]: Firmware Analysis and Comparison Tool.
* [Firmwalker][207]: Script for searching the extracted firmware file system for
  goodies.
* [Firmware mod kit][225]: collection of scripts and utilities to extract and
  rebuild linux based firmware images.
* [Flashrom][74]: utility for detecting, reading, writing, verifying and erasing
  flash chips.
* [Frankenstein][192]: Broadcom and Cypress firmware emulation for fuzzing and
  further full-stack debugging.
* [FuzzWare][394]: automated, self-configuring fuzzing of firmware images.
* [HardwareAllTheThings][436]: list of useful payloads and bypasses for Hardware
  and IOT Security.
* [KataOS][440]: embedded OS written most enrtirely in rust.
* [InternalBlue][193]: bluetooth experimentation framework for Broadcom and
  Cypress chips.
* [LLP University][202]: Low Level Programming University.
* [Low level][48]: misc documentation about low level development.
* [NexMon][49]: C-based Firmware Patching Framework for Broadcom/Cypress WiFi
  Chips.
* [nvram-faker][415]: simple library to intercept calls to libnvram when running
  embedded linux applications in emulated environments.
* [OFRAK][393]: unpack, modify, and repack binaries.
* [OpenOCD][212]: Open On-Chip Debugger.
* [OpenWRT][239]: Linux operating system targeting embedded devices.
* [OS Kernel Lab][203]: OS kernel labs based on Rust/C Lang & RISC-V 64/X86-32.
* [OWASP-FSTM][201]: OWASP Firmware Security Testing Methodology.
* [unblob][385]: curate, fast, and easy-to-use extraction suite.

## Emulators and Dynamic Analysis

* [Avatar2][62]: target orchestration framework with focus on dynamic analysis
  of embedded devices' firmware!
* [EMUX][9]: Firmware Emulation Framework.
* [Firmadyne][63]: platform for emulation and dynamic analysis of Linux-based
  firmware.
  * [scraper][287]: firmwares scraper.
* [QEMU][28]: open source machine emulator and virtualizer.
  * [quickemu][561]: create and run optimised Windows, macOS and Linux desktop.
* [Panda][64]: platform for Architecture-Neutral Dynamic Analysis.
* [Qiling][10]: Qiling Advanced Binary Emulation Framework.
* [Renode][138]: virtual development framework for complex embedded systems.
* [Triton][65]: dynamic binary analysis library.
* [Unicorn][187]: CPU emulator framework.

## Exploit Development

* [Exploit mitigations][292]: knowledge base of exploit mitigations available
  across numerous operating systems.
* [how2heap][47]: repository for learning various heap exploitation techniques.
* [kernel-exploit-factory][459]: Linux kernel CVE exploit analysis report and
  relative debug environment.
* [libc-database][69]: database of libc offsets to simplify exploitation.
* [Linux Kernel Exploit][199]: links related to Linux kernel exploitation.
* [Linux Kernel Exploitation][21]: collection of links related to Linux kernel
  security and exploitation.
* [one_gadget][70]: tool for finding one gadget RCE in libc.so.6.
* [pwndocker][458]: docker environment for pwn in ctf.
* [pwninit][457]: automate starting binary exploit challenges.
* [pwntools][71]: framework and exploit development library.
* [ronin-exploits][663]: A Ruby micro-framework for writing and running exploits and payloads.
* [ROPGadget][159]: search your gadgets on your binaries to facilitate your ROP
  exploitation.
* [ropr][247]: fast multithreaded ROP Gadget finder.
* [Ropper][160]: find gadgets to build rop chains for different architectures.
* [ZDI PoCs][404]: the Zero Day Initiative Proofs-of-concept.

## Fuzzing and Vulnerability Research

* [AFLplusplus][38]: improved version of AFL.
  * [Grammar-mutator][519]: A grammar-based custom mutator for AFL++.
* [afl-training][508]: Exercises to learn how to fuzz with American Fuzzy Lop.
* [appsec (Testing Handbook)][562]: configuring, optimizing, and automating
many of the static and dynamic analysis tools.
* [Arbitrary][524]: Generating structured data from arbitrary, unstructured input.
* [BinAbsInspector][560]: Vulnerability Scanner for Binaries.
* [boofuzz][89]: fork and successor of the Sulley Fuzzing Framework.
* [cargo-fuzz][507]: Command line helpers for fuzzing.
* [CodeQL][293]: semantic code analysis engine.
  * [Use case example][294]: One day short of a full chain.
* [cwe_ckecker][101]: finds vulnerable patterns in binary executables.
* [difuze][90]: fuzzer for Linux Kernel Drivers.
* [ferofuzz][424]: structure-aware HTTP fuzzing library.
* [fuzz-introspector][523]: introspect, extend and optimise fuzzers.
* [fuzzable][518]: Framework for Automating Fuzzable Target Discovery with
  Static Analysis.
* [fuzzing][513]: Tutorials, examples, discussions, research proposals, and
  other resources related to fuzzing.
* [fuzzTest][502]: testing framework for writing and executing fuzz tests
  (replaces libfuzzer).
* [fuzzing101][510]: step by step fuzzing tutorial.
* [Fuzzing Book][390]: tools and techniques for generating software tests.
* [FuzzingPaper][506]: Recent Fuzzing Papers
* [halfempty][91]: fast, parallel test case minimization tool.
* [Healer][190]: kernel fuzzer inspired by Syzkaller.
* [Honggfuzz][39]: evolutionary, feedback-driven fuzzing based on code coverage.
* [iCicle][515]: grey-box firmware fuzzing
* [joern][580]: Open-source code analysis platform.
* [krf][92]: kernelspace syscall interceptor and randomized faulter.
* [lain][381]: fuzzer framework built in Rust.
* [LibAFL][95]: fuzzing library.
* [libfuzzer][511]: in-process, coverage-guided, evolutionary fuzzing engine
  * [Tutorial][512]: learn how to use libFuzzer.
* [libfuzzer (rust)][514]: Rust bindings and utilities for LLVM’s libFuzzer.
* [Nautilus][520]: A grammar based feedback Fuzzer.
* [netzob][391]: Protocol Reverse Engineering, Modeling and Fuzzing.
* [MATE][420]: suite of tools for interactive program analysis with a focus on
  hunting for bugs in C and C++.
* [onefuzz][382]: self-hosted Fuzzing-As-A-Service platform.
* [oss-fuzz][521]: continuous fuzzing for open source software.
  * [Documentation][522]
* [papers collection][509]: Academic papers related to fuzzing.
* [propfuzz][387]: Rust toolkit to combine property-based testing and fuzzing.
* [Radamsa][386]: general purpose fuzzer.
* [Rusty-Radamsa][504]: Radamsa fuzzer ported to rust lang.
* [Safirefuzz][516]: same-Architecture Firmware Rehosting and Fuzzing.
* [SemGrep][343]: lightweight static analysis for many languages.
  * [0xdea rules][551]
  * [Rules][344]: Semgrep rules to facilitate vulnerability research.
  * [Trail-of-bits rules][550]
* [silifuzz][422]: finds CPU defects by fuzzing software proxies.
* [Syzkaller][37]: unsupervised coverage-guided kernel fuzzer.
  * [Syzbot][94]: continuously fuzzes main Linux kernel branches and
    automatically reports found bugs
  * [SyzScope][413]: automatically uncover high-risk impacts given a bug with
    only low-risk impacts.
* [weggli][270]: fast and robust semantic search tool for C and C++ codebases.

## Misc

* [Arti][427]: implementation of Tor, in Rust.
* [bat][625]: A cat(1) clone with wings.
* [broot][626]: A new way to see and navigate directory trees
* [Caddy][363]: fast, multi-platform web server with automatic HTTPS.
* [CoreUtils][214]: Cross-platform Rust rewrite of the GNU coreutils.
* [delta][632]: syntax-highlighting pager for git, diff, and grep output.
* [difftastic][440]: structural diff that understands syntax.
* [e9patch][582]: static binary rewriting tool.
* [esphome.io][449]: control your ESP8266/ESP32.
* [f4pga][450]: fully open source toolchain for the development of FPGAs of
  multiple vendors.
* [fccid][433]: information resource for all wireless device applications filed
  with the FCC.
* [fd][627]: A simple, fast and user-friendly alternative to 'find'
* [FlipperZero][402]: portable multi-tool for pentesters and geeks in a toy-like
  body.
* [fx][638]: Terminal JSON viewer & processor
* [fzf][636]: command-line fuzzy finder.
* [Googl Home][452]: smart home ecosystem.
* [httpie (cli)][640]: modern, user-friendly command-line HTTP client for the
API era.
* [jless][434]: command-line JSON viewer designed for reading, exploring, and
  searching through JSON data.
* [klgrth][245]: pastebin alternative.
* [jnv][634]: interactive JSON filter using jq
* [jq][637]: Command-line JSON processor
* [lazygit][639]: simple terminal UI for git commands.
* [lsd][631]: next gen ls command.
* [makefiletutorial][487]: makefile tutorial
* [miller][629]: like awk, sed, cut, join, and sort for name-indexed data such
as CSV, TSV, and tabular JSON.
* [miniserve][634]: serve some files over HTTP right now.
* [OpenSK][67]: open-source implementation for security keys written in Rust.
* [partialzip][664]: download single files from inside online zip archives.
* [Pastebin][242]: store any text online for easy sharing.
* [patents][434]: patents db from Google.
* [Polypyus][191]: locate functions in raw binaries by extracting known functions
  from similar binaries.
* [procs][633]: modern replacement for ps written in Rust.
* [pspy][264]: monitor linux processes without root permissions.
* [ranger][642]: VIM-inspired filemanager for the console
* [ripgrep][628]: line-oriented search tool.
* [sd][641]: Intuitive find & replace CLI.
* [sniffglue][455]: Secure multithreaded packet sniffer (in rust).
* [sniffle][444]: sniffer for Bluetooth 5 and 4.x LE.
* [temp.sh][246]: alternative to transfer.sh.
* [transfer.sh][243]: easy file sharing from the command line.
* [uhr][237]: Universal Radio Hacker.
* [wabt][255]: WebAssembly Binary Toolkit.
* [yazi][643]: terminal file manager written in Rus
* [ZeroBin][244]: open source online pastebin where the server has zero
  knowledge of pasted data.

## Networking

* Illustrated Connections:
  * [DTLS][484]
  * [QUIC][483]
  * [TLS 1.2][486]
  * [TLS 1.3][485]
* Misc:
  * [innernet][421]: private network system that uses WireGuard under the hood.
  * [nebula][122]: scalable overlay networking tool.
  * [netbird][331]: connect your devices into a single secure private
    WireGuard®-based mesh network.
  * [netmaker][369]: makes networks with WireGuard.
  * [tailscale][357]: zero config VPN.
    * [tailscale github][358]: the easiest, most secure way to use WireGuard and
      2FA.
  * [scapy][539]: Python-based interactive packet manipulation program &
  library.
  * [zeek][368]: network analysis framework.
  * [zerotier][356]: secure networks between devices.
    * [ZeroTierOne][357]: smart ethernet switch for earth.
* Network Scanners:
  * [masscan][8]: TCP port scanner, spews SYN packets asynchronously.
  * [nmap][4]: utility for network scanning and discovery and security auditing
  * [RustScan][5]: quick port scanner implemented in rust.
  * [skanuvaty][7]: fast DNS/network/port scanner.
  * [ZGrab2][266]: fast, modular application-layer network scanner.
  * [ZMap][6]: fast single packet network scanner.

## Programming Languages

* [libhunt][567]: trending open-source projects and their alternatives
* Assembly:
  * ARM:
    * [Docs][124]: official documentation.
    * [Instructions Reference][125]: official instruction reference.
    * [A Guide to ARM64 / AArch64 Assembly on Linux][527]
  * MIPS:
    * [Manuals][128]: official manuals.
  * RISC-V:
    * [Book assembly][312]: introduction to Assembly Programming with RISC-V.
    * [Manuals][129]: official specifications.
    * [RISC-V card][285]: unofficial assembly reference for RISC-V.
  * x86:
    * [felixcloutier.com][126]: instructions reference.
    * [Software Developer Manuals][127]: official manuals.
* [C][57]: C reference
  * libc implementations:
    * [glibc][58]: GNU C library.
    * [musl][59]: C standard library.
    * [uclibc][60]: C library for developing embedded Linux systems.
    * [uclibc-ng][61]: small C library for developing embedded Linux systems.
    * [uv][660]: Cross-platform asynchronous I/O
  * Libraries:
    * [libaco][104]: blazing fast and lightweight C asymmetric coroutine
      library.
    * [libdill][269]: structured concurrency in C.
    * [linux-syscall-support][431]: low level C API for making direct Linux syscalls.
    * [sc][271]: common libraries and data structures for C.
* [Go][106]: open source programming language supported by Google.
  * [Docs][107]: official documentation.
  * [pkg.go.dev][108]: packages documentation.
* [Python][535]: official website
  * [Docs][536]: official documentation
    * [standard library][566]
  * [awesome-python][568]: curated list of awesome Python frameworks,
  libraries, software and resources.
  * [Hitchhiker’s Guide][569]: best practice handbook.
  * [mamba][548]: fast, robust, and cross-platform package manager.
  * [packaging][564]
    * [poetry][549]: packaging and dependency management.
  * [pypi][570]: repository of software for the Python programming language.
  * [PySnooper][579]: poor man's debugger for Python.
  * [realpython][565]: python guides and tutorials.
* [Rust][41]: secure system programming language.
  * [aquascope][466]: Interactive visualizations of Rust at compile-time and run-time
  * [API guidelines][319]: set of recommendations on how to design and present
    APIs for the Rust programming.
  * [AreWeRustYet][465]: Awesome list of "Are We *thing* Yet" for Rust
  * [Black Hat Rust][380]: applied offensive security with Rust.
  * [Book][42]: introductory book about Rust.
  * [Book (Brown univ)][505]: Rust book experiment.
  * [Cargo][571]
    * [Cargo Book][129]: official cargo book.
    * [cargo-machete][572]: Remove unused Rust dependencies
    * [cargo-make][574]: task runner and build tool.
    * [nextest][573]: next-generation test runner for Rust
  * [Cheats][398]: Rust language cheat sheet.
  * [Clippy][218]: lints to catch common mistakes and improve your Rust code.
  * [Command Line Applications in Rust][563]:
  * [crates.io][44]: rust community's crate registry.
  * [cryptography.rs][464]: list of actively maintained, high-quality
    cryptography libraries.
  * [Design patterns][321]: catalogue of Rust design patterns, anti-patterns and
    idioms.
  * [docker-rust][541]: Docker official image for rust.
  * [Easy Rust][311]: rust explained using easy English.
  * [Editions][309]: editions guide.
  * [Embedded Rust Book][153]: introductory book about using the Rust
    Programming Language on "Bare Metal" embedded systems.
  * [esp-rs][454]: Rust on ESP.
  * [flamegraph][577]: Easy flamegraphs for Rust projects.
  * [How to learn modern Rust][498]: guide to rust adventurer.
  * [Macros][308]: the little book of rust macros.
  * [min-sized-rust][373]: how to minimize Rust binary size.
  * [miri][621]: interpreter for Rust's mid-level intermediate representation.
  * [Offensive Rust][379]: Rust Weaponization for Red Team Engagements.
  * [Official Repository][286]: official Rust repository.
  * [Performance][322]: Rust Performance Book.
  * [Practice][375]: easily diving into and get skilled with Rust.
  * [pretzelhammer's Rust blog][657]
  * [proc-macro-workshop][645]: Learn to write Rust procedural macros.
  * [Raspberrypi OS Tutorials][186]: learn to write an embedded OS in Rust.
  * [Redox OS][318]: Unix-like Operating System written in Rust.
  * [RFCs][320]: RFCs for changes to Rust.
  * [Rust by Example][503]: collection of runnable examples.
  * [Rust Embedded][542]: Rust on Embedded Devices Working Group.
  * [rustsec][575]: RustSec API & Tooling.
  * [rust-musl-cross][540]: Docker images for compiling static Rust binaries
  using musl-cross.
  * [Rust cookbook][544]: collection of simple examples in Rust
  * [Rust for professionals][545]: short introduction to Rust
  * [rust-indexed][620]
  * [Rust to Assembly][501]: Understanding the Inner Workings of Rust.
  * [RustBooks][547]: List of Rust books
  * [Rustonomicon][150]: awful details that you need to understand when writing
    Unsafe Rust programs.
  * [rust-learning][546]: links to blog posts, articles, videos, etc for
  learning Rust.
  * [Rust Reference][151]: primary reference for the Rust programming language.
  * [rustup][152]: installer for the systems programming language Rust.
  * [std][43]: standard library documentation.
  * [The Little Book of Rust Books][619]
  * [Usafe Code Guidelines][552]: "guide" for writing unsafe code
  * [Windows RS][383]: Rust for Windows.
  * [This Week In Rust][148]: handpicked Rust updates, delivered to your inbox.
  * Libraries:
    * Async Runtimes:
      * [async-std][325]: async version of the Rust standard library.
      * [smol][326]: small and fast async runtime for Rust.
      * [Tokio][323]: runtime for writing reliable asynchronous applications
        with Rust.
        * [Tutorial][324]: official Tokio tutorial.
        * [console][576]: debugger for async rust.
    * [avml][384]: Acquire Volatile Memory for Linux.
    * [Aya][222]: eBPF library for the Rust programming language.
    * [binrw][661]: parse and rebuild binary data.
    * [cbindgen][499]: project for generating C bindings from Rust code.
    * [cross][553]: “Zero setup” cross compilation and “cross testing” of Rust
    crates.
    * [embassy][399]: framework for embedded applications.
    * [Goblin][99]: cross-platform binary parsing crate, written in Rust.
    * [libp2p][241]: Rust Implementation of the libp2p networking stack.
    * [nix][304]: rust friendly bindings to \*nix APIs.
    * [nom][662]: parser combinator framework
    * [py03][543]: Rust bindings for the Python interpreter.
    * [redbpf][119]: Rust library for building and running BPF/eBPF modules.
    * [redhook][96]: dynamic function call interposition / hooking (LD_PRELOAD)
      for Rust.
    * [Rustix][303]: Safe Rust bindings to POSIX/Unix/Linux/Winsock2 syscalls.
    * [rust-bindgen][500]: Automatically generates Rust FFI bindings to C (and
      some C++) libraries.
    * [teloxide][490]: Telegram bots framework for Rust.
    * [tui][489]: terminal user interfaces and dashboards using Rust.
* Shell:
  * [Shell Scripting Primer][531]: shell programming guide from Apple.

## Reverse Engineering

* [Angr][109]: user-friendly binary analysis platform.
* [BAP][282]: binary analysis platform.
* [binary-parsing][656]: list of generic tools for parsing binary data.
* [bincat][555]: Binary code static analyser.
* [BinDiff][204]: compare executables by identifying identical and similar
  functions.
  * [Source code][525]: source code of BinDiff
* [BinExport][205]: export disassemblies into Protocol Buffers.
* [CAPA][73]: tool to identify capabilities in executable files.
  * [lancelot-flirt][103]: library for parsing, compiling, and matching Fast
    Library Identification and Recognition Technology (FLIRT) signatures.
* [Capstone Engine][223]: disassembly/disassembler framework.
* [cpu_rec][301]: recognize cpu instructions in an arbitrary binary file.
* [CyberChef][155]: web app for encryption, encoding, compression and data
  analysis.
* [decomp2dbg][442]: plugin to introduce interactive symbols into your debugger
  from your decompiler.
* [Diffing (quarkslab)][526]: resources on binary diffing which is handy for
  reverse-engineering.
* [Diffware][52]: configurable tool providing a summary of the changes between
  two files or directories
  * [Diffoscope][53]: directory differ.
* [DogBolt][342]: decompiler explorer.
* [ELFKickers][156]: collection of programs that access and manipulate ELF
  files.
* [ESP32-reversing][618]: curated list of ESP32 related reversing resources
* [esp32knife][617]: Tools for ESP32 firmware dissection.
* [flare-emu][226]: easy to use and flexible interface for scripting emulation
  tasks.
* [FLOSS][102]: FLARE Obfuscated String Solver.
* [fq][227]: jq for binary formats.
* [Ghidra][206]: software reverse engineering (SRE) framework.
  * [AngryGhidra][596]: use angr in Ghidra.
  * [APIs][591]
  * [BinDiffHelper][602]: Ghidra Extension to integrate BinDiff for function matching.
  * [BTIGhidra][613]: Binary Type Inference Ghidra Plugin.
  * [Cartographer][601]: Code Coverage Exploration Plugin for Ghidra.
  * [docker-ghidra][606]: Ghidra Client/Server Docker Image.
  * [ghidra-findcrypt][603]: Ghidra analysis plugin to locate cryptographic constants.
  * [ghidra-firmware-utils][598]: Ghidra utilities for firmware reverse
    engineering.
  * [ghidra_kernelcache][599]: framework for iOS kernelcache reverse engineering.
  * [ghidra2dwarf][600]: Export ghidra decompiled code to dwarf sections inside ELF binary.
  * [Ghidralligator][534]: multi-architecture pcode emulator based on the Ghidra
  libsla.
  * [Ghidrathon][592]: Python 3 scripting to Ghidra.
  * [GhidraEmu][597]: Native Pcode emulator
  * [GhidraScripts][607]: Scripts to run within Ghidra, maintained by the Trellix ARC team.
  * [GhidraSnippets][605]: Python snippets for Ghidra's Program and Decompiler APIs.
  * [ghidrecomp][609]: Python Command-Line Ghidra Decompiler.
  * [ghidriff][532]: Python Command-Line Ghidra Binary Diffing Engine.
  * [IDAObjcTypes][604]: collection of types & functions definitions useful for Objective-C binaries analysis.
  * [pyhidra][612]: Ghidra API within a native CPython interpreter using jpype.
  * [pypcode][611]: Python bindings to Ghidra's SLEIGH library for disassembly and lifting to P-Code IR
  * [refinery][622]: transformations of binary data
  * [Sekiryu][517]: comprehensive toolkit for Ghidra headless.
  * [SVD-Loader-Ghidra][593]: SVD loader for Ghidra.
    * [cmsis-svd][594]: Aggegration of ARM Cortex-M (and other) CMSIS SVDs and related tools
    * [keil (devices)][595]: Keil devices SVDs
* [hexyl][630]: command-line hex viewer
* [ImHex][584]: Hex Editor for Reverse Engineers.
* [kaiju][610]: binary analysis framework extension for Ghidra.
* [Kaitai Struct][231]: declarative language to generate binary data parsers.
* [Keystone Engine][232]: assembler framework.
* [Linux syscalls][462]: Linux kernel syscall tables
* [mgika][578]: detect file content types with deep learning.
* [McSema][249]: Framework for lifting program binaries to LLVM bitcode.
* [Metasm][250]: a free assembler / disassembler / compiler.
* [Miasm][251]: reverse engineering framework in Python.
* [Objection][583]: runtime mobile exploration.
* [Radare2][1]: UNIX-like reverse engineering framework and command-line
  toolset.
  * [Book][98]: radare2 official book.
  * [Cutter][3]: GUI based on [Rizin][2].
  * [pwntools-r2][327]: launch radare2 like a boss from pwntools in tmux.
  * [Rizin][2]: radare2 fork.
* [REMnux][257]: Linux toolkit for reverse-engineering.
* [RetDec][252]: retargetable machine-code decompiler based on LLVM.
* [ret-sync][608]: synchronize a debugging session with disassemblers.
* [Yara][72]: pattern matching swiss knife for malware researchers.
* [z3][581]: high-performance theorem prover being developed at Microsoft

## RTOS

* [FreeRTOS][140]: open source, real-time operating system for microcontrollers.
* [MangooseOS][139]: IoT operating system and networking library.
* [MyNewt][529]: OS to build, deploy and securely manage billions of device
* [NuttX][528]: mature, real-time embedded operating system (RTOS)
* [RIOT][530]: Operating System for the Internet of Things
* [ThreadX][302]: advanced real-time operating system (RTOS) designed
  specifically for deeply embedded applications.
* [Tock][210]: secure embedded operating system for microcontrollers.
* [Zephyr][50]: mall, scalable, real-time operating system (RTOS).
  * [Docs][51]: zephyt project documentation.

## Sandboxing

* [Code Sandboxing][333]: code execution isolation and containment with sandbox
  solutions.
* [gvisor][174]: application Kernel for Containers.
* [Firecracker][175]: secure and fast microVMs for serverless computing.
* [KAta containers][306]: standard implementation of lightweight Virtual
  Machines (VMs) that feel and perform like containers, but provide the workload
  isolation and security advantages of VMs.
* [nano][176]: kernel designed to run one and only one application in a
  virtualized environment.
* [ops][178]: build and run nanos unikernels.
* [RustyHermit][189]: rust-based, lightweight unikernel.
* [sandboxed-api][177]: generates sandboxes for C/C++ libraries automatically.
* [Unikraft][268]:  automated system for building specialized OSes known as
  unikernels.

## Tools

* [curl][403]: command line tool and library for transferring data with URL
  syntax.
* [patchelf][414]: small utility to modify the dynamic linker and RPATH of ELF
  executables.
* [tcpdump][416]: command-line packet analyzer.
* [wireshark][417]: network protocol analyzer.
  * [tshark][418]: CLI tool for analyzing network traffic.
  * [tshark.dev][419]: guide to working with packet captures on the
    command-line.

## Tracing, Hooking and Instrumentation

* [bcc][118]: rools for BPF-based Linux IO analysis, networking, monitoring, and
  more.
* [bpftrace][120]: high-level tracing language for Linux eBPF.
* [cannoli][248]: high-performance QEMU memory and instruction tracing.
* [DynamoRIO][23]: runtime code manipulation system.
* [Falco][367]: cloud native runtime security tool.
* [Frida][36]: instrumentation toolkit for developers, reverse-engineers, and
  security researchers.
  * [frida-gum][589]: Cross-platform instrumentation and introspection library written in C.
  * [frida-snippets][586]: Hand-crafted Frida examples
  * [frida-tools][590]: Frida CLI tools
  * [medusa][588]: Binary instrumentation framework based on FRIDA
  * [r2frida][587]: plugin for radare2
* [LIEF][158]: library to Instrument Executable Formats.
* [ltrace][233]: intercepts and records both the dynamic library calls and
  signals.
* [QDBI][88]: a Dynamic Binary Instrumentation framework based on LLVM.
* [Reverie][453]: ergonomic and safe syscall interception framework for Linux
  (Rust).
* [S2E][300]: platform for multi-path program analysis with selective symbolic
  execution.
* [strace][254]: diagnostic, debugging and instructional userspace utility for
  Linux.
* [TinyInst][659]: lightweight dynamic instrumentation library.
* [Tracee][24]: Linux Runtime Security and Forensics using eBPF.

## Trusted Execution Environment

* [OP-TEE][54]: Open Portable Trusted Execution Environment.
  * [TrustedFirmware][188]:  reference implementation of secure software for
    Armv8-A, Armv9-A and Armv8-M.
  * [Docs][55]: official OP-TEE documentation.
* [TEE-reversing][447]: A curated list of public TEE resources for learning how
  to reverse-engineer and achieve trusted code execution on ARM devices.

# Other Lists

* [Blockchains and Smart Contracts](topics/web3.md)
* [OT/IoT Security](topics/ot_security.md)
* [Red Teaming and Offensive Security](topics/red-team-adversary-emulation.md)

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
[13]: https://guyinatuxedo.github.io/index.html
[14]: https://gcc.gnu.org/
[15]: https://clang.llvm.org/
[16]: https://toolchains.bootlin.com/
[17]: https://github.com/oz123/awesome-c
[18]: https://github.com/rust-unofficial/awesome-rust
[19]: https://github.com/phodal/awesome-iot
[20]: https://github.com/nhivp/Awesome-Embedded
[21]: https://github.com/xairy/linux-kernel-exploitation
[23]: https://github.com/DynamoRIO/dynamorio
[24]: https://github.com/aquasecurity/tracee
[25]: https://github.com/zoidbergwill/awesome-ebpf
[26]: https://www.sourceware.org/gdb/
[27]: https://github.com/hugsy/gef
[28]: https://www.qemu.org/
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
[88]: https://github.com/QBDI/QBDI
[89]: https://github.com/jtpereyda/boofuzz
[90]: https://github.com/ucsb-seclab/difuze
[91]: https://github.com/googleprojectzero/halfempty
[92]: https://github.com/trailofbits/krf
[94]: https://syzkaller.appspot.com/upstream
[95]: https://github.com/AFLplusplus/LibAFL
[96]: https://github.com/geofft/redhook
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
[122]: https://github.com/slackhq/nebula
[124]: https://developer.arm.com/documentation/
[125]: https://developer.arm.com/documentation/dui0068/b/ARM-Instruction-Reference
[126]: https://www.felixcloutier.com/x86/
[127]: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
[128]: https://www.mips.com/downloads/
[129]: https://github.com/riscv
[137]: https://github.blog/tag/github-security-lab/
[138]: https://github.com/renode/renode
[139]: https://mongoose-os.com/
[140]: https://aws.amazon.com/freertos/
[148]: https://this-week-in-rust.org/
[150]: https://doc.rust-lang.org/nomicon/
[151]: https://doc.rust-lang.org/stable/reference/
[152]: https://rustup.rs/
[153]: https://docs.rust-embedded.org/book/
[155]: https://github.com/gchq/CyberChef
[156]: https://github.com/BR903/ELFkickers
[157]: https://www.malware-traffic-analysis.net/
[158]: https://github.com/lief-project/LIEF
[159]: https://github.com/JonathanSalwan/ROPgadget
[160]: https://github.com/sashs/Ropper
[162]: https://github.com/alphaSeclab/awesome-rat/blob/master/Readme_en.md
[171]: https://github.com/cilium/tetragon
[172]: https://github.com/cilium/ebpf
[173]: https://bumblebee.io/EN
[174]: https://github.com/google/gvisor
[175]: https://github.com/firecracker-microvm/firecracker
[176]: https://github.com/nanovms/nanos
[177]: https://github.com/google/sandboxed-api
[178]: https://github.com/nanovms/ops
[181]: https://github.com/anderspitman/awesome-tunneling.git
[185]: https://www.cvedetails.com/
[186]: https://github.com/rust-embedded/rust-raspberrypi-OS-tutorials
[187]: https://github.com/unicorn-engine/unicorn
[188]: https://www.trustedfirmware.org/
[189]: https://github.com/hermitcore/rusty-hermit
[190]: https://github.com/SunHao-0/healer
[191]: https://github.com/seemoo-lab/polypyus
[192]: https://github.com/seemoo-lab/frankenstein
[193]: https://github.com/seemoo-lab/internalblue
[194]: https://www.exploitalert.com/browse-exploit.html
[195]: https://0day.today/
[196]: https://connormcgarr.github.io/
[197]: https://a13xp0p0v.github.io/
[198]: https://googleprojectzero.blogspot.com/
[199]: https://github.com/SecWiki/linux-kernel-exploits
[201]: https://github.com/scriptingxss/owasp-fstm
[202]: https://github.com/gurugio/lowlevelprogramming-university
[203]: https://github.com/chyyuu/os_kernel_lab
[204]: https://www.zynamics.com/bindiff.html
[205]: https://github.com/google/binexport
[206]: https://github.com/NationalSecurityAgency/ghidra
[207]: https://github.com/craigz28/firmwalker
[208]: https://github.com/ReFirmLabs/binwalk
[209]: https://github.com/fkie-cad/awesome-embedded-and-iot-security
[210]: https://github.com/tock/tock
[211]: https://github.com/rust-embedded/awesome-embedded-rust
[212]: https://sourceforge.net/p/openocd/code/ci/master/tree/
[213]: https://buildroot.org/
[214]: https://github.com/uutils/coreutils
[215]: https://www.linuxfromscratch.org/
[216]: https://wiki.gentoo.org/wiki/Main_Page
[217]: https://wiki.archlinux.org/
[218]: https://github.com/rust-lang/rust-clippy
[220]: https://www.zerodayinitiative.com/blog
[222]: https://github.com/aya-rs/aya
[223]: https://github.com/capstone-engine/capstone
[224]: https://github.com/e-m-b-a/emba
[225]: https://github.com/rampageX/firmware-mod-kit
[226]: https://github.com/mandiant/flare-emu
[227]: https://github.com/wader/fq
[229]: https://github.com/cyrus-and/gdb-dashboard
[230]: https://github.com/cs01/gdbgui
[231]: https://github.com/kaitai-io/kaitai_struct
[232]: https://github.com/keystone-engine/keystone
[233]: https://gitlab.com/cespedes/ltrace
[235]: https://0x434b.dev/
[236]: https://0x00sec.org/
[237]: https://github.com/jopohl/urh
[239]: https://openwrt.org/start
[241]: https://github.com/libp2p/rust-libp2p
[242]: https://pastebin.com/
[243]: https://transfer.sh/
[244]: https://zerobin.net/
[245]: https://www.klgrth.io/
[246]: https://temp.sh/
[247]: https://github.com/Ben-Lichtman/ropr
[248]: https://github.com/MarginResearch/cannoli
[249]: https://github.com/lifting-bits/mcsema
[250]: https://github.com/jjyg/metasm
[251]: https://github.com/cea-sec/miasm
[252]: https://github.com/avast/retdec
[253]: https://github.com/rr-debugger/rr
[254]: https://github.com/strace/strace
[255]: https://github.com/WebAssembly/wabt
[257]: https://remnux.org/
[264]: https://github.com/DominicBreuker/pspy
[266]: https://github.com/zmap/zgrab2
[268]: https://github.com/unikraft/unikraft
[269]: https://github.com/sustrik/libdill
[270]: https://github.com/googleprojectzero/weggli
[271]: https://github.com/tezc/sc
[272]: https://github.com/stong/how-to-exploit-a-double-free
[273]: https://github.com/V33RU/IoTSecurity101
[281]: https://github.com/alphaSeclab/awesome-network-stuff/blob/master/Readme_en.md
[282]: https://github.com/BinaryAnalysisPlatform/bap
[284]: https://github.com/dhondta/awesome-executable-packing
[285]: https://github.com/jameslzhu/riscv-card
[286]: https://github.com/rust-lang/rust
[287]: https://github.com/firmadyne/scraper
[288]: https://alexplaskett.github.io/
[290]: https://www.willsroot.io/
[291]: https://security.googleblog.com/
[292]: https://github.com/nccgroup/exploit_mitigations
[293]: https://codeql.github.com/
[294]: https://securitylab.github.com/research/one_day_short_of_a_fullchain_android/
[295]: https://github.com/google/security-research
[296]: https://grsecurity.net/blog
[297]: https://xairy.io/
[298]: https://sam4k.com/
[300]: https://github.com/S2E/s2e
[301]: https://github.com/airbus-seclab/cpu_rec
[302]: https://github.com/azure-rtos/threadx/
[303]: https://github.com/bytecodealliance/rustix
[304]: https://github.com/nix-rust/nix
[306]: https://github.com/kata-containers/kata-containers
[307]: https://github.com/sidkshatriya/rd
[308]: https://veykril.github.io/tlborm/
[309]: https://doc.rust-lang.org/stable/edition-guide/
[310]: https://github.com/tmpout/awesome-elf
[311]: https://github.com/Dhghomon/easy_rust
[312]: https://riscv-programming.org/book/riscv-book.html
[317]: https://github.com/0xInfection/Awesome-WAF
[318]: https://gitlab.redox-os.org/redox-os
[319]: https://rust-lang.github.io/api-guidelines/about.html
[320]: https://github.com/rust-lang/rfcs
[321]: https://github.com/rust-unofficial/patterns
[322]: https://github.com/nnethercote/perf-book
[323]: https://github.com/tokio-rs/tokio
[324]: https://tokio.rs/tokio/tutorial
[325]: https://github.com/async-rs/async-std
[326]: https://github.com/smol-rs/smol
[327]: https://github.com/ps1337/pwntools-r2
[331]: https://github.com/netbirdio/netbird
[333]: https://developers.google.com/code-sandboxing
[339]: https://github.com/edoardottt/awesome-hacker-search-engines
[342]: https://dogbolt.org/
[343]: https://github.com/returntocorp/semgrep
[344]: https://github.com/0xdea/semgrep-rules
[355]: https://outflux.net/blog/
[356]: https://www.zerotier.com/
[357]: https://tailscale.com/
[358]: https://github.com/zerotier/ZeroTierOne
[360]: https://github.com/Exein-io/pulsar
[361]: https://github.com/Hack-with-Github/Awesome-Hacking
[362]: https://github.com/trimstray/the-book-of-secret-knowledge
[363]: https://github.com/caddyserver/caddy
[364]: https://cheatsheetseries.owasp.org/
[365]: https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
[366]: https://linkedin.github.io/school-of-sre/
[367]: https://github.com/falcosecurity/falco
[368]: https://github.com/zeek/zeek
[369]: https://github.com/gravitl/netmaker
[371]: https://github.com/analysis-tools-dev/static-analysis
[372]: https://github.com/analysis-tools-dev/dynamic-analysis
[373]: https://github.com/johnthagen/min-sized-rust
[374]: https://github.com/ITI/ICS-Security-Tools
[375]: https://practice.rs/why-exercise.html
[376]: https://github.com/ex0dus-0x/awesome-rust-security
[379]: https://github.com/trickster0/OffensiveRust
[380]: https://github.com/skerkour/black-hat-rust
[381]: https://github.com/microsoft/lain
[382]: https://github.com/microsoft/onefuzz
[383]: https://github.com/microsoft/windows-rs
[384]: https://github.com/microsoft/avml
[385]: https://unblob.org/
[386]: https://gitlab.com/akihe/radamsa
[387]: https://github.com/facebookincubator/propfuzz
[388]: https://github.com/secfigo/Awesome-Fuzzing
[390]: https://github.com/uds-se/fuzzingbook
[391]: https://github.com/netzob/netzob
[393]: https://github.com/redballoonsecurity/ofrak
[394]: https://github.com/fuzzware-fuzzer/fuzzware
[395]: https://pawnyable.cafe/
[397]: https://github.com/0xricksanchez/paper_collection
[398]: https://cheats.rs/
[399]: https://embassy.dev/
[400]: https://github.com/karanpratapsingh/system-design
[401]: https://github.com/yangshun/tech-interview-handbook
[402]: https://github.com/flipperdevices/flipperzero-firmware
[403]: https://github.com/curl/curl
[404]: https://github.com/thezdi/PoC
[413]: https://github.com/plummm/SyzScope
[414]: https://github.com/NixOS/patchelf
[415]: https://github.com/zcutlip/nvram-faker
[416]: https://www.tcpdump.org/
[417]: https://www.wireshark.org/
[418]: https://www.wireshark.org/docs/man-pages/tshark.html
[419]: https://tshark.dev/
[420]: https://github.com/GaloisInc/MATE
[421]: https://github.com/tonarino/innernet
[422]: https://github.com/google/silifuzz
[423]: https://thephd.dev/
[424]: https://github.com/epi052/feroxfuzz
[426]: https://blog.xilokar.info/
[427]: https://gitlab.torproject.org/tpo/core/arti
[428]: https://cve-north-stars.github.io/
[431]: https://chromium.googlesource.com/linux-syscall-support/
[433]: https://fccid.io/
[434]: https://patents.google.com/
[435]: https://www.apps3c.info/
[436]: https://swisskyrepo.github.io/HardwareAllTheThings/
[437]: https://github.com/PreOS-Security/awesome-firmware-security
[438]: https://github.com/djsime1/awesome-flipperzero
[439]: https://epi052.gitlab.io/notes-to-self/
[440]: https://github.com/AmbiML/sparrow-kata-full
[442]: https://github.com/mahaloz/decomp2dbg
[444]: https://github.com/nccgroup/Sniffle
[447]: https://github.com/enovella/TEE-reversing
[448]: https://github.com/andreia-oca/awesome-embedded-fuzzing
[449]: https://esphome.io/
[450]: https://f4pga.org/
[451]: https://class.malware.re/
[452]: https://developers.home.google.com/
[453]: https://github.com/facebookexperimental/reverie
[454]: https://github.com/esp-rs
[455]: https://github.com/kpcyrd/sniffglue
[456]: https://n1ght-w0lf.github.io
[457]: https://github.com/io12/pwninit
[458]: https://github.com/skysider/pwndocker
[459]: https://github.com/bsauce/kernel-exploit-factory
[462]: https://syscalls.mebeim.net/?table=arm/32/eabi/v6.2
[464]: https://cryptography.rs/
[465]: https://github.com/UgurcanAkkok/AreWeRustYet
[466]: https://github.com/cognitive-engineering-lab/aquascope
[480]: https://github.com/f/awesome-chatgpt-prompts
[481]: https://github.com/promptslab/Awesome-Prompt-Engineering
[482]: https://github.com/dair-ai/Prompt-Engineering-Guide
[483]: https://quic.xargs.org
[484]: https://dtls.xargs.org
[485]: https://tls13.xargs.org
[486]: https://tls12.xargs.org
[487]: https://makefiletutorial.com
[488]: https://github.com/e-m-b-a/embark
[489]: https://github.com/fdehau/tui-rs
[490]: https://github.com/teloxide/teloxide
[491]: https://github.com/awesome-lists/awesome-bash
[492]: https://github.com/dylanaraps/pure-bash-bible
[493]: https://github.com/ibraheemdev/modern-unix
[494]: https://github.com/onceupon/Bash-Oneliner
[495]: https://github.com/denysdovhan/bash-handbook
[496]: https://github.com/jlevy/the-art-of-command-line
[497]: https://github.com/rockerBOO/awesome-neovim
[498]: https://github.com/joaocarvalhoopen/How_to_learn_modern_Rust
[499]: https://github.com/mozilla/cbindgen
[500]: https://github.com/rust-lang/rust-bindgen
[501]: https://eventhelix.com/rust/
[502]: https://github.com/google/fuzztest
[503]: https://doc.rust-lang.org/stable/rust-by-example/index.html
[504]: https://github.com/microsoft/rusty-radamsa
[505]: https://rust-book.cs.brown.edu/
[506]: https://github.com/wcventure/FuzzingPaper
[507]: https://github.com/rust-fuzz/cargo-fuzz
[508]: https://github.com/mykter/afl-training
[509]: https://github.com/0xricksanchez/paper_collection
[510]: https://github.com/antonio-morales/Fuzzing101
[511]: https://llvm.org/docs/LibFuzzer.html
[512]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md
[513]: https://github.com/google/fuzzing
[514]: https://github.com/rust-fuzz/libfuzzer
[515]: https://github.com/icicle-emu/icicle
[516]: https://github.com/pr0me/SAFIREFUZZ
[517]: https://github.com/20urc3/Sekiryu
[518]: https://github.com/ex0dus-0x/fuzzable
[519]: https://github.com/AFLplusplus/Grammar-Mutator
[520]: https://github.com/nautilus-fuzz/nautilus
[521]: https://github.com/google/oss-fuzz
[522]: https://google.github.io/oss-fuzz/
[523]: https://github.com/ossf/fuzz-introspector
[524]: https://github.com/rust-fuzz/arbitrary/
[525]: https://github.com/google/bindiff/tree/main
[526]: http://diffing.quarkslab.com
[527]: https://modexp.wordpress.com/2018/10/30/arm64-assembly/
[528]: https://nuttx.apache.org
[529]: https://mynewt.apache.org
[530]: https://www.riot-os.org
[531]: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/Introduction/Introduction.html#//apple_ref/doc/uid/TP40004268-TP40003516-SW1
[532]: https://github.com/clearbluejar/ghidriff
[533]: https://maxwelldulin.com/Blog
[534]: https://github.com/airbus-cyber/ghidralligator
[535]: https://www.python.org
[536]: https://www.python.org/doc/
[537]: https://github.com/pwndbg/pwndbg
[538]: https://github.com/osandov/drgn
[539]: https://github.com/secdev/scapy
[540]: https://github.com/rust-cross/rust-musl-cross
[541]: https://github.com/rust-lang/docker-rust
[542]: https://github.com/rust-embedded
[543]: https://github.com/PyO3/PyO3
[544]: https://rust-lang-nursery.github.io/rust-cookbook/
[545]: https://overexact.com/rust-for-professionals/
[546]: https://github.com/ctjhoa/rust-learning
[547]: https://github.com/sger/RustBooks
[548]: https://mamba.readthedocs.io/en/latest/index.html
[549]: https://python-poetry.org
[550]: https://github.com/trailofbits/semgrep-rules
[551]: https://github.com/0xdea/semgrep-rules
[552]: https://rust-lang.github.io/unsafe-code-guidelines/
[553]: https://github.com/cross-rs/cross
[554]: https://lldb.llvm.org
[555]: https://github.com/airbus-seclab/bincat
[556]: https://github.com/snare/voltron
[557]: https://github.com/foundryzero/llef
[558]: https://github.com/rohanrhu/gdb-frontend
[559]: https://blog.malware.re
[560]: https://github.com/KeenSecurityLab/BinAbsInspector
[561]: https://github.com/quickemu-project/quickemu
[562]: https://appsec.guide
[563]: https://rust-cli.github.io/book/index.html
[564]: https://packaging.python.org/en/latest/
[565]: https://realpython.com
[566]: https://docs.python.org/3/py-modindex.html
[567]: https://www.libhunt.com
[568]: https://awesome-python.com
[569]: https://docs.python-guide.org/#scenario-guide-for-python-applications
[570]: https://pypi.org
[571]: https://github.com/rust-lang/cargo
[572]: https://github.com/bnjbvr/cargo-machete
[573]: https://github.com/nextest-rs/nextest
[574]: https://github.com/sagiegurari/cargo-make
[575]: https://github.com/rustsec/rustsec/tree/main
[576]: https://github.com/tokio-rs/console
[577]: https://github.com/flamegraph-rs/flamegraph
[578]: https://github.com/google/magika
[579]: https://github.com/cool-RR/PySnooper
[580]: https://github.com/joernio/joern
[581]: https://github.com/Z3Prover/z3
[582]: https://github.com/GJDuck/e9patch
[583]: https://github.com/sensepost/objection
[584]: https://github.com/WerWolv/ImHex
[585]: https://github.com/DerekSelander/LLDB
[586]: https://github.com/iddoeldor/frida-snippets
[587]: https://github.com/nowsecure/r2frida
[588]: https://github.com/Ch0pin/medusa
[589]: https://github.com/frida/frida-gum
[590]: https://github.com/frida/frida-tools
[591]: https://ghidra.re/ghidra_docs/api/index.html
[592]: https://github.com/mandiant/Ghidrathon
[593]: https://github.com/leveldown-security/SVD-Loader-Ghidra?tab=readme-ov-file
[594]: https://github.com/cmsis-svd/cmsis-svd
[595]: https://www.keil.arm.com/devices/
[596]: https://github.com/Nalen98/AngryGhidra
[597]: https://github.com/Nalen98/GhidraEmu
[598]: https://github.com/al3xtjames/ghidra-firmware-utils
[599]: https://github.com/0x36/ghidra_kernelcache
[600]: https://github.com/cesena/ghidra2dwarf
[601]: https://github.com/nccgroup/Cartographer
[602]: https://github.com/ubfx/BinDiffHelper
[603]: https://github.com/TorgoTorgo/ghidra-findcrypt
[604]: https://github.com/PoomSmart/IDAObjcTypes
[605]: https://github.com/HackOvert/GhidraSnippets
[606]: https://github.com/blacktop/docker-ghidra
[607]: https://github.com/advanced-threat-research/GhidraScripts
[608]: https://github.com/bootleg/ret-sync
[609]: https://github.com/clearbluejar/ghidrecomp
[610]: https://github.com/CERTCC/kaiju
[611]: https://github.com/angr/pypcode
[612]: https://github.com/dod-cyber-crime-center/pyhidra
[613]: https://github.com/trailofbits/BTIGhidra
[614]: https://github.com/alphaSeclab/awesome-reverse-engineering
[615]: https://github.com/wtsxDev/reverse-engineering
[616]: https://github.com/onethawt/reverseengineering-reading-list
[617]: https://github.com/jmswrnr/esp32knife
[618]: https://github.com/BlackVS/ESP32-reversing
[619]: https://lborb.github.io/book/official.html
[620]: https://rust-indexed.com
[621]: https://github.com/rust-lang/miri
[622]: https://github.com/binref/refinery
[623]: https://github.com/you-dont-need/You-Dont-Need-GUI
[624]: https://github.com/trinib/Linux-Bash-Commands
[625]: https://github.com/sharkdp/bat
[626]: https://github.com/Canop/broot
[627]: https://github.com/sharkdp/fd
[628]: https://github.com/BurntSushi/ripgrep
[629]: https://github.com/johnkerl/miller
[630]: https://github.com/sharkdp/hexyl
[631]: https://github.com/lsd-rs/lsd
[632]: https://github.com/dandavison/delta
[633]: https://github.com/dalance/procs
[634]: https://github.com/svenstaro/miniserve
[636]: https://github.com/junegunn/fzf
[637]: https://github.com/jqlang/jq
[638]: https://github.com/antonmedv/fx
[639]: https://github.com/jesseduffield/lazygit
[640]: https://github.com/httpie/cli
[641]: https://github.com/chmln/sd
[642]: https://github.com/ranger/ranger
[643]: https://github.com/sxyazi/yazi
[644]: https://github.com/rothgar/awesome-tmux
[645]: https://github.com/dtolnay/proc-macro-workshop
[656]: https://github.com/dloss/binary-parsing?tab=readme-ov-file
[657]: https://github.com/pretzelhammer/rust-blog
[658]: https://github.com/Hirrolot/awesome-c-preprocessor
[659]: https://github.com/googleprojectzero/TinyInst
[660]: https://libuv.org
[661]: https://binrw.rs
[662]: https://github.com/rust-bakery/nom
[663]: https://github.com/ronin-rb/ronin-exploits#readme
[664]: https://github.com/marcograss/partialzip
