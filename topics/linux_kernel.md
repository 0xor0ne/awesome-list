# Linux Kernel

## Content

* [Blogs and Awesomes](#blogs-awesomes-and-learning)
* [Exploitation](#exploitation)
* [Fuzzing](#fuzzing)
* [Misc](#misc)
* [Toolchains and Cross-compilation](#toolchains-and-cross-compilation)
* [Repositories](#repositories)
* [Resources](#resources)
* [Rootkits](#rootkits)
* [Rust](#rust)

## Blogs, Awesomes and learning

* [build linux][89]: short tutorial about building Linux based operating
  systems.
* [How did I approach making linux LKM rootkit, “reveng_rtkit” ?][70]
* [Linux kernel programming][90]: code repository for Linux Kernel Programming,
  published by Packt.
* [man pages][95]: manual pages for GNU/Linux
* Linux rootkit series by Xcellerator
  * [Introduction and Workflow][51]
  * [Ftrace and Function Hooking][52]
  * [A Backdoor to Root][53]
  * [Backdooring PRNGs by Interfering with Char Devices][54]
  * [Hiding Kernel Modules from Userspace][55]
  * [Hiding Directories][56]
  * [Hiding Processes][57]
  * [Hiding Open Ports][58]
  * [Hiding Logged In Users (Modifying File Contents Without Touching Disk)][59]
  * [A Dive into the Kernel Component of Drovorub][60]
  * [New Methods for Kernel 5.7+][61]
* [Writing a simple rootkit for linux][87]

## Exploitation

* [kasld][1]: collection of various techniques to infer the Linux kernel base
  virtual address as an unprivileged local user.
* [kernel-exploit-factory][16]: Linux kernel CVE exploit analysis report and
  relative debug environment.
* [Linux Exploit Suggester][83]: Linux privilege escalation auditing tool
* [Linux Kernel Exploit][17]: links related to Linux kernel exploitation.
* [Linux Kernel Exploitation][18]: collection of links related to Linux kernel
  security and exploitation.

## Fuzzing

* [difuze][19]: fuzzer for Linux Kernel Drivers.
* [healer][92]: Kernel fuzzer inspired by Syzkaller.
* [Syzkaller][20]: unsupervised coverage-guided kernel fuzzer.
  * [Syzbot][21]: continuously fuzzes main Linux kernel branches and
    automatically reports found bugs
  * [SyzScope][22]: automatically uncover high-risk impacts given a bug with
    only low-risk impacts.

## Misc

* [Clang Built Linux][23]: building the Linux kernel with Clang.
* [crash][96]: Linux kernel crash utility
* [lowlevelprogramming-university][82]: How to be low-level programmer
* [TuxSuite][42]: on-demand APIs and tools for building Linux Kernels.
* [vmlinux-to-elf][86]: tool to recover a fully analyzable .ELF from a raw
  kernel.

## Toolchains and Cross-compilation

* [Buildroot][15]: simple, efficient and easy-to-use tool to generate embedded
  Linux systems through cross-compilation.
* [clang][11]: C language family frontend for LLVM.
* [Cross-compilation toolchains (Bootlin)][12]: large number of ready-to-use
  cross-compilation toolchains, targetting the Linux operating system on a large
  number of architectures.
* [Dockcross][14]: cross compiling toolchains in Docker images.
* [gcc][13]: GNU Compiler Collection.

## Repositories

* [Next][48]: next tree
* [Rust][49]: rust tree
* [Stable][47]: Stable tree
* [Torvalds][46]: Linus Torvald tree

## Resources

* [Bootlin courses][66]: Linux related courses from bootlin
  * [Training material][94]: embedded Linux and kernel training materials.
* [Defence Map][24]: relationships between vulnerability classes, exploitation
  techniques, bug detection mechanisms, and defence technologies.
* [Elixir][40]: Linux kernel source code cross reference.
* [kconfig-hardened-check][25]: tool for checking the security hardening
  options of the Linux kernel.
* [kernel-security-learning][26]: Anything about kernel security.
* [Kernel documentation][27]: official linux kernel documentation.
* [Kernel map][67]: interactive map of Linux kernel sources.
* [kernel.org][28]: linux kernel archives.
* [kernelci.org][29]: test system focused on the upstream Linux kernel.
* [kernelconfig][30]: Linux kernel configuration entries.
* [like-gdb][31]: fully dockerized Linux kernel debugging environment.
* [Linux lab][85]: create a Docker and QEMU based Linux development Lab to
  easier the learning.
* [linux-insides][32]: a book about linux kernel and its insides.
* [Linux kernel CVEs][93]: Tracking CVEs for the linux Kernel
* [Linux Kernel Labs][63]: lectures and labs on Linux Kernel.
* [Linux Kernel Module Cheat][33]: emulation setup to study and develop the
  Linux kernel.
* [Linux Kernel Wiki][84]: linux kernel wiki (in chinese)
* [Linux Kernel Workshop][65]: learn linux kernel programming.
* [Linux Weekly News][64]: site dedicated to producing the best coverage from
  within the Linux and free software development communities.
* [LKFT][34]: Linux Kernel Functional Testing.
* [lkmpg][35]: The Linux Kernel Module Programming Guide.
* [ltp][36]: Linux Test Project.
* [Mailing Lists]:
  * [Lore kernel][37]: Linux kernel mailing lists.
    * [Linux hardening][38]: Linux hardening.
    * [Kernel Hardening][39]: kernel hardening.
* [mebeim][62]: Linux kernel syscall tables.

## Rootkits

* [1337kit][81]: 64-bit LKM Rootkit builder based on yaml prescription.
* [Awesome Linux Rootkits][2].
* [brokepkg][77]: LKM rootkit working in Linux Kernels 2.6.x/3.x/4.x/5.x
* [Brootus][76]: educational Linux Kernel Rootkit.
* [Diamorphine][3]: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and
  ARM64.
* [Drovorub][50]: Analysis of Drovorub
* [enyelkm][78]: LKM rootkit for Linux x86 with the 2.6 kerne
* [KoviD][79]: Kernel rk
* [linux-rootkit][80]: Remote Linux Loadable Kernel Module (LKM) rootkit (For
  Linux Kernels 5.x).
* [linux-rootkits][75]: collection of Linux kernel rootkits found across the
  internet taken and put together.
* [Pinkit][4]: LKM rootkit that executes a reverse TCP netcat shell with root
  privileges.
* [Red Blue Teams][72]: Linux Rootkits (4.x Kernel)
* [Reptile][5]: LKM Linux rootkit.
* [Research rootkit][6]: LibZeroEvil & the Research Rootkit project.
* [Reveng_rtkit][69]: Linux Loadable Kernel Module (LKM) based rootkit (ring-0).
* [rkduck][73]: Linux v4.x.x Rootkit
* [Rootkit][7]: rootkit for Ubuntu 16.04 and 10.04 (Linux Kernels 4.4.0 and
  2.6.32), both i386 and amd64.
* [Rootkit list download][8]: list of rootkits (includes also userspace
  rootkits).
* [rootkitkev][74]: Rootkit Development tutorial series.
* [Satan][88]: x86 Linux Kernel rootkit for Debian 9 
* [spy][91]: Linux kernel mode debugfs keylogger.
* [Sutekh][9]: rootkit that gives a userland process root permissions.
* [TripleCross][10]: Linux eBPF rootkit.

## Rust

* [Getting started][45]: official documentation for getting started with Rust
  and Linux kernel.
* [knock-out][44]: example of a kernel module in Rust.
* [out-of-tree][68]: basic template for an out-of-tree Linux kernel module
  written in Rust.
* [Rust for Linux][43]: organization for adding support for the Rust language
  to the Linux kernel.
* [Rust for Linux mailing list][41]: rust for Linux mailing list
* [Rust Kernel Programming (blog)][71]

[1]: https://github.com/bcoles/kasld
[2]: https://github.com/milabs/awesome-linux-rootkits
[3]: https://github.com/m0nad/Diamorphine
[4]: https://github.com/PinkP4nther/Pinkit
[5]: https://github.com/f0rb1dd3n/Reptile
[6]: https://github.com/NoviceLive/research-rootkit
[7]: https://github.com/nurupo/rootkit
[8]: https://github.com/d30sa1/RootKits-List-Download
[9]: https://github.com/PinkP4nther/Sutekh
[10]: https://github.com/h3xduck/TripleCross
[11]: https://clang.llvm.org/
[12]: https://toolchains.bootlin.com/
[13]: https://gcc.gnu.org/
[14]: https://github.com/dockcross/dockcross
[15]: https://buildroot.org/
[16]: https://github.com/bsauce/kernel-exploit-factory
[17]: https://github.com/SecWiki/linux-kernel-exploits
[18]: https://github.com/xairy/linux-kernel-exploitation
[19]: https://github.com/ucsb-seclab/difuze
[20]: https://github.com/google/syzkaller
[21]: https://syzkaller.appspot.com/upstream
[22]: https://github.com/plummm/SyzScope
[23]: https://clangbuiltlinux.github.io/
[24]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[25]: https://github.com/a13xp0p0v/kconfig-hardened-check
[26]: https://github.com/bsauce/kernel-security-learning
[27]: https://www.kernel.org/doc/html/latest/index.html
[28]: https://kernel.org/
[29]: https://kernelci.org/
[30]: https://www.kernelconfig.io/index.html
[31]: https://github.com/0xricksanchez/like-dbg
[32]: https://0xax.gitbooks.io/linux-insides/content/
[33]: https://github.com/cirosantilli/linux-kernel-module-cheat
[34]: https://lkft.linaro.org/
[35]: https://sysprog21.github.io/lkmpg/
[36]: https://github.com/linux-test-project/ltp
[37]: https://lore.kernel.org/
[38]: https://lore.kernel.org/linux-hardening/
[39]: https://lore.kernel.org/kernel-hardening/
[40]: https://lore.kernel.org/kernel-hardening/
[41]: https://lore.kernel.org/rust-for-linux/
[42]: https://tuxsuite.com/
[43]: https://github.com/Rust-for-Linux
[44]: https://github.com/jbaublitz/knock-out
[45]: https://docs.kernel.org/rust/quick-start.html
[46]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
[47]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/
[48]: https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/
[49]: https://github.com/Rust-for-Linux/linux
[50]: https://access.redhat.com/articles/5320961
[51]: https://xcellerator.github.io/posts/linux_rootkits_01/
[52]: https://xcellerator.github.io/posts/linux_rootkits_02/
[53]: https://xcellerator.github.io/posts/linux_rootkits_03/
[54]: https://xcellerator.github.io/posts/linux_rootkits_04/
[55]: https://xcellerator.github.io/posts/linux_rootkits_05/
[56]: https://xcellerator.github.io/posts/linux_rootkits_06/
[57]: https://xcellerator.github.io/posts/linux_rootkits_07/
[58]: https://xcellerator.github.io/posts/linux_rootkits_08/
[59]: https://xcellerator.github.io/posts/linux_rootkits_09/
[60]: https://xcellerator.github.io/posts/linux_rootkits_10/
[61]: https://xcellerator.github.io/posts/linux_rootkits_11/
[62]: https://syscalls.mebeim.net/?table=x86/64/x64/v6.2
[63]: https://linux-kernel-labs.github.io/refs/heads/master/
[64]: https://lwn.net
[65]: https://lkw.readthedocs.io/en/latest/index.html
[66]: https://bootlin.com/training/
[67]: https://makelinux.github.io/kernel/map/
[68]: https://github.com/Rust-for-Linux/rust-out-of-tree-module
[69]: https://github.com/reveng007/reveng_rtkit
[70]: https://reveng007.github.io/blog/2022/03/08/reveng_rkit_detailed.html
[71]: https://coderjoshdk.github.io/posts/Rust-Kernel-Programming.html
[72]: https://github.com/pentesteracademy/linux-rootkits-red-blue-teams/tree/master
[73]: https://github.com/QuokkaLight/rkduck
[74]: https://github.com/SourceCodeDeleted/rootkitdev-linux/tree/master
[75]: https://github.com/R3x/linux-rootkits
[76]: https://github.com/dsmatter/brootus
[77]: https://github.com/R3tr074/brokepkg
[78]: https://github.com/therealdreg/enyelkm
[79]: https://github.com/carloslack/KoviD
[80]: https://github.com/Zhang1933/linux-rootkit
[81]: https://github.com/lukasbalazik123/1337kit
[82]: https://github.com/gurugio/lowlevelprogramming-university
[83]: https://github.com/The-Z-Labs/linux-exploit-suggester
[84]: https://github.com/0voice/linux_kernel_wiki
[85]: https://github.com/tinyclub/linux-lab
[86]: https://github.com/marin-m/vmlinux-to-elf
[87]: https://0x00sec.org/t/writing-a-simple-rootkit-for-linux/29034
[88]: https://github.com/aesophor/satan
[89]: https://github.com/MichielDerhaeg/build-linux
[90]: https://github.com/PacktPublishing/Linux-Kernel-Programming
[91]: https://github.com/jarun/spy
[92]: https://github.com/SunHao-0/healer
[93]: https://github.com/nluedtke/linux_kernel_cves
[94]: https://github.com/bootlin/training-materials
[95]: https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/
[96]: https://crash-utility.github.io
