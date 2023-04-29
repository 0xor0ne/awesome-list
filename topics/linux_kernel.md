# Linux Kernel

## Content

* [Blog and Awesomes](#blog-and-awesomes)
* [Exploitation](#exploitation)
* [Fuzzing](#fuzzing)
* [Misc](#misc)
* [Toolchains and Cross-compilation](#toolchains-and-cross-compilation)
* [Repositories](#repositories)
* [Resources](#resources)
* [Rootkits](#rootkits)
* [Rust](#rust)

## Blog and Awesomes

## Exploitation

* [kasld][1]: collection of various techniques to infer the Linux kernel base
  virtual address as an unprivileged local user.
* [kernel-exploit-factory][16]: Linux kernel CVE exploit analysis report and
  relative debug environment.
* [Linux Kernel Exploit][17]: links related to Linux kernel exploitation.
* [Linux Kernel Exploitation][18]: collection of links related to Linux kernel
  security and exploitation.

## Fuzzing

* [difuze][19]: fuzzer for Linux Kernel Drivers.
* [Syzkaller][20]: unsupervised coverage-guided kernel fuzzer.
  * [Syzbot][21]: continuously fuzzes main Linux kernel branches and
    automatically reports found bugs
  * [SyzScope][22]: automatically uncover high-risk impacts given a bug with
    only low-risk impacts.

## Misc

* [Clang Built Linux][23]: building the Linux kernel with Clang.
* [TuxSuite][42]: on-demand APIs and tools for building Linux Kernels.

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

* [Defence Map][24]: relationships between vulnerability classes, exploitation
  techniques, bug detection mechanisms, and defence technologies.
* [Elixir][40]: Linux kernel source code cross reference.
* [kconfig-hardened-check][25]: tool for checking the security hardening
  options of the Linux kernel.
* [kernel-security-learning][26]: Anything about kernel security.
* [Kernel documentation][27]: official linux kernel documentation.
* [kernel.org][28]: linux kernel archives.
* [kernelci.org][29]: test system focused on the upstream Linux kernel.
* [kernelconfig][30]: Linux kernel configuration entries.
* [like-gdb][31]: fully dockerized Linux kernel debugging environment.
* [linux-insides][32]: a book about linux kernel and its insides.
* [Linux Kernel Module Cheat][33]: emulation setup to study and develop the
  Linux kernel.
* [LKFT][34]: Linux Kernel Functional Testing.
* [lkmpg][35]: The Linux Kernel Module Programming Guide.
* [ltp][36]: Linux Test Project.
* [Mailing Lists]:
  * [Lore kernel][37]: Linux kernel mailing lists.
    * [Linux hardening][38]: Linux hardening.
    * [Kernel Hardening][39]: kernel hardening.

## Rootkits

* [Awesome Linux Rootkits][2].
* [Diamorphine][3]: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and
  ARM64.
* [Pinkit][4]: LKM rootkit that executes a reverse TCP netcat shell with root
  privileges.
* [Reptile][5]: LKM Linux rootkit.
* [Research rootkit][6]: LibZeroEvil & the Research Rootkit project.
* [Rootkit][7]: rootkit for Ubuntu 16.04 and 10.04 (Linux Kernels 4.4.0 and
  2.6.32), both i386 and amd64.
* [Rootkit list download][8]: list of rootkits (includes also userspace
  rootkits).
* [Sutekh][9]: rootkit that gives a userland process root permissions.
* [TripleCross][10]: Linux eBPF rootkit.

## Rust

* [Getting started][45]: official documentation for getting started with Rust
  and Linux kernel.
* [knock-out][44]: example of a kernel module in Rust.
* [Rust for Linux][43]: organization for adding support for the Rust language
  to the Linux kernel.
* [Rust for Linux mailing list][41]: rust for Linux mailing list

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
