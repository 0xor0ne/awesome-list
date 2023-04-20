# Red Teaming, Adversary Simulation and Offensive Security

Collection of resources related to offensive security (red teaming and adversary
simulation) with a focus on Linux environments.

# Content

* [Backdoors](#backdoors)
* [C2 Frameworks](#c2-frameworks)
* [Libraries](#libraries)
* [Malwares](#malwares)
* [Misc](#misc)
* [Networking](#networking)
* [Resources](#resources)
* [Rootkits](#rootkits)
* [Tools](#tools)

## Backdoors

* [BDF][5]: The Backdoor Factory.
* [ReCmd][97]: Remote Command executor
* [Tiny Shell][96]: An open-source UNIX backdoor

## C2 Frameworks

* [C2 matrix][38]: C2 frameworks comparison.
  * [Spreadsheet][40]
* [Emp3r0r][41]: Linux/Windows post-exploitation framework made by linux
  user.
* [empire][39]: PowerShell and Python 3.x post-exploitation framework.
* [Heroinn][15]: Rust cross platform C2/post-exploitation framework.
* [Link][20]: command and control framework written in rust.
* [pupy][42]: cross-platform remote administration and post-exploitation
  tool.
* [sliver][43]: Adversary Emulation Framework.
* [pwncat][44]: reverse and bind shell handler.
* [Stitch][45]: python Remote Administration Tool.
* [TheFatRat][46]: generate backdoor and easy tool to post exploitation
  attack.
* [veil][47]: generate metasploit payloads that bypass common anti-virus
  solutions.

## Libraries

* [ColdFire][10]: malware development library.
* [Houdini][16]: rust library that allows you to delete your executable while
  it's running.
* [Impacket][17]: collection of Python classes for working with network
  protocols.
* [Intruducer][18]: Rust crate to load a shared library into a Linux process
  without using ptrace.

## Malwares

* [Linux Malware][53]: tracking interesting Linux (and UNIX) malware.
  * [ATT&CK mapping][54]: linux malware to ATTACK.
  * [elfloader][55]: architecture-agnostic ELF file flattener for shellcode.
* Dumpers:
  * [pamspy][56]: Credentials Dumper for Linux using eBPF.
* Log Cleaners:
  * [Moonwalk][57]: Cover your tracks during Linux Exploitation by leaving zero
    traces on system logs and filesystem timestamps.
* [Malware Source Code][58]: collection of malware source code for a variety of
  platforms.
* Obfuscation:
  * [Bashfuscator][59]: configurable and extendable Bash obfuscation framework.
* Packers:
  * [oxide][60]: PoC packer written in Rust.
  * [UPX][61]: free, portable, extendable, high-performance executable packer.
* [Pafish][62]: testing tool that uses different techniques to detect virtual
  machines and malware analysis environments.

## Misc

* [antiscan][111]: scan service similar to virustotal
* [kasld][112]: collection of various techniques to infer the Linux kernel base
  virtual address as an unprivileged local user.

## Networking

* File Transfer:
  * [croc][63]: easily and securely send things from one computer to another.
  * [pcp][64]: peer-to-peer data transfer tool based on libp2p.
* Proxies:
  * [frp][65]: fast reverse proxy.
  * [leaf][66]: versatile and efficient proxy framework.
  * [mitmproxy][67]: interactive HTTPS proxy.
  * [ngrok][68]: introspected tunnels to localhost.
  * [Proxiechain][69]: a tool that forces any TCP connection made by any given
    application to follow through proxies.
  * [rathole][70]: lightweight and high-performance reverse proxy for NAT
    traversal, written in Rust.
  * [Shadowsocks][71]: fast tunnel proxy that helps you bypass firewalls.
  * [socat][72]: relay for bidirectional data transfer.
* Remote/Reverse Shells:
  * [GTRS][73]: Google Translator Reverse Shell.
  * [hershell][74]: multiplatform reverse shell generator.
  * [icmpsh][75]: reverse ICMP shell.
  * [Platypus][76]: modern multiple reverse shell sessions manager written in
    go.
  * [rpty][77]: tricking shells into interactive mode when local PTY's are not
    available.
  * [rsg][78]: tool to generate various ways to do a reverse shell.
  * [rtty][79]: access your terminal from anywhere via the web.
  * [rustcat][80]: modern Port listener and Reverse shell.
  * [tunshell][81]: remote shell into ephemeral environments.
  * [wash][82]: a cloud-native shell for bringing remote infrastructure to your
    terminal.
* Tunnelling:
  * [bore][83]: simple CLI tool for making tunnels to localhost.
  * [chisel][84]: fast TCP/UDP tunnel over HTTP.
  * [clash][85]: rule-based tunnel in Go.
  * [dog-tunnel][86]: p2p tunnel.
    * [kcp][87]: a Fast and Reliable ARQ Protocol.
  * [gost][88]: a simple tunnel written in golang.
  * [gsocket][89]: connect like there is no firewall. Securely.
  * [icmptunnel][90]: tunnel your IP traffic through ICMP echo and reply
    packets.
  * [iodine][91]:  tunnel IPv4 data through a DNS server.
  * [pingtunnel][92]: tool that send TCP/UDP traffic over ICMP.
  * [ssf][93]: Secure Socket Funneling.
  * [Stowaway][94]: Multi-hop Proxy Tool for pentesters.
  * [udp2raw][95]: tunnel which Turns UDP Traffic into Encrypted
    UDP/FakeTCP/ICMP Traffic.

## Resources

* [ATT&CK][4]: knowledge base of adversary tactics and techniques.
* [GTFOBins][12]: curated list of Unix binaries that can be used to bypass
  local security restrictions.
* [HackTricks][13]: hacking trick/technique/whatever
* [Linode Red Teaming Series][1]
* [LOLBAS][22]: Living Off The Land Binaries, Scripts and Libraries.
* [Offensive Security][26]: Tools & Interesting Things for RedTeam Ops.
* [PayloadAllTheThings][27]: list of useful payloads and bypass for Web
  Application Security and Pentest/CTF.
* [PayloadBox][28]: list of attack payloads.
* [Red Teaming][3]: List of Awesome Red Teaming Resources.
* [Red team cheatsheet][2]: Red Team Cheatsheet in constant expansion.
* [Red Team Infrastructure][31]: Red Team infrastructure hardening resources.
* [RedTeam-Tools][32]: Tools and Techniques for Red Team
* [Red Teaming Toolkit][33]: cutting-edge open-source security tools (OST) for
  a red teamer and threat hunter.
* [RedTeaming-TT][34]: Red Teaming Tactics and Techniques
* [SecList][35]: collection of multiple types of lists used during security
  assessments.
* Standards:
  * [NIST][48]:  Framework for Improving Critical Infrastructure Cybersecurity.
  * [OSSTMM][49]: Open Source Security Testing Methodology Manual.
  * [PTES][50]: Penetration Testing Methodologies and Standards.
  * [TIBER][51]: Threat Intelligence-Based Ethical Red Teaming Framework.
  * [STG][52]: OWASP testing methodologies.

## Rootkits

* Kernel
  * [Awesome Linux Rootkits][101].
  * [Diamorphine][102]: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and
    ARM64.
  * [Pinkit][103]: LKM rootkit that executes a reverse TCP netcat shell with root
    privileges.
  * [Reptile][104]: LKM Linux rootkit.
  * [Research rootkit][105]: LibZeroEvil & the Research Rootkit project.
  * [Rootkit][106]: rootkit for Ubuntu 16.04 and 10.04 (Linux Kernels 4.4.0 and
    2.6.32), both i386 and amd64.
  * [Rootkit list download][107]: list of rootkits (includes also userspace
    rootkits).
  * [Sutekh][108]: rootkit that gives a userland process root permissions.
  * [TripleCross][109]: Linux eBPF rootkit.
* Resources
  * [xcellerator][110]: Linux kernel rootkit series

## Tools

* [airgeddon][7]: multi-use bash script for Linux systems to audit wireless
  networks.
* [Beshark][6]: Bash post exploitation toolkit.
* [Bettercap][8]: networks reconnaissance and MITM attacks.
* [BloodHound][9]: Six Degrees of Domain Admin.
* [CrackMapExec][11]: evaluates and exploits vulnerabilities in an active
  directory environment.
* [HashCat][14]: password recovery utility.
* [LaZagne][19]: retrieve passowrds.
* [Linux Exploit Suggester][21]: Linux privilege escalation auditing tool.
* [Metasploit Framework][23]: penetration testing framework.
  * [Venom][24]: metasploit Shellcode generator/compiller.
* [NoseyParker][25]: command-line program that finds secrets and sensitive
  information in textual data and Git history.
* [PEASS-ng][29]: Privilege Escalation Awesome Scripts SUITE.
* [pixload][30]: set of tools for creating/injecting payload into images.
* [Sherlock][36]: hunt down social media accounts by username across social
  networks.
* SSH weaponization:
  * [reverse-ssh][99]: Statically-linked ssh server with reverse shell
  * [reverse_ssh][100]: SSH based reverse shell.
  * [sshimpanzee][98]: static reverse ssh server
    functionality.
* [traitor][37]: automatic Linux privesc via exploitation of low-hanging fruit.


[1]: https://www.linode.com/docs/guides/hackersploit-red-team-series/
[2]: https://github.com/RistBS/Awesome-RedTeam-Cheatsheet
[3]: https://github.com/yeyintminthuhtut/Awesome-Red-Teaming
[4]: https://attack.mitre.org/
[5]: https://github.com/secretsquirrel/the-backdoor-factory
[6]: https://github.com/redcode-labs/Bashark
[7]: https://github.com/v1s1t0r1sh3r3/airgeddon
[8]: https://github.com/bettercap/bettercap
[9]: https://github.com/BloodHoundAD/BloodHound
[10]: https://github.com/redcode-labs/Coldfire
[11]: https://github.com/Porchetta-Industries/CrackMapExec
[12]: https://gtfobins.github.io/
[13]: https://book.hacktricks.xyz/welcome/readme
[14]: https://github.com/hashcat/hashcat
[15]: https://github.com/b23r0/Heroinn
[16]: https://github.com/yamakadi/houdini
[17]: https://github.com/fortra/impacket
[18]: https://github.com/vfsfitvnm/intruducer
[19]: https://github.com/AlessandroZ/LaZagne
[20]: https://github.com/postrequest/link
[21]: https://github.com/mzet-/linux-exploit-suggester
[22]: https://lolbas-project.github.io/
[23]: https://github.com/rapid7/metasploit-framework
[24]: https://github.com/r00t-3xp10it/venom
[25]: https://github.com/praetorian-inc/noseyparker
[26]: https://github.com/bigb0sss/RedTeam-OffensiveSecurity
[27]: https://github.com/swisskyrepo/PayloadsAllTheThings
[28]: https://github.com/payloadbox/
[29]: https://github.com/carlospolop/PEASS-ng
[30]: https://github.com/chinarulezzz/pixload
[31]: https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki
[32]: https://github.com/A-poc/RedTeam-Tools
[33]: https://github.com/infosecn1nja/Red-Teaming-Toolkit
[34]: https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques
[35]: https://github.com/danielmiessler/SecLists
[36]: https://github.com/sherlock-project/sherlock
[37]: https://github.com/liamg/traitor
[38]: https://www.thec2matrix.com/
[39]: https://github.com/BC-SECURITY/Empire
[40]: https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit#gid=0
[41]: https://github.com/jm33-m0/emp3r0r
[42]: https://github.com/n1nj4sec/pupy
[43]: https://github.com/BishopFox/sliver
[44]: https://github.com/calebstewart/pwncat
[45]: https://github.com/nathanlopez/Stitch
[46]: https://github.com/screetsec/TheFatRat
[47]: https://github.com/Veil-Framework/Veil
[48]: https://www.nist.gov/news-events/news/2018/04/nist-releases-version-11-its-popular-cybersecurity-framework
[49]: https://www.isecom.org/research.html#content5-9d
[50]: http://www.pentest-standard.org/index.php/Main_Page
[51]: https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html
[52]: https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies
[53]: https://github.com/timb-machine/linux-malware
[54]: https://gist.github.com/timb-machine/05043edd6e3f71569f0e6d2fe99f5e8c
[55]: https://github.com/gamozolabs/elfloader
[56]: https://github.com/citronneur/pamspy
[57]: https://github.com/mufeedvh/moonwalk
[58]: https://github.com/vxunderground/MalwareSourceCode
[59]: https://github.com/Bashfuscator/Bashfuscator
[60]: https://github.com/frank2/oxide
[61]: https://upx.github.io/
[62]: https://github.com/a0rtega/pafish
[63]: https://github.com/schollz/croc
[64]: https://github.com/dennis-tra/pcp
[65]: https://github.com/fatedier/frp
[66]: https://github.com/eycorsican/leaf
[67]: https://mitmproxy.org/
[68]: https://github.com/inconshreveable/ngrok
[69]: https://github.com/haad/proxychains
[70]: https://github.com/rapiz1/rathole
[71]: https://github.com/shadowsocks/shadowsocks-rust
[72]: https://repo.or.cz/socat.git
[73]: https://github.com/mthbernardes/GTRS
[74]: https://github.com/lesnuages/hershell
[75]: https://github.com/bdamele/icmpsh
[76]: https://github.com/WangYihang/Platypus
[77]: https://github.com/TimeToogo/remote-pty
[78]: https://github.com/mthbernardes/rsg
[79]: https://www.graplsecurity.com/blog
[80]: https://github.com/robiot/rustcat
[81]: https://github.com/TimeToogo/tunshell
[82]: https://github.com/puppetlabs/wash
[83]: https://github.com/ekzhang/bore
[84]: https://github.com/jpillora/chisel
[85]: https://github.com/Dreamacro/clash
[86]: https://github.com/vzex/dog-tunnel
[87]: https://github.com/skywind3000/kcp
[88]: https://github.com/ginuerzh/gost
[89]: https://github.com/hackerschoice/gsocket
[90]: https://github.com/DhavalKapil/icmptunnel
[91]: https://github.com/yarrick/iodine
[92]: https://github.com/esrrhs/pingtunnel
[93]: https://github.com/securesocketfunneling/ssf
[94]: https://github.com/ph4ntonn/Stowaway
[95]: https://github.com/wangyu-/udp2raw
[96]: https://github.com/creaktive/tsh
[97]: https://github.com/0xor0ne/recmd
[98]: https://github.com/lexfo/sshimpanzee
[99]: https://github.com/Fahrj/reverse-ssh
[100]: https://github.com/NHAS/reverse_ssh
[101]: https://github.com/milabs/awesome-linux-rootkits
[102]: https://github.com/m0nad/Diamorphine
[103]: https://github.com/PinkP4nther/Pinkit
[104]: https://github.com/f0rb1dd3n/Reptile
[105]: https://github.com/NoviceLive/research-rootkit
[106]: https://github.com/nurupo/rootkit
[107]: https://github.com/d30sa1/RootKits-List-Download
[108]: https://github.com/PinkP4nther/Sutekh
[109]: https://github.com/h3xduck/TripleCross
[110]: https://xcellerator.github.io/tags/rootkit/
[111]: https://antiscan.me
[112]: https://github.com/bcoles/kasld
