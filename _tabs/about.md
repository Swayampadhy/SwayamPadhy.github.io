---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

I am an undergraduate student at **Manipal Institute of Technology**, majoring in **Computer Science and Engineering** with a minor in **Digital Marketing**. My passion lies in **malware research**, **exploit development**, and **red teaming**. As an **OSCP** and **CRTO** professional, I actively engage in vulnerability assessments, malware research, and cybersecurity projects.

## 🏆 Certifications
<table>
            <tr>
                <td><img src="https://api.eu.badgr.io/public/assertions/sVLbxYtxS3-q3TOiSmF1sA/image" alt="Red Team Operator Badge" width="120" height="120"></td>
                <td><img src="https://user-images.githubusercontent.com/37104162/259928338-85e4ba85-02c1-4486-9135-0366072d5657.png" width="120" height="120"></td>
                <td><img src="https://user-images.githubusercontent.com/37104162/259928418-1445a5ef-f522-4dd7-9209-194448a14259.png" width="120" height="120"></td>
                <td><img src="https://github-production-user-asset-6210df.s3.amazonaws.com/37104162/259929332-42e90c03-187d-4ab0-8774-7896175acfb8.png" width="120" height="120"></td>
            </tr>
</table>

## 🔥 Technical Skills

- **Languages:** C, C++, Python, C#, Bash, Powershell, x86\_64 Assembly, SQL, Java, Go, Rust
- **Networking:** DNS management, Routing, Switching, TCP/IP, NAT, IPv4 and IPv6 addressing and subnetting, VLANs, trunking, and inter-VLAN routing, Wireshark, Terraform
- **Pentesting:** Malware Development, Exploit Development, Network Penetration Testing, Active Directory Attacks, Secure Coding, Webapp Exploitation
- **System Administration:** Linux, Windows, Active Directory

## 💼 Experience

### Security Engineer Intern @ Bugbase (April 2024 - July 2024)

- Developed Active Directory internal assessment modules for RedTeam Copilot, enhancing the tool’s capability to simulate real-world attack scenarios
- Created custom scripts for enumeration and exploitation in Sliver C2 using Sliverpy.
- Automated deployment of expendable payloads, C2 redirectors, and SMTP relays using Terraform.
- Contributed to the design and development of a custom C2 framework with AI-based agents.
- Integrated netexec tool into the copilot agent for automated deployment when run on a target system.

### Intern @ Breach Point (ISAC) (Oct 2023 - Jan 2024)

- Conducted VAPT assessments on Government of India infrastructure.
- Performed vulnerability scans for critical industrial sectors such as aviation, power, and finance.
- Documented and responsibly disclosed proof-of-concept exploits for discovered vulnerabilities.
- Promoted to team leader after two months, managing a team of interns and coordinating vulnerability assessments.

## 🎤 Conference Presentations

### 🎙️ The Threat Triplet: RATs, Keyloggers, and Registry Keys

**Presented at HINT-24 (Springer Lecture Notes in Networks and Systems - LNNS)**

- Demonstrated how **RATs, keyloggers, and registry keys** work together to **compromise systems**.
- Explored **persistence techniques** used in **modern malware**.
- Provided **detection and mitigation strategies** to counter these threats.

## 🏗 Notable Projects

### 🔐 [CurveLock](https://github.com/Swayampadhy/CurveLock) (Jan 2025)

- Developed a ransomware prototype leveraging Elliptic Curve Cryptography (ECC) to encrypt files with high efficiency.
- Implemented advanced anti-analysis techniques such as API hammering and compile-time Import Address Table (IAT) randomization for enhanced evasion.
- Utilized process hollowing by leveraging clean ntdll.dll copies from suspended processes to bypass security hooks.
- Embedded mechanisms for escalating privileges dynamically, including token manipulation and abuse of high-privileged processes, to extend ransomware capabilities.
- Incorporated DcSync attack capabilities to dump all username-NTLM hash combinations in an Active Directory network.

### 🛠 [ShadowChain](https://github.com/Swayampadhy/ShadowChain) (Dec 2024)

- ShadowChain is designed as a modular DLL injector, allowing flexibility in injecting DLLs into target processes.
- Implements DRM features to protect the payloads and their functionality, ensuring controlled distribution and execution.
- Utilizes Thread Local Storage (TLS) callbacks for anti-debugging mechanisms and makes it difficult for reverse engineers and debuggers to analyze the injector.
- ShadowChain utilizes the Windows Startup folder as a persistence mechanism by creating a copy of the injector at runtime into the startup folder which the system automatically executes whenever the user logs into Windows.
- Supports a wide range of payloads, making the tool adaptable to various use cases while maintaining a high level of security and obfuscation.

### 🕵️‍♂️ [CryoLeak](https://github.com/Swayampadhy/CryoLeak) (Nov 2023)

- CryoLeak utilizes a C#-based server-grunt C2 model for managing multiple implants remotely to control systems remotely.
- The system uses a RESTful API over HTTP for secure command issuance and result retrieval from its implants, ensuring operations are stealthy and secure.
- Supports a broad array of commands for extensive remote system management, including file operations, system queries, and advanced control functions.
- Built the Team Server using ASP.NET Core for scalability and security.

### 💻 [BlueNovember](https://github.com/Swayampadhy/BlueNovember) (Aug 2023)

- BlueNovember is designed as an offensive driver with capabilities to bypass kernel-level security measures including antivirus defenses and built-in Windows protection mechanisms like Kernel Patch Protection (KPP) and callbacks.
- The driver is capable of modifying process protections and privileges, enabling actions that typically require higher permissions such as changing process tokens and disabling kernel callbacks.
- It includes techniques to evade Microsoft’s PatchGuard that protects kernel integrity, by exploiting race conditions and operational gaps in its monitoring processes.
- Developed a handler using C++ with WinAPI wrappers to execute commands and manage the driver’s operations.

## 📚 Research

- **Exploring Elliptic Curves Implementation in Modern Ransomware** *(In Review - International Journal Of Information Security )*
- **Evading Security Analysis Using Digital Rights Management** *(Final Draft - IEEE Access)*
- **Detection and Mitigation of Cyber Attacks in IoT** *(In Review - Cogent Engineering)*
- **The Threat Triplet: RATs, Keyloggers, and Registry Keys** *(Published - Springer LNNS)*


