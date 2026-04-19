<div align="center">

<H1>FPTN</H1>
<H6>Custom VPN technology</H6>

[\[English\]](README.md)
•
[\[Русский\]](README_RU.md)


[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://github.com/batchar2/fptn/releases)
[![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)](https://github.com/batchar2/fptn/releases)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/batchar2/fptn/releases)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/batchar2/fptn/releases)
[![Build and Test](https://img.shields.io/github/actions/workflow/status/batchar2/fptn/main.yml?style=for-the-badge&logo=github-actions&logoColor=white&label=Build&labelColor=2088FF)](https://github.com/batchar2/fptn/actions/workflows/main.yml)
[![GitHub All Releases](https://img.shields.io/github/downloads/batchar2/fptn/total.svg?style=for-the-badge&logo=github&logoColor=white&label=Downloads&labelColor=181717)](https://github.com/batchar2/fptn/releases)
</div>

---

### Core Features of FPTN

FPTN is a VPN technology engineered from the ground up to provide secure, robust, and censorship-resistant connections capable of bypassing network filtering and deep packet inspection (DPI).

Project website: [https://storage.googleapis.com/fptn.org/index.html](https://storage.googleapis.com/fptn.org/index.html)

Key Technical Features:

1. **L3 Tunnel (Network Layer)**
  - **IP Packet Tunneling:** Encapsulates and transmits raw IP packets (IPv4/IPv6) over a secure tunnel to the VPN server.
  - **Split Tunneling:** Provides granular control over routing policies. Users can define rules (based on domains or IP networks) to specify which traffic is routed through the VPN tunnel; all other traffic uses the direct internet connection.
  - **Server-side NAT:** Implements Network Address Translation (NAT) on the server. Future roadmap includes support for user grouping into virtual LANs (VLANs) for peer-to-peer communication within the VPN.

2. **Traffic Obfuscation and Blocking Evasion**
  - **Resistance to active Deep Packet Inspection (DPI):** The server can identify FPTN clients during the TLS handshake by analyzing the session_id (which the FPTN client can set using a special time-based method). If the client is not recognized as an FPTN client, the server acts as a transparent proxy and returns legitimate content for the requested domain.
  - The VPN connection is masqueraded as regular HTTPS traffic (a mode for short-lived HTTPS connections is also under development).
  - Three implemented methods for bypassing blocks:
    - **SNI Spoofing:** A fake domain name is set in the TLS ClientHello packet that initiates the connection. Traffic analysis systems observe a legitimate TLS connection, while the traffic is actually routed to the VPN server.
    - **Obfuscation:** The traffic is disguised as an already established TLS session, hiding the initial TLS handshake and preventing detection by DPI systems.
    - **Reality Mode with SNI Spoofing:** The client initiates a connection to the VPN server using a spoofed Server Name Indication (SNI), receives a genuine TLS handshake response from the actual (spoofed) website, and then continues data exchange with the VPN server within the same connection.
  - The desktop client includes an integrated `SNI scanner utility`.

3. Transport Protocol
  - Uses a proprietary transport protocol based on Protocol Buffers (Protobuf) for data exchange between the client and server.
  - **Protocol-level padding:** Data packets are padded with random data to randomize traffic patterns and complicate analysis.
  - The server provides a **REST API** for client authentication and retrieving specific configuration settings.

4. **Advanced Functionality**
  - Built-in filtering of unwanted traffic (e.g., the BitTorrent protocol).
  - Per-user bandwidth and traffic control: The server employs a traffic shaper based on the **Leaky Bucket** algorithm, allowing for granular bandwidth policy configuration.
  - Support for a multi-server architecture with a single master server that stores all user data and configuration.
  - System monitoring via **Prometheus** and visualization dashboards in **Grafana**.
  - Ability for users to connect and manage their service via a **Telegram bot**.

5. **Cross-Platform Clients**
  - A cross-platform core library, **libfptn**, has been developed for use across various operating systems. It implements the FPTN network protocol, connection management, and data transmission mechanisms for the VPN tunnel.
  - **Desktop Clients**: Windows, macOS, Linux — a minimalist client focused on ease of use.
  - **Mobile Clients**: Android, iOS (under development).

6. **Simple Token-Based Configuration**
  - A **Token** is a specially generated configuration file containing all necessary settings for the system.
  - Enables connection to the VPN without manual configuration: the user simply imports the token into the client application to begin using the service.

---

### Demonstration

Download the FPTN client from the [website](http://batchar2.github.io/fptn/) or [GitHub](https://github.com/batchar2/fptn/releases). After downloading, install and launch the client.

The client is a compact application whose icon resides in the system tray.

Simply click the icon to open the context menu.

<img style="max-height: 100px" class="img-center" src="docs/images/macos/en/client.png" alt="Application"/>

Navigate to the "Settings" menu, where you need to add an access token.
Obtain a token by contacting our <a target="_blank" href="https://t.me/fptn_bot">Telegram bot</a>,

<img style="max-height: 200px" class="img-center" src="docs/images/telegram_token_en.png" alt="Settings"/>

Copy the token, click the "Add Token" button, paste it into the form, and save.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/settings-2.png" alt="Settings"/>

After this, available servers will appear in the list.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/settings-3.png" alt="Settings"/>

Ease of use:

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/running-client.png" alt="Settings"/>

You can also easily turn your Raspberry Pi or Orange Pi into a WiFi access point and install the FPTN client on it.
In this case, all devices connected to this WiFi network will be able to access the internet, bypassing any restrictions.
[Read more here](https://github.com/batchar2/fptn/blob/master/deploy/linux/wifi/README.md)

<img style="max-height: 350px" class="img-center" src="docs/images/orangepi.jpg" alt="Settings"/>

---

### Installation, Building, and Configuration


<details>
  <summary><strong>Installing and Configuring the FPTN Server</strong></summary>

Setting up and running your own FPTN server is done via Docker.
This ensures easy deployment, convenient updates, and environment isolation.
Instructions are available on [DockerHub](https://hub.docker.com/r/fptnvpn/fptn-vpn-server).

You can also deploy your own management and monitoring tools:
- **Telegram bot** – issuing tokens to users [sysadmin-tools/telegram-bot/README.md](sysadmin-tools/telegram-bot/README.md).
- **Grafana + Prometheus** – monitoring server and user status [sysadmin-tools/grafana/README.md](sysadmin-tools/grafana/README.md)

</details>







<details>
  <summary>Building the Project from Source</summary>

1. Install required dependencies
- For [Windows](deploy/windows/README.md)
- For [Ubuntu](deploy/linux/deb/README.md)
- For [macOS](deploy/macos/README.md)

2. Install Conan (version 2.24.0):

```bash
pip install conan==2.24.0
```

3. Detect and configure the Conan profile:

```bash
conan profile detect --force
```

4. Install dependencies, build, and install:

*(For debugging and development purposes, use Debug instead of Release.)*

```bash
conan install . --output-folder=build --build=missing  -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug

cd build

# Linux & macOS only
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug
# Windows only
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Debug

cmake --build . --config Debug
ctest
```

5. Building the Installer

*(For debugging and development purposes, use Debug instead of Release.)*

- Windows

  ```bash
  cmake --build . --config Release --target build-installer
  ```

- Ubuntu

  ```bash
  cmake --build . --config Release --target build-deb-gui
  ```
  
- macOS

  ```bash
  cmake --build . --target build-pkg
  ```

</details>








<details>

<summary>Using CLion IDE for Development</summary>

Run the following command in the project's root folder:

```bash
conan install . --output-folder=cmake-build-debug --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug
```

Open the project in CLion. After opening, the Open Project Wizard window will appear automatically. In it, you need to add the following CMake parameter:

```bash
-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
```

</details>

---

### About the Project

FPTN is developed by a team of volunteers and independent developers.

If you wish to support the project, you can donate via [Boosty](https://boosty.to/fptn). Project sponsors have speed limits removed on our servers and (optionally) have their usernames published in FPTN clients.

Our Telegram chat for users and developers: [FPTN Project](https://t.me/fptn_project)

Join the community and the development team!

---

## Community Tools

The following tools are built and maintained by the community to extend or simplify working with FPTN.

### fptn-manager

A small external management tool built around FPTN, focused on simplifying deployment and common day-to-day administrative tasks.

It is especially useful for users who prefer not to work directly with Docker commands or internal configuration details.

It provides:
- A Docker-based installer
- An interactive CLI for user, password, and token management
- Easier initial setup and repeated operations

Project repository:  
https://github.com/FarazFe/fptn-manager
