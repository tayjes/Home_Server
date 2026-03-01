# 🏠 Home_Server

Home_Server is an ongoing **C++ + Python hybrid project** focused on building a modular home server system from scratch.

The first implemented component is a **local network discovery engine**, written in C++ for performance and exposed to Python using pybind11.

This project is being built step-by-step toward a complete home server ecosystem.

## 🚀 Current Progress
**Step 1 Completed** ✅ **Local Network Scanner**

**Implemented:**
- ARP-based local subnet scanning (`/24`)
- MAC address extraction
- Vendor lookup using IEEE OUI database
- Python bindings via pybind11
- CMake-based build system

**The scanner identifies:**
- 🖧 IP address
- 🔑 MAC address
- 🏷 Vendor/company name

## 📁 Project Structure

Home_Server/
├── build/ # CMake build output
├── helper/
│ ├── MAC.txt # IEEE OUI vendor database
│ └── command.txt # Command reference / notes
├── main.cpp # Core C++ scanner + pybind bindings
├── main.py # Example Python usage
├── CMakeLists.txt # Build configuration
├── .gitignore
└── README.md

text

## 🧠 How It Works

1. Opens a raw socket (`AF_PACKET`)
2. Broadcasts ARP requests across local subnet
3. Collects ARP replies
4. Extracts MAC address
5. Matches first 3 bytes (OUI) against `helper/MAC.txt`
6. Returns results to Python as a list of dictionaries

## 🛠 Requirements

- Linux (raw sockets required)
- C++14+
- Python 3.12
- pybind11
- CMake ≥ 3.12

## ⚙️ Build Instructions

### 1️⃣ Setup Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install pybind11

2️⃣ Build With CMake

bash
mkdir build
cd build
cmake ..
make

This generates a file like: scan.cpython-312-x86_64-linux-gnu.so(in linux env)

Copy it into your virtual environment:

bash
cp scan*.so ../venv/lib64/python3.12/site-packages/

🐍 Usage

Activate your virtual environment:

bash
source venv/bin/activate

Run:

python
import scan
scan.init()  # Loads helper/MAC.txt
devices = scan.arp_scan("wlp2s0")  # replace with your interface

for device in devices:
    print(device)

Example output:

json
{ "ip": "192.168.1.5", "mac": "5c:22:da:3f:3b:f7", "company": "Some Vendor Name" }

⚠️ Important Notes

    Must run with root privileges: sudo python3 main.py

    Raw sockets require elevated permissions

    Only scans the local subnet

    Interface name must be correct (ip a to check)

📌 helper Directory
File	Description
MAC.txt	IEEE OUI vendor assignments used to map MAC prefixes to company names
command.txt	Development commands and notes related to the project
🔮 Roadmap

This project is currently in its foundation stage. The long-term vision is to evolve Home_Server into a complete, modular home infrastructure platform.
🌐 1. Advanced Network Scanning

    Full subnet discovery

    TCP / UDP port scanning

    Service detection (HTTP, SSH, etc.)

    OS fingerprinting (TTL, packet behavior)

    Device profiling & classification

    Real-time device monitoring

👨‍👩‍👧 2. Parental Control System

    Device-based access control

    Scheduled internet restrictions

    Website / service blocking

    Usage monitoring per device

    Activity reporting dashboard

☁️ 3. Family File Sharing System

Goals:

    Local network file sharing

    Secure remote access while traveling

    Optional cloud synchronization

    Low-bandwidth optimized transfers

    Personal drive-style interface

    Version control for important documents

Aims to reduce dependency on third-party cloud platforms while maintaining convenience.
📷 4. Smart Security & Surveillance

    Security camera integration

    Real-time motion detection

    Human detection using AI

    Entry/exit tracking logs

    Alert notifications (mobile/email)

    Visitor tracking

    Home delivery tracking & logging

📱 5. Mobile Dashboard Application

A centralized mobile control panel to:

    Monitor connected devices

    Control parental settings

    Access shared files

    View security camera feeds

    Receive alerts & notifications

    Manage automation rules

    Cross-platform (Android/iOS) planned

🏠 6. Home Automation Services

    Smart light control

    Appliance scheduling

    Energy monitoring

    Rule-based automation engine

    Integration with IoT devices

    Voice assistant compatibility (future scope)

🧩 7. Modular Plugin Architecture

To keep the system scalable:

    Plugin-based feature system

    Easy module addition/removal

    API layer for extensions

    Community-developed plugins

    Isolated service components

🤝 Contributing

This project is currently in early development. Suggestions, issues, and improvements are welcome!
📜 License

License to be added.
