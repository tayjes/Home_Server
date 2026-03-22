# 🏠 Home_Server

Home_Server is an ongoing **C++ + Python hybrid project** focused on building a modular home server system from scratch.

The first implemented component is a **local network discovery engine**, written in C++ for performance and exposed to Python using pybind11, served as a REST API via FastAPI, and fully containerized with Docker.

This project is being built step-by-step toward a complete home server ecosystem.

---

## 🚀 Current Progress

**Step 1 Completed** ✅ **Local Network Scanner**

**Implemented:**
- ARP-based local subnet scanning (`/24`)
- MAC address extraction
- Vendor lookup using IEEE OUI database
- Python bindings via pybind11
- CMake-based build system
- FastAPI REST API (`/Scanner?iface=wlp2s0`)
- Docker containerization with full build pipeline

**The scanner identifies:**
- 🖧 IP address
- 🔑 MAC address
- 🏷 Vendor/company name

---

## 📁 Project Structure

```
Home_Server/
├── build/                  # CMake build output (git ignored)
├── helper/
│   ├── MAC.txt             # IEEE OUI vendor database
│   └── command.txt         # Command reference / notes
├── .vscode/
│   ├── settings.json       # CMake + IntelliSense config
│   └── c_cpp_properties.json
├── main.cpp                # Core C++ scanner + pybind11 bindings
├── main.py                 # FastAPI app
├── CMakeLists.txt          # Build configuration
├── Dockerfile              # Container build instructions
├── .dockerignore           # Excludes build/, venv/, *.so from image
├── requirements.txt        # Python dependencies
├── .gitignore
└── README.md
```

---

## 🧠 How It Works

1. Opens a raw socket (`AF_PACKET`)
2. Queries interface info via `ioctl()` (index, MAC, IP)
3. Broadcasts ARP requests across the local `/24` subnet
4. Collects and deduplicates ARP replies
5. Extracts MAC address
6. Matches first 3 bytes (OUI) against `helper/MAC.txt`
7. Returns results to Python as a list of dictionaries
8. FastAPI serves results as JSON over HTTP

---

## 🛠 Requirements

- Linux (raw sockets required)
- C++14+
- Python 3.12
- pybind11
- CMake ≥ 3.12
- Docker (for containerized usage)

---

## ⚙️ Build Instructions (Local)

### 1️⃣ Setup Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2️⃣ Build With CMake
```bash
mkdir build && cd build
cmake ..
make
cd ..
```

### 3️⃣ Run the API
```bash
sudo ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 3000 --reload
```

---

## 🐳 Docker Usage

### Build the image
```bash
sudo docker build -t network-scanner .
```

### Run the container
```bash
sudo docker run \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e MAC_DB_PATH=/app/helper/MAC.txt \
  network-scanner
```

### Test it
```bash
curl http://localhost:3000/
curl http://localhost:3000/Scanner?iface=wlp2s0
```

> **Note:** To find your interface name inside the container run:
> ```bash
> sudo docker run --network host --rm network-scanner ip link show
> ```

### Runtime flags explained

| Flag | Why it's needed |
|------|----------------|
| `--network host` | ARP scanning needs access to the real physical network — Docker's default virtual bridge blocks raw packets |
| `--cap-add NET_RAW` | Required to open raw sockets (`AF_PACKET, SOCK_RAW`) for sending ARP frames |
| `--cap-add NET_ADMIN` | Required for `ioctl()` calls that read interface MAC address, IP, and index |
| `-e MAC_DB_PATH` | Points the scanner to the IEEE OUI database inside the container |

### Sharing the image

**Via Docker Hub:**
```bash
sudo docker login
sudo docker tag network-scanner yourusername/network-scanner:latest
sudo docker push yourusername/network-scanner:latest

# Anyone can then pull and run:
sudo docker pull yourusername/network-scanner:latest
```

**Via file (offline):**
```bash
sudo docker save -o network-scanner.tar network-scanner
gzip network-scanner.tar

# Receiver loads it with:
gunzip network-scanner.tar.gz
sudo docker load -i network-scanner.tar
```

---

## 🐍 Usage (Python / Library)

```python
import scan

scan.init()  # Loads MAC.txt (set MAC_DB_PATH env var to override path)
devices = scan.arp_scan("wlp2s0")  # replace with your interface

for device in devices:
    print(device)
```

**Example output:**
```json
{ "ip": "192.168.1.5", "mac": "5c:22:da:3f:3b:f7", "company": "Some Vendor Name" }
```

**REST API:**
```
GET /                          → { "status": "connected" }
GET /Scanner?iface=wlp2s0     → [ { "ip": "...", "mac": "...", "company": "..." }, ... ]
```

---

## ⚠️ Important Notes

- Must run with root privileges (raw sockets require elevated permissions)
- Only scans the local `/24` subnet
- Interface name must be correct — use `ip a` to check
- Inside Docker, use `--network host` or the scanner cannot reach real network devices
- `MAC_DB_PATH` env var overrides the default `helper/MAC.txt` path

---

## 📌 helper Directory

| File | Description |
|------|-------------|
| `MAC.txt` | IEEE OUI vendor assignments — maps MAC prefixes to company names |
| `command.txt` | Development commands and notes related to the project |

---

## 🔮 Roadmap

This project is currently in its foundation stage. The long-term vision is to evolve Home_Server into a complete, modular home infrastructure platform.

### 🌐 1. Advanced Network Scanning
- Full subnet discovery
- TCP / UDP port scanning
- Service detection (HTTP, SSH, etc.)
- OS fingerprinting (TTL, packet behavior)
- Device profiling & classification
- Real-time device monitoring

### 👨‍👩‍👧 2. Parental Control System
- Device-based access control
- Scheduled internet restrictions
- Website / service blocking
- Usage monitoring per device
- Activity reporting dashboard

### ☁️ 3. Family File Sharing System
- Local network file sharing
- Secure remote access while traveling
- Optional cloud synchronization
- Low-bandwidth optimized transfers
- Personal drive-style interface
- Version control for important documents

Aims to reduce dependency on third-party cloud platforms while maintaining convenience.

### 📷 4. Smart Security & Surveillance
- Security camera integration
- Real-time motion detection
- Human detection using AI
- Entry/exit tracking logs
- Alert notifications (mobile/email)
- Visitor tracking
- Home delivery tracking & logging

### 📱 5. Mobile Dashboard Application
A centralized mobile control panel to:
- Monitor connected devices
- Control parental settings
- Access shared files
- View security camera feeds
- Receive alerts & notifications
- Manage automation rules
- Cross-platform (Android/iOS) planned

### 🏠 6. Home Automation Services
- Smart light control
- Appliance scheduling
- Energy monitoring
- Rule-based automation engine
- Integration with IoT devices
- Voice assistant compatibility (future scope)

### 🧩 7. Modular Plugin Architecture
To keep the system scalable:
- Plugin-based feature system
- Easy module addition/removal
- API layer for extensions
- Community-developed plugins
- Isolated service components

---

## 🤝 Contributing

This project is currently in early development. Suggestions, issues, and improvements are welcome!

## 📜 License

License to be added.