from scapy.all import IP, TCP, sr1, conf
import socket

conf.verb = 0

CAMERA_PORTS = [554, 80, 8080, 8554, 443, 37777, 34567]

CAMERA_KEYWORDS = [
    "ipcamera", "hikvision", "dahua", "axis",
    "foscam", "netcam", "webcam", "camera",
    "dvr", "nvr", "rtsp","nginx"
]

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        return False
    if resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:
            rst = IP(dst=ip) / TCP(dport=port, flags="R")
            sr1(rst, timeout=0.5)
            return True
    return False

def grab_http_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()
        return banner
    except Exception:
        return ""

def detect_camera(ip: str) -> dict:
    result = {
        "rtsp_open": False,
        "http_open": False,
        "banner": "",
        "is_camera": False,
        "camera_type": ""
    }

    result["rtsp_open"] = is_port_open(ip, 554)

    http_port = None
    if is_port_open(ip, 80):
        result["http_open"] = True
        http_port = 80
    elif is_port_open(ip, 8080):
        result["http_open"] = True
        http_port = 8080

    if http_port:
        result["banner"] = grab_http_banner(ip, http_port)

    lower_banner = result["banner"].lower()

    for keyword in CAMERA_KEYWORDS:
        if keyword in lower_banner:
            result["is_camera"] = True
            result["camera_type"] = f"IP Camera ({keyword})"
            return result

    if result["rtsp_open"]:
        result["is_camera"] = True
        result["camera_type"] = "IP Camera / Media Device (RTSP)"

    return result