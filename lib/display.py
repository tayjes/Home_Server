import cv2
import os
import time

os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp|timeout;10000000"

def get_rtsp_url(ip: str, username: str = "admin", password: str = "") -> str | None:
    patterns = [
        f"rtsp://{username}:{password}@{ip}:554/ch0_0.264",
        f"rtsp://{username}:{password}@{ip}:554/stream",
        f"rtsp://{username}:{password}@{ip}:554/stream1",
        f"rtsp://{username}:{password}@{ip}:554/video1",
        f"rtsp://{username}:{password}@{ip}:554/live/ch00_0",
        f"rtsp://{username}:{password}@{ip}:554/cam/realmonitor",
        f"rtsp://{username}:{password}@{ip}:554/h264Preview_01_main",
    ]
    for url in patterns:
        cap = cv2.VideoCapture(url)
        if cap.isOpened():
            ret, _ = cap.read()
            if ret:
                cap.release()
                print(f"[+] Connected: {url}")
                return url
        cap.release()
    return None


def generate_frames(rtsp_url: str):
    cap = cv2.VideoCapture(rtsp_url)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 2)
    cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 10000)

    fail_count = 0
    MAX_FAILS = 5

    while True:
        ret, frame = cap.read()

        if not ret:
            fail_count += 1
            print(f"[-] Frame fail {fail_count}/{MAX_FAILS}")
            if fail_count >= MAX_FAILS:
                print("[*] Reconnecting...")
                cap.release()
                time.sleep(2)
                cap = cv2.VideoCapture(rtsp_url)
                fail_count = 0
            continue

        fail_count = 0

        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
        yield (
            b'--frame\r\n'
            b'Content-Type: image/jpeg\r\n\r\n'
            + buffer.tobytes()
            + b'\r\n'
        )