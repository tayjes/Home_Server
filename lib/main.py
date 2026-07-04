#import modules
from fastapi import FastAPI, WebSocket
import asyncio
from fastapi.responses import HTMLResponse, StreamingResponse
import scan
from pydantic import BaseModel
import netifaces
from typing import Optional
from fastapi.concurrency import run_in_threadpool
from . import camera ,display

#load mac address
scan.init()

# to do add this 
def get_active_iface():
    for iface in netifaces.interfaces():
        if iface=="lo":
            continue
        addrs=netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            print(f"Active interface found: {iface}")
            return iface
    print("No active interface found, defaulting to eth0")
    return "eth0" #default ethernet for linux(docker image)

class Device(BaseModel):
    ip:str
    mac:str
    company:str
    ttl:int
    os:str

#tmp to store data 
last_scan:list[dict]=[{}]
camera_results:list[dict]=[{}]
#fastapi app

app = FastAPI()
#Route
@app.get("/")
def home():
    return {"status":"connected"}

@app.get("/Scanner",response_model=list[Device])
async def network(iface: str = ""):
    if not iface:
        iface = get_active_iface()
    
    d = await run_in_threadpool(scan.arp_scan, iface)
    last_scan[0]=d
    return d


@app.get("/Ip_camera_search")
async def ipcamera(iface: str = ""):        
    #if no iface passed, auto detect
    if not iface:
        iface = get_active_iface()

    #if last_scan is empty, run a fresh scan first
    if last_scan[0]=={}:
        print("Running initial scan...")                       
        d = await run_in_threadpool(scan.arp_scan, iface)
        last_scan[0]=d

    #run camera detection on each IP from last scan
    results = []
    for device in last_scan[0]:
        cam = await run_in_threadpool(camera.detect_camera, device["ip"])
        if cam["is_camera"]:
            cam["ip"] = device["ip"]
            cam["mac"] = device["mac"]
            results.append(cam)

    camera_results[0] = results
    return results

@app.get("/Camera_stream/{ip}")
async def camera_stream(
    ip: str,
    username: Optional[str] = "admin",
    password: Optional[str] = ""
):
    if camera_results[0] == {}:
        return {"error": "No camera results. Run /Ip_camera_search first."}

    cam_info = next((c for c in camera_results[0] if c["ip"] == ip), None)
    if not cam_info:
        return {"error": f"No camera found with IP {ip}"}

    rtsp_url = await run_in_threadpool(display.get_rtsp_url, ip, username, password)

    if rtsp_url is None:
        return {"error": f"Cannot connect to RTSP stream at {ip}"}

    return StreamingResponse(
        display.generate_frames(rtsp_url),
        media_type="multipart/x-mixed-replace; boundary=frame"
    )

@app.get("/Camera_view/{ip}", response_class=HTMLResponse)
async def camera_view(
    ip: str,
    username: Optional[str] = "admin",
    password: Optional[str] = ""
):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Camera {ip}</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background: #111; display: flex; flex-direction: column;
                    align-items: center; padding: 20px; font-family: sans-serif; }}
            h2 {{ color: #aaa; font-weight: 400; margin-bottom: 16px; }}
            img {{ width: 100%; max-width: 1280px; border-radius: 8px; background: #000; }}
        </style>
    </head>
    <body>
        <h2>Camera — {ip}</h2>
        <img src="/Camera_stream/{ip}?username={username}&password={password}"/>
    </body>
    </html>
    """ 

