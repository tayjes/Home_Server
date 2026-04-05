#import modules
from fastapi import FastAPI, WebSocket
import asyncio
import scan
from pydantic import BaseModel
import netifaces
from typing import Optional
from fastapi.concurrency import run_in_threadpool
from . import camera 
#load mac address
scan.init()
# to do add this 
def get_active_iface():
    for iface in netifaces.interfaces():
        if iface=="lo":
            continue
        addrs=netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    return "eth0" #default ethernet for linux(docker image)

class Device(BaseModel):
    ip:str
    mac:str
    company:str
    ttl:int
    os:str

#tmp to store data 
last_scan:list[dict]=[{}]

#fastapi app
app = FastAPI()
#Route
@app.get("/")
def home():
    return {"status":"connected"}

@app.get("/Scanner",response_model=list[Device])
async def network(iface: str = "wlp2s0"):
    
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
        d = await run_in_threadpool(scan.arp_scan, iface)
        last_scan[0]=d

    #run camera detection on each IP from last scan
    results = []
    for device in last_scan[0]:
        cam = await run_in_threadpool(camera.detect_camera, device["ip"])
        cam["ip"] = device["ip"]
        cam["mac"] = device["mac"]
        results.append(cam)

    return results

