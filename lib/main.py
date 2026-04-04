#import modules
from fastapi import FastAPI, WebSocket
import asyncio
import scan
from pydantic import BaseModel
from typing import Optional
from fastapi.concurrency import run_in_threadpool 
#load mac address
scan.init()

#fastapi app
app = FastAPI()

#Route
@app.get("/")
def home():
    return {"status":"connected"}
@app.get("/Scanner")
async def network(iface: str = "eth0"):
    devices = await run_in_threadpool(scan.arp_scan, iface)
    return devices
