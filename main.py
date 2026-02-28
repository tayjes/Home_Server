#import modules
from fastapi import FastAPI, WebSocket
import asyncio
import scan
from pydantic import BaseModel
from fastapi.concurrency import run_in_threadpool

#fastapi app
app = FastAPI()

#load mac address
scan.init()

#Route
@app.get("/")
def home():
    return {"status":"connected"}
@app.get("/Scanner")
async def network():
    devices = await run_in_threadpool(scan.arp_scan, "wlp2s0")
    return devices