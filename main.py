from fastapi import FastAPI, WebSocket
import asyncio
import scan
from pydantic import BaseModel
from fastapi.concurrency import run_in_threadpool
app = FastAPI()
history=[]
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    print("Client connected")

    try:
        while True:
            data = await run_in_threadpool(ws.receive_text,)
            print("From Flutter:", data)
            history.append(data)

            await ws.send_text(f"Echo: {data}")
    except Exception:
        print("Client disconnected")
@app.get("/")
def home():
    return {"status":"connected"}
@app.get("/Scanner")
async def network():
    devices = await run_in_threadpool(scan.arp_scan, "wlp2s0")
    return devices