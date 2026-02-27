from fastapi import FastAPI
from brain import Model
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
model = Model()


class ScanRequest(BaseModel):
   code_text: str


@app.post("/scan")
async def scan_code(request: ScanRequest):
   report = model.scan(request.code_text)
   return {"report": report}

