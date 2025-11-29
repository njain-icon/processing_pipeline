from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Processing Pipeline API",
    description="API for document classification and OCR processing",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "processing_pipeline"}

@app.get("/")
async def root():
    return {"message": "Welcome to the Processing Pipeline API"}
