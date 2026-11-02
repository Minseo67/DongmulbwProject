
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="Jev Mock API")


class URLRequest(BaseModel):
    url: str = Field(min_length=1)


@app.get("/health")
def health():
    return {
        "status": "OK",
        "service": "jev-mock"
    }


@app.post("/detect")
def detect(request: URLRequest):
    print(f"[MOCK] 받은 원본 URL: {request.url}", flush=True)

    return {
        "status": "SUCCESS",
        "jevAnalysis": {
            "url": request.url,
            "risk_level": "safe",
            "confidence": 0.72,
            "probabilities": {
                "safe": 0.79,
                "caution": 0.14,
                "danger": 0.01,
                "unknown": 0.06
            },
            "phishing_suspicion": 0.15,
            "model": "jev-mock",
            "cached": False
        }
    }
