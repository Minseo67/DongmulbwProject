
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import requests

from main import detect_url


# FastAPI 서버 생성
app = FastAPI(
    title="Jev URL Detector API",
    description="Jev 기반 URL 위험 분석 API",
    version="1.0.0"
)


# URL 분석 요청 형식
class URLRequest(BaseModel):
    url: str = Field(min_length=1)


# 서버 상태 확인
@app.get("/health")
def health_check():
    return {
        "status": "OK",
        "service": "jev-detector"
    }


# URL 분석 API
@app.post("/detect")
def detect(request: URLRequest):
    try:
        result = detect_url(request.url)

        return {
            "status": "SUCCESS",
            "jevAnalysis": result
        }

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except requests.exceptions.RequestException:
        raise HTTPException(
            status_code=502,
            detail="Jev API 요청에 실패했습니다."
        )

    except (KeyError, TypeError):
        raise HTTPException(
            status_code=502,
            detail="Jev API 응답 형식이 올바르지 않습니다."
        )
