
from main import save_result_csv

# 이전 Jev API 응답을 재현한 테스트 데이터
test_result = {
    "code": 0,
    "message": "ok",
    "data": {
        "model": "jev-1.14.0",
        "answers": {
            "risk_level": {
                "type": "choice",
                "choice": "safe",
                "probabilities": {
                    "safe": 0.79,
                    "caution": 0.14,
                    "danger": 0.01,
                    "unknown": 0.06
                },
                "confidence": 0.72
            },
            "phishing_suspicion": {
                "type": "noul",
                "noul": 0.15
            }
        },
        "credits": {
            "charged": 1,
            "remaining": 21
        },
        "latency_ms": 1843
    }
}

test_url = "https://example.com/login?id=123#top"

# API 호출 없이 CSV 저장 함수만 실행
save_result_csv(test_url, test_result)

print("로컬 CSV 저장 테스트 완료")
