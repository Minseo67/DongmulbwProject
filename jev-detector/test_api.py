
from unittest.mock import patch

import requests
from fastapi.testclient import TestClient

import api


client = TestClient(api.app)

# 테스트용 가짜 Jev 분석 결과
MOCK_RESULT = {
    "url": "https://example.com/",
    "risk_level": "safe",
    "confidence": 0.72,
    "probabilities": {
        "safe": 0.79,
        "caution": 0.14,
        "danger": 0.01,
        "unknown": 0.06
    },
    "phishing_suspicion": 0.15,
    "model": "jev-test",
    "cached": False
}


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "OK"

    print("서버 상태 확인: PASS")


def test_detect_success():
    with patch.object(
        api,
        "detect_url",
        return_value=MOCK_RESULT
    ) as mock_detect:

        response = client.post(
            "/detect",
            json={"url": "https://example.com/"}
        )

        assert response.status_code == 200

        data = response.json()

        assert data["status"] == "SUCCESS"
        assert data["jevAnalysis"]["risk_level"] == "safe"

        mock_detect.assert_called_once_with(
            "https://example.com/"
        )

        print("URL 분석 요청·응답: PASS")


def test_invalid_url():
    with patch.object(
        api,
        "detect_url",
        side_effect=ValueError("HTTP/HTTPS URL만 지원합니다.")
    ):
        response = client.post(
            "/detect",
            json={"url": "ftp://example.com"}
        )

        assert response.status_code == 400

        print("잘못된 URL 오류 처리: PASS")


def test_api_failure():
    with patch.object(
        api,
        "detect_url",
        side_effect=requests.exceptions.Timeout()
    ):
        response = client.post(
            "/detect",
            json={"url": "https://example.com/"}
        )

        assert response.status_code == 502

        print("Jev API 오류 처리: PASS")


if __name__ == "__main__":
    test_health()
    test_detect_success()
    test_invalid_url()
    test_api_failure()

    print("\n모든 FastAPI 테스트 통과!")
