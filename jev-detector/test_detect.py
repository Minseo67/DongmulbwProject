
import os
import tempfile
from unittest.mock import patch

import main


TEST_URL = "https://example.com/login"


# 실제 API 대신 사용할 테스트 응답
def mock_response():
    return {
        "code": 0,
        "message": "ok",
        "data": {
            "model": "jev-test",
            "answers": {
                "risk_level": {
                    "choice": "safe",
                    "confidence": 0.72,
                    "probabilities": {
                        "safe": 0.79,
                        "caution": 0.14,
                        "danger": 0.01,
                        "unknown": 0.06
                    }
                },
                "phishing_suspicion": {
                    "noul": 0.15
                }
            },
            "credits": {
                "charged": 0,
                "remaining": 0
            },
            "latency_ms": 0
        }
    }


def test_detect():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_csv = os.path.join(
            temp_dir,
            "test_results.csv"
        )

        # 실제 CSV 대신 임시 CSV 사용
        with patch.object(main, "CSV_FILE", test_csv):

            # 실제 API 함수는 호출되지 않도록 대체
            with patch.object(
                main,
                "analyze_url",
                return_value=mock_response()
            ) as mock_api:

                # 테스트 1: 신규 URL
                first = main.detect_url(TEST_URL)

                assert first["cached"] is False
                assert first["risk_level"] == "safe"
                assert mock_api.call_count == 1

                print("신규 URL 자동 분석: PASS")

                # 테스트 2: 동일 URL 재분석
                second = main.detect_url(TEST_URL)

                assert second["cached"] is True
                assert second["risk_level"] == "safe"
                assert mock_api.call_count == 1

                print("72시간 이내 캐시 재사용: PASS")

                # 테스트 3: 반환 형식 확인
                assert first["probabilities"]["safe"] == 0.79
                assert second["probabilities"]["safe"] == 0.79

                print("분석 결과 형식 통일: PASS")

                # 테스트 4: 잘못된 URL 차단
                try:
                    main.detect_url("ftp://example.com")
                    raise AssertionError("잘못된 URL이 허용됨")
                except ValueError:
                    pass

                assert mock_api.call_count == 1
                print("잘못된 URL 차단: PASS")

    print("\n모든 detect_url 테스트 통과!")


if __name__ == "__main__":
    test_detect()
