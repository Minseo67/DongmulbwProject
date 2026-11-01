
import csv
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import main


TEST_URL = "https://example.com/login"


# 실제 Jev API를 대신하는 가짜 응답
def mock_jev_response():
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


# 임시 CSV에 분석 기록 생성
def create_test_csv(file_path, hours_ago):
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(hours=hours_ago)
    ).isoformat()

    row = {
        "timestamp": timestamp,
        "url": TEST_URL,
        "model": "jev-test",
        "risk_level": "safe",
        "confidence": 0.72,
        "safe_probability": 0.79,
        "caution_probability": 0.14,
        "danger_probability": 0.01,
        "unknown_probability": 0.06,
        "phishing_suspicion": 0.15,
        "latency_ms": 0
    }

    with open(
        file_path, "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=row.keys()
        )
        writer.writeheader()
        writer.writerow(row)


# 캐시 조회 및 API 호출 분기 검증
def run_test(name, hours_ago, expected_api_calls):
    with tempfile.TemporaryDirectory() as temp_dir:
        test_csv = os.path.join(
            temp_dir, "test_results.csv"
        )

        if hours_ago is not None:
            create_test_csv(test_csv, hours_ago)

        with patch.object(main, "CSV_FILE", test_csv):
            with patch.object(
                main,
                "analyze_url",
                return_value=mock_jev_response()
            ) as mock_api:

                cached = main.get_cached_result(TEST_URL)

                if cached is not None:
                    main.print_cached_result(cached)
                else:
                    result = main.analyze_url(TEST_URL)
                    main.save_result_csv(TEST_URL, result)

                actual_calls = mock_api.call_count

                assert actual_calls == expected_api_calls, (
                    f"{name}: API 호출 횟수 불일치 "
                    f"(예상 {expected_api_calls}, 실제 {actual_calls})"
                )

                print(
                    f"{name}: PASS "
                    f"(API 호출 {actual_calls}회)"
                )


if __name__ == "__main__":
    run_test(
        "24시간 전 기록",
        hours_ago=24,
        expected_api_calls=0
    )

    run_test(
        "73시간 전 기록",
        hours_ago=73,
        expected_api_calls=1
    )

    run_test(
        "신규 URL",
        hours_ago=None,
        expected_api_calls=1
    )

    print("\n모든 API 호출 분기 테스트 통과!")
