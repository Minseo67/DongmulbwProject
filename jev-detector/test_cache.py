
import csv
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import main


def test_cache():
    url = "https://example.com/login"

    now = datetime.now(timezone.utc)

    test_cases = [
        ("24시간 전", now - timedelta(hours=24), True),
        ("73시간 전", now - timedelta(hours=73), False),
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        csv_path = os.path.join(temp_dir, "test_results.csv")

        with patch.object(main, "CSV_FILE", csv_path):

            for name, timestamp, expected in test_cases:
                with open(
                    csv_path,
                    "w",
                    newline="",
                    encoding="utf-8-sig"
                ) as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["timestamp", "url", "risk_level"]
                    )
                    writer.writeheader()
                    writer.writerow({
                        "timestamp": timestamp.isoformat(),
                        "url": url,
                        "risk_level": "safe"
                    })

                result = main.get_cached_result(url)
                success = (result is not None) == expected

                print(
                    f"{name}: "
                    f"{'PASS' if success else 'FAIL'}"
                )

                assert success, f"{name} 테스트 실패"

            # 저장된 기록이 없는 URL
            result = main.get_cached_result(
                "https://new-example.com"
            )

            assert result is None
            print("신규 URL: PASS")


if __name__ == "__main__":
    test_cache()
