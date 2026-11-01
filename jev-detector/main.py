import os
import json
import sys
import csv
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests

# Jev API 설정
JEV_API_URL = "https://jevstation.com/api/v1/systemone"
CSV_FILE = "jev_results.csv"
CACHE_HOURS = 72


# URL 구성 요소 추출
def parse_url(url):
    parsed = urlsplit(url)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("HTTP/HTTPS URL만 지원합니다.")

    if not parsed.hostname:
        raise ValueError("호스트명이 없습니다.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("UserInfo가 포함된 URL은 제외합니다.")

    return {
        "url": url,
        "hostname": parsed.hostname,
        "path": parsed.path,
        "scheme": parsed.scheme.lower(),
        "query": (
            "?" + parsed.query
            if "?" in url.split("#", 1)[0]
            else ""
        ),
        "port": parsed.port,
        "fragment": (
            "#" + parsed.fragment
            if "#" in url
            else ""
        )
    }


# Jev 질문 구성
def build_questions():
    return {
        "risk_level": {
            "type": "choice",
            "instructions": (
                "Classify the phishing risk based only on "
                "the URL structure. Do not assume external "
                "reputation data has been checked."
            ),
            "criteria": {
                "safe": "No clear suspicious indicators",
                "caution": "Some suspicious indicators",
                "danger": "Strong phishing-related indicators",
                "unknown": "Insufficient evidence"
            }
        },
        "phishing_suspicion": {
            "type": "noul",
            "instructions": (
                "Does this URL structure show indicators "
                "commonly associated with phishing?"
            )
        }
    }


# Jev API 요청
def analyze_url(url):
    api_key = os.getenv("JEVSTATION_API_KEY")

    if not api_key:
        raise ValueError(
            "JEVSTATION_API_KEY가 설정되지 않았습니다."
        )

    state = parse_url(url)

    body = {
        "model": "jev",
        "state": state,
        "questions": build_questions()
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    response = requests.post(
        JEV_API_URL,
        headers=headers,
        json=body,
        timeout=60
    )

    response.raise_for_status()

    return response.json()


# Jev 분석 결과 CSV 저장
def save_result_csv(url, result):
    data = result["data"]
    answers = data["answers"]

    risk = answers["risk_level"]
    phishing = answers["phishing_suspicion"]

    probabilities = risk["probabilities"]

    file_path = CSV_FILE
    file_exists = os.path.isfile(file_path)

    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "url": url,
        "model": data.get("model"),
        "risk_level": risk.get("choice"),
        "confidence": risk.get("confidence"),
        "safe_probability": probabilities.get("safe"),
        "caution_probability": probabilities.get("caution"),
        "danger_probability": probabilities.get("danger"),
        "unknown_probability": probabilities.get("unknown"),
        "phishing_suspicion": phishing.get("noul"),
        "latency_ms": data.get("latency_ms")
    }

    with open(file_path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    print(f"\nCSV 저장 완료: {os.path.abspath(file_path)}")


# 기존 Jev 분석 결과 확인
def get_cached_result(url):
    if not os.path.isfile(CSV_FILE):
        return None

    now = datetime.now(timezone.utc)
    latest_row = None
    latest_time = None

    with open(CSV_FILE, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row.get("url") != url:
                continue

            try:
                saved_time = datetime.fromisoformat(row["timestamp"])

                # 이전 CSV 형식의 시각은 한국 시간으로 해석
                if saved_time.tzinfo is None:
                    saved_time = saved_time.replace(
                        tzinfo=timezone(timedelta(hours=9))
                    )

            except (ValueError, KeyError, TypeError):
                continue

            if latest_time is None or saved_time > latest_time:
                latest_time = saved_time
                latest_row = row

    if latest_row is None:
        return None

    elapsed = now - latest_time

    if elapsed >= timedelta(hours=CACHE_HOURS):
        return None

    return latest_row


# 저장된 CSV 결과 출력
def print_cached_result(row):
    print("\n===== Jev 분석 결과 (캐시) =====")
    print(f"분석 URL: {row['url']}")
    print(f"모델 버전: {row['model']}")
    print(f"분석 시각: {row['timestamp']}")
    print(f"판단 결과: {row['risk_level']}")
    print(f"판단 신뢰도: {row['confidence']}")

    print("\n[위험 등급별 확률]")
    for level in ("safe", "caution", "danger", "unknown"):
        value = row.get(f"{level}_probability")
        if value is not None and value != "":
            print(f"{level}: {float(value):.2%}")

    print("\n[피싱 의심]")
    print(f"Jev noul 점수: {row['phishing_suspicion']}")

    print("\n[API 사용 정보]")
    print("기존 분석 결과 재사용 (신규 API 호출 없음)")


# Jev 분석 결과를 공통 형식으로 변환
def format_result(url, data, cached):
    answers = data["answers"]
    risk = answers["risk_level"]
    phishing = answers["phishing_suspicion"]

    return {
        "url": url,
        "risk_level": risk["choice"],
        "confidence": risk.get("confidence"),
        "probabilities": risk["probabilities"],
        "phishing_suspicion": phishing.get("noul"),
        "model": data.get("model"),
        "cached": cached
    }


# CSV에 저장된 분석 결과를 공통 형식으로 변환
def format_cached_result(row):
    return {
        "url": row["url"],
        "risk_level": row["risk_level"],
        "confidence": float(row["confidence"]),
        "probabilities": {
            "safe": float(row["safe_probability"]),
            "caution": float(row["caution_probability"]),
            "danger": float(row["danger_probability"]),
            "unknown": float(row["unknown_probability"])
        },
        "phishing_suspicion": float(row["phishing_suspicion"]),
        "model": row["model"],
        "cached": True
    }


# Jev URL 탐지 통합 함수
def detect_url(url):
    # 1. URL 형식 검증
    parse_url(url)

    # 2. 기존 분석 기록 확인
    cached = get_cached_result(url)

    if cached is not None:
        return format_cached_result(cached)

    # 3. 캐시가 없거나 72시간이 지났으면 API 호출
    result = analyze_url(url)

    if result.get("code") != 0:
        raise ValueError(
            f"Jev 분석 실패: {result.get('message')}"
        )

    # 4. 신규 분석 결과 저장
    save_result_csv(url, result)

    # 5. 공통 형식으로 반환
    return format_result(
        url,
        result["data"],
        cached=False
    )



# 프로그램 실행
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("사용법: python main.py <URL>")
        sys.exit(1)

    test_url = sys.argv[1]

    try:
        result = detect_url(test_url)

        print("\n===== Jev 분석 결과 =====")
        print(f"분석 URL: {result['url']}")
        print(f"모델 버전: {result['model']}")

        print("\n[위험 등급]")
        print(f"판단 결과: {result['risk_level']}")
        print(f"판단 신뢰도: {result['confidence']}")

        print("\n[위험 등급별 확률]")
        for level, probability in result["probabilities"].items():
            print(f"{level}: {probability:.2%}")

        print("\n[피싱 의심]")
        print(f"Jev noul 점수: {result['phishing_suspicion']}")

        print("\n[캐시 정보]")
        if result["cached"]:
            print("기존 분석 결과 재사용 (API 호출 없음)")
        else:
            print("신규 Jev API 분석 완료")

    except requests.exceptions.RequestException as e:
        print("Jev API 요청 오류:", e)

    except (ValueError, KeyError, TypeError) as e:
        print("입력 또는 응답 처리 오류:", e)
