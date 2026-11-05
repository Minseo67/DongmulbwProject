# RF F URL 특징 추출 함수 (원본 Colab 셀 23에서 추출)

import re
import math
import ipaddress
from collections import Counter
from urllib.parse import urlsplit, parse_qsl
from difflib import SequenceMatcher

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "domain_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "digit_ratio",
    "has_ip_address",
    "has_https",
    "has_at_symbol",
    "path_length",
    "path_depth",
    "query_param_count",
    "has_punycode",
    "suspicious_keyword_count",
    "url_entropy",
    "has_url_shortener",
    "brand_similarity",
    "scheme_missing"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure",
    "update", "confirm", "password",
    "signin", "bank", "payment"
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly"
}

BRAND_DOMAINS = [
    "google.com",
    "naver.com",
    "kakao.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "paypal.com"
]

# 공개 접미사 처리용 라이브러리
import tldextract

# 실행 중 네트워크 조회를 피하고 내장 접미사 목록 사용
TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url):
    url = str(url).strip()

    has_explicit_scheme = bool(
        re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url)
    )

    parsed = urlsplit(
        url if has_explicit_scheme else "http://" + url
    )

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = TLD_EXTRACT(hostname)

    registered_domain = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.suffix
        else extracted.domain
    )

    subdomain_count = (
        len(extracted.subdomain.split("."))
        if extracted.subdomain
        else 0
    )

    # IP 주소 여부
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    # 브랜드 도메인 유사도
    # 정확한 브랜드 도메인은 의심 점수 0
    if registered_domain in BRAND_DOMAINS:
        brand_similarity = 0.0
    else:
        brand_similarity = max(
            SequenceMatcher(
                None, registered_domain, brand
            ).ratio()
            for brand in BRAND_DOMAINS
        )

    # 단축 URL 도메인 여부
    has_shortener = int(
        hostname in URL_SHORTENERS
        or any(
            hostname.endswith("." + domain)
            for domain in URL_SHORTENERS
        )
    )

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "domain_length": len(registered_domain),
        "subdomain_count": subdomain_count,
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "digit_count": sum(c.isdigit() for c in url),
        "special_char_count": sum(
            c in "@?=&%_~#"
            for c in url
        ),
        "digit_ratio": (
            sum(c.isdigit() for c in url) / len(url)
            if url else 0.0
        ),
        "has_ip_address": has_ip,
        "has_https": int(
            has_explicit_scheme
            and parsed.scheme.lower() == "https"
        ),
        "has_at_symbol": int("@" in url),
        "path_length": len(path),
        "path_depth": len(
            [part for part in path.split("/") if part]
        ),
        "query_param_count": len(
            parse_qsl(query, keep_blank_values=True)
        ),
        "has_punycode": int("xn--" in hostname),
        "suspicious_keyword_count": sum(
            url.lower().count(keyword)
            for keyword in SUSPICIOUS_KEYWORDS
        ),
        "url_entropy": calculate_entropy(url),
        "has_url_shortener": has_shortener,
        "brand_similarity": brand_similarity,
        "scheme_missing": int(not has_explicit_scheme)
    }

    return features


# 특징 개수 확인
assert len(FEATURE_NAMES) == 21

test_features = extract_features(
    "https://example.com/login?user=test"
)

assert list(test_features.keys()) == FEATURE_NAMES

print("RF F 특징 추출 함수 준비 완료!")
print("특징 개수:", len(test_features))
print("\n예시 URL 특징:")
for name, value in test_features.items():
    print(f"{name}: {value}")

def extract_feature_vector(url):
    """Return 21 features in model input order as float32."""
    import numpy as np
    features = extract_features(url)
    return np.asarray([features[name] for name in FEATURE_NAMES], dtype=np.float32)
