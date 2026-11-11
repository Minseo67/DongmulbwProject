
import re
import math
import ipaddress
from collections import Counter
from urllib.parse import urlsplit, parse_qsl
from difflib import SequenceMatcher

import numpy as np
import tldextract


# 기존 RF F의 특징 순서 유지
FEATURE_NAMES_21 = [
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
    "scheme_missing",
]

NEW_FEATURE_NAMES = [
    "hostname_entropy",
    "subdomain_length",
    "has_port",
    "percent_encoded_count",
    "query_length",
    "has_encoded_url",
    "hostname_digit_ratio",
    "suspicious_file_extension",
]

FEATURE_NAMES_29 = FEATURE_NAMES_21 + NEW_FEATURE_NAMES

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure",
    "update", "confirm", "password",
    "signin", "bank", "payment",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly",
}

BRAND_DOMAINS = [
    "google.com", "naver.com", "kakao.com",
    "youtube.com", "facebook.com",
    "instagram.com", "amazon.com",
    "microsoft.com", "apple.com", "paypal.com",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi",
    ".apk", ".hta",
}

TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=()
)


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features_21(url):
    """RF F의 기존 21개 특징 계산."""

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

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    if registered_domain in BRAND_DOMAINS:
        brand_similarity = 0.0
    else:
        brand_similarity = max(
            SequenceMatcher(
                None, registered_domain, brand
            ).ratio()
            for brand in BRAND_DOMAINS
        )

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
            c in "@?=&%_~#" for c in url
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
        "path_depth": len([
            part for part in path.split("/") if part
        ]),
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
        "scheme_missing": int(not has_explicit_scheme),
    }

    return features


def extract_features_29(url):
    """기존 21개 + 신규 8개 특징 계산."""

    url = str(url).strip()

    features = extract_features_21(url)

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

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 0

    filename = path.rsplit("/", 1)[-1].lower()

    new_features = {
        "hostname_entropy": calculate_entropy(hostname),

        "subdomain_length": len(
            extracted.subdomain or ""
        ),

        "has_port": has_port,

        "percent_encoded_count": len(
            re.findall(r"%[0-9A-Fa-f]{2}", url)
        ),

        "query_length": len(query),

        "has_encoded_url": int(bool(
            re.search(
                r"https?%3a%2f%2f",
                url,
                flags=re.IGNORECASE
            )
        )),

        "hostname_digit_ratio": (
            sum(c.isdigit() for c in hostname)
            / len(hostname)
            if hostname else 0.0
        ),

        "suspicious_file_extension": int(
            any(
                filename.endswith(ext)
                for ext in SUSPICIOUS_EXTENSIONS
            )
        ),
    }

    features.update(new_features)

    return features


def extract_feature_vector(url, feature_count=29):
    """특징 순서가 고정된 float32 벡터 반환."""

    if feature_count == 21:
        names = FEATURE_NAMES_21
        features = extract_features_21(url)

    elif feature_count == 29:
        names = FEATURE_NAMES_29
        features = extract_features_29(url)

    else:
        raise ValueError(
            "feature_count는 21 또는 29여야 합니다."
        )

    return np.asarray(
        [features[name] for name in names],
        dtype=np.float32
    )


assert len(FEATURE_NAMES_21) == 21
assert len(FEATURE_NAMES_29) == 29

assert list(
    extract_features_21("https://example.com")
) == FEATURE_NAMES_21

assert list(
    extract_features_29("https://example.com")
) == FEATURE_NAMES_29


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.naver.com",
        "https://github.com",
        "http://example.com/login?user=test",
        "example.com/path/file.exe",
        "http://192.168.1.1:8080/login",
    ]

    print("=" * 60)
    print("STEP 09-1 RF G 특징 추출 테스트")
    print("=" * 60)

    for url in test_urls:
        vector21 = extract_feature_vector(url, 21)
        vector29 = extract_feature_vector(url, 29)

        print(f"\nURL: {url}")
        print(f"G-A 특징 개수: {len(vector21)}")
        print(f"G-B 특징 개수: {len(vector29)}")
        print("신규 8개 특징:")

        features = extract_features_29(url)

        for name in NEW_FEATURE_NAMES:
            print(f"  {name}: {features[name]}")

    print("\nSTEP 09-1 기본 테스트 완료!")
