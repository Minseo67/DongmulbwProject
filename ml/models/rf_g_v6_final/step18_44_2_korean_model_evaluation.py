
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter
from math import log2
import sys
import json
import shutil

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)


# ==================================================
# 0. 경로 및 환경 설정
# ==================================================

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "src"))

from rf_g_features import extract_features_29

INPUT = (
    BASE
    / "results/reports/step18_44_1_korean_candidates.csv"
)

REPORT = BASE / "results/reports"
MODELS = BASE / "models"

REPORT.mkdir(parents=True, exist_ok=True)

MODEL_NAMES = [
    "G-V5-A_T5",
    "G-V5-C_T5"
]


# ==================================================
# 1. V2 URL 정규화
# G-V5 학습 코드와 동일
# ==================================================

def normalize_v2(value):
    url = str(value).strip()

    if not url:
        return ""

    if url.startswith("//"):
        url = url[2:]

    if "://" in url:
        url = url.split("://", 1)[1]

    try:
        parsed = urlsplit("//" + url)
    except ValueError:
        return url

    host = parsed.netloc.lower()

    if host.startswith("www."):
        host = host[4:]

    path = parsed.path

    if path == "/":
        path = ""

    result = host + path

    if parsed.query:
        result += "?" + parsed.query

    if parsed.fragment:
        result += "#" + parsed.fragment

    return result


# ==================================================
# 2. 엔트로피
# ==================================================

def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    n = len(text)

    return -sum(
        (count / n) * log2(count / n)
        for count in counts.values()
    )


# ==================================================
# 3. G-V5 추가 특징 6개
# 실제 step18_35_train_v5.py 기준
# ==================================================

def extract_extra_features(normalized):
    try:
        parsed = urlsplit("//" + normalized)

    except ValueError:
        return {
            "has_path": 0.0,
            "has_query": 0.0,
            "hostname_digit_ratio": 0.0,
            "path_entropy": 0.0,
            "max_subdomain_length": 0.0,
            "hostname_hyphen_count": 0.0
        }

    host = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    hostname = host.split(":")[0]
    host_length = len(hostname)

    digit_count = sum(
        char.isdigit()
        for char in hostname
    )

    parts = hostname.split(".")

    subdomains = (
        parts[:-2]
        if len(parts) > 2
        else []
    )

    return {
        "has_path": int(bool(path)),
        "has_query": int(bool(query)),
        "hostname_digit_ratio": (
            digit_count / host_length
            if host_length else 0.0
        ),
        "path_entropy": entropy(path),
        "max_subdomain_length": max(
            [len(part) for part in subdomains],
            default=0
        ),
        "hostname_hyphen_count": hostname.count("-")
    }


# ==================================================
# 4. 전체 특징 추출
# ==================================================

def get_features(url):
    normalized = normalize_v2(url)

    features = extract_features_29(normalized)

    features.update(
        extract_extra_features(normalized)
    )

    return features


# ==================================================
# 5. 성능 지표 계산
# ==================================================

def calculate_metrics(
    y_true,
    y_pred,
    probabilities
):
    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    )

    tn, fp, fn, tp = cm.ravel()

    return {
        "count": len(y_true),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),

        "accuracy": accuracy_score(
            y_true, y_pred
        ),

        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "fpr": (
            fp / (fp + tn)
            if (fp + tn)
            else np.nan
        ),

        "fnr": (
            fn / (fn + tp)
            if (fn + tp)
            else np.nan
        ),

        "auc": (
            roc_auc_score(
                y_true,
                probabilities
            )
            if len(np.unique(y_true)) == 2
            else np.nan
        )
    }


# ==================================================
# 6. 기존 결과 백업
# ==================================================

def backup_existing_results():
    filenames = [
        "step18_44_2_metrics.csv",
        "step18_44_2_predictions.csv"
    ]

    for filename in filenames:
        original = REPORT / filename

        if not original.exists():
            continue

        backup = REPORT / filename.replace(
            ".csv",
            "_before_fix.csv"
        )

        if backup.exists():
            print(
                f"기존 백업 유지: {backup.name}"
            )
            continue

        shutil.copy2(original, backup)

        print(
            f"백업 완료: {backup.name}"
        )


# ==================================================
# 7. 평가 시작
# ==================================================

def main():
    print("=" * 65)
    print(
        "STEP 18-44-2 | 국내 URL 기존 RF 모델 재평가"
    )
    print("=" * 65)

    # ----------------------------------------------
    # 평가 데이터 확인
    # ----------------------------------------------

    if not INPUT.exists():
        raise FileNotFoundError(
            f"평가 데이터 없음: {INPUT}"
        )

    df = pd.read_csv(INPUT)

    required_columns = [
        "url",
        "label",
        "source",
        "simple_url"
    ]

    missing_columns = [
        col
        for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"평가 데이터 컬럼 누락: {missing_columns}"
        )

    print("\n[1] 평가 데이터")

    print("전체:", len(df))

    print(
        df["label"]
        .value_counts()
        .sort_index()
    )

    # ----------------------------------------------
    # 특징 추출
    # ----------------------------------------------

    print("\n[2] 특징 추출")

    feature_rows = []

    for i, url in enumerate(
        df["url"].astype(str),
        start=1
    ):
        feature_rows.append(
            get_features(url)
        )

        if i % 2000 == 0:
            print(
                f"특징 추출: {i:,}/{len(df):,}",
                flush=True
            )

    features_df = pd.DataFrame(
        feature_rows
    )

    print(
        "특징 추출 완료:",
        features_df.shape
    )

    y_true = (
        df["label"]
        .astype(int)
        .to_numpy()
    )

    # ----------------------------------------------
    # 기존 결과 백업
    # ----------------------------------------------

    print("\n[3] 기존 결과 백업")

    backup_existing_results()

    # ----------------------------------------------
    # 모델별 평가
    # ----------------------------------------------

    summary = []

    predictions = df[
        [
            "url",
            "label",
            "source",
            "simple_url"
        ]
    ].copy()

    for name in MODEL_NAMES:
        print(f"\n[4] {name} 평가")

        model_path = (
            MODELS / f"{name}.joblib"
        )

        metadata_path = (
            MODELS / f"{name}.json"
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"모델 파일 없음: {model_path}"
            )

        if not metadata_path.exists():
            raise FileNotFoundError(
                f"메타데이터 없음: {metadata_path}"
            )

        model = joblib.load(
            model_path
        )

        metadata = json.loads(
            metadata_path.read_text(
                encoding="utf-8"
            )
        )

        feature_names = metadata[
            "feature_names"
        ]

        threshold = float(
            metadata["threshold"]
        )

        print(
            f"특징 개수: {len(feature_names)}"
        )

        print(
            f"임계값: {threshold}"
        )

        missing = [
            col
            for col in feature_names
            if col not in features_df.columns
        ]

        if missing:
            raise ValueError(
                f"{name} 특징 누락: {missing}"
            )

        X = (
            features_df[feature_names]
            .copy()
        )

        X = (
            X.replace(
                [np.inf, -np.inf],
                np.nan
            )
            .fillna(0)
        )

        probabilities = (
            model.predict_proba(
                X.to_numpy()
            )[:, 1]
        )

        y_pred = (
            probabilities >= threshold
        ).astype(int)

        predictions[
            f"{name}_prob"
        ] = probabilities

        predictions[
            f"{name}_pred"
        ] = y_pred

        metrics = calculate_metrics(
            y_true,
            y_pred,
            probabilities
        )

        metrics["model"] = name
        metrics["group"] = "ALL"

        summary.append(metrics)

        print("\n전체 혼동행렬")

        print(
            confusion_matrix(
                y_true,
                y_pred,
                labels=[0, 1]
            )
        )

        print(
            f"Accuracy={metrics['accuracy']:.4f}, "
            f"Precision={metrics['precision']:.4f}, "
            f"Recall={metrics['recall']:.4f}, "
            f"F1={metrics['f1']:.4f}"
        )

        print(
            f"FPR={metrics['fpr']:.4f}, "
            f"FNR={metrics['fnr']:.4f}, "
            f"AUC={metrics['auc']:.4f}"
        )

        # ------------------------------------------
        # 그룹별 평가
        # ------------------------------------------

        groups = {
            "Korean_Public": (
                df["label"] == 0
            ),

            "KISA_Phishing": (
                df["label"] == 1
            ),

            "KISA_Simple": (
                (df["label"] == 1)
                & (df["simple_url"] == 1)
            ),

            "KISA_NonSimple": (
                (df["label"] == 1)
                & (df["simple_url"] == 0)
            )
        }

        for group_name, mask in groups.items():
            mask = mask.to_numpy()

            group_metrics = calculate_metrics(
                y_true[mask],
                y_pred[mask],
                probabilities[mask]
            )

            group_metrics["model"] = name
            group_metrics["group"] = group_name

            summary.append(
                group_metrics
            )

            if group_name == "Korean_Public":
                print(
                    f"{group_name}: "
                    f"FPR={group_metrics['fpr']:.4f}"
                )

            else:
                print(
                    f"{group_name}: "
                    f"Recall={group_metrics['recall']:.4f}"
                )

        del model

    # ----------------------------------------------
    # 결과 저장
    # ----------------------------------------------

    summary_df = pd.DataFrame(
        summary
    )

    summary_path = (
        REPORT / "step18_44_2_metrics.csv"
    )

    predictions_path = (
        REPORT / "step18_44_2_predictions.csv"
    )

    summary_df.to_csv(
        summary_path,
        index=False,
        encoding="utf-8-sig"
    )

    predictions.to_csv(
        predictions_path,
        index=False,
        encoding="utf-8-sig"
    )

    print("\n[5] 결과 저장 완료")

    print(summary_path)
    print(predictions_path)

    print("\nSTEP 18-44-2 완료!")


if __name__ == "__main__":
    main()
