RF F-Base v1.0 - Random Forest malicious URL detection model
# RF F-Base v1.0 — 악성 URL 탐지 모델

## 1. 모델 개요

| 항목 | 내용 |
|---|---|
| 프로젝트 | AI 기반 실시간 악성 URL 탐지 크롬 확장 프로그램 |
| 알고리즘 | Random Forest Classifier |
| 모델명 | RF F-Base |
| 버전 | v1.0 |
| 모델 형식 | ONNX |
| 입력 특징 | URL 기반 특징 21개 |
| 분류 클래스 | 정상(0), 악성(1) |
| 판정 임계값 | 0.50 |
| 실행 환경 | ONNX Runtime |
| 사용 목적 | 백엔드 연동 및 시연용 |

본 모델은 URL의 특징 21개를 입력받아 악성 URL일 확률을 예측하는 이진 분류 모델입니다.

현재 버전은 시연 및 백엔드 연동 테스트를 위한 모델이며, 추후 새로운 데이터셋을 활용한 재학습 및 성능 개선 후 교체할 예정입니다.

## 2. 파일 구성

```text
ml/models/rf_f_v1/
├── rf_f_base.onnx
├── feature_names.json
├── model_config.json
└── README.md
```

| 파일명 | 설명 |
|---|---|
| `rf_f_base.onnx` | 학습된 Random Forest 모델 |
| `feature_names.json` | 입력 특징 21개의 이름 및 순서 |
| `model_config.json` | 모델 정보 및 판정 임계값 |
| `README.md` | 모델 사용 방법 및 연동 안내 |

## 3. 모델 입력

ONNX 모델은 URL 문자열 자체가 아닌, URL에서 추출한 21개의 숫자형 특징을 입력받습니다.

| 항목 | 값 |
|---|---|
| 입력 이름 | `input` |
| 입력 형태 | `[None, 21]` |
| URL 1개 입력 | `[1, 21]` |
| 입력 데이터 타입 | `float32` |
| 입력 특징 개수 | 21개 |

- `None`: 한 번에 입력할 URL의 개수
- `21`: URL에서 추출한 특징 개수

**주의사항**

- 입력 특징은 반드시 `feature_names.json`에 정의된 순서대로 전달해야 합니다.
- 특징 추출 방식은 모델 학습 당시 사용한 계산 방식과 동일해야 합니다.
- 특징값은 `float32` 형식으로 변환해야 합니다.

## 4. 모델 출력

ONNX 모델은 다음 두 가지 결과를 반환합니다.

| 출력 이름 | 데이터 타입 | 출력 형태 | 설명 |
|---|---|---|---|
| `label` | int64 | `[None]` | 모델 기본 예측 클래스 |
| `probabilities` | float32 | `[None, 2]` | 정상 및 악성 예측 확률 |

**클래스 정의**

| 클래스 | 의미 |
|---|---|
| 0 | 정상 URL (Benign) |
| 1 | 악성 URL (Malicious) |

URL 1개를 입력했을 때:

- `probabilities[0][0]`: 정상 URL일 확률
- `probabilities[0][1]`: 악성 URL일 확률

백엔드에서는 `probabilities`의 두 번째 클래스 확률을 악성 확률로 사용합니다.

## 5. 모델 판정 기준

모델의 악성 확률을 기준으로 이진 분류를 수행합니다.

| 악성 확률 | RF 판정 |
|---|---|
| 0.50 미만 | 정상(0) |
|