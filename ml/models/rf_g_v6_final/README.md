# G-V6-A-31 최종 RF 모델

## 모델 정보
- 알고리즘: Random Forest
- 모델 파일: G-V6-A-31.onnx
- 입력 특징: 31개, float32
- 악성 판정 임계값: 0.534
- URL 정규화: normalize_v2()

## URL 분석 순서
1. 원본 URL 입력
2. normalize_v2() 적용
3. get_features()로 31개 특징 추출
4. feature_names.json 순서대로 float32 배열 생성
5. ONNX Runtime으로 악성 확률 예측
6. 악성 확률 >= 0.534이면 RF 악성 판정

## 주요 코드
- rf_g_features.py: 기본 특징 추출
- step18_44_2_korean_model_evaluation.py:
  normalize_v2(), get_features() 구현

주의: get_features() 내부에서 정규화를 수행하므로
Python에서 별도로 normalize_v2()를 적용한 뒤
다시 정규화할 필요는 없습니다.

## 연동 주의사항
- 기존 F 모델의 특징 추출 로직을 그대로 사용하지 마세요.
- 정규화 및 31개 특징 계산 방식과 순서를 일치시켜야 합니다.
- 원본 URL은 화면 표시 및 DB 저장을 위해 별도로 유지하세요.
- ONNX 모델에는 정규화 함수와 임계값이 포함되지 않습니다.
- 최종 안전/주의/위험 판정은 규칙 기반 탐지와 결합합니다.
- Python과 Java의 악성 확률이 일치하는지 검증해야 합니다.

## 알려진 한계
- 구글 정상 URL에 대한 악성 오탐 확인
- PhiUSIIL Dev에서 재현율 약 43.04%
