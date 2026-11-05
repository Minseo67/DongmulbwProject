"""Generate RF F feature parity fixtures from the actual Python extractor.
Run in the same environment as the RF F training notebook:
    pip install -r requirements.txt
    python generate_feature_test_cases.py
"""
import json
from pathlib import Path
import numpy as np
from features import FEATURE_NAMES, extract_features

HERE = Path(__file__).resolve().parent
feature_names = json.loads((HERE / 'feature_names.json').read_text(encoding='utf-8'))
assert feature_names == FEATURE_NAMES, 'feature order differs from training metadata'

cases = [
    ('normal_google', 'https://www.google.com/', 'normal_example'),
    ('normal_naver', 'https://www.naver.com/', 'normal_example'),
    ('suspicious_pattern', 'http://secure-login.example.com/verify-account?confirm=1', 'synthetic_suspicious_example'),
    ('missing_scheme', 'example.com/login?user=test', 'scheme_edge_case'),
]
result = {
    'description': 'RF F Python feature extraction reference; labels are illustrative, not ground-truth malware labels.',
    'feature_order': FEATURE_NAMES,
    'input_dtype': 'float32',
    'normalization': 'No separate URL normalization; extract_features strips surrounding whitespace and temporarily adds http:// for parsing when scheme is absent.',
    'cases': []
}
for case_id, url, category in cases:
    features = extract_features(url)
    assert list(features) == FEATURE_NAMES
    vector = np.asarray([features[name] for name in FEATURE_NAMES], dtype=np.float32)
    result['cases'].append({
        'id': case_id, 'url': url, 'category': category,
        'features_python': features,
        'vector_float32': [float(x) for x in vector],
    })

out = HERE / 'feature_test_cases.json'
out.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
print(f'Wrote {out} ({len(cases)} cases, {len(FEATURE_NAMES)} features each)')
