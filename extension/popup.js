const API_URL = "http://localhost:8080/api/urls/analyze";
const $ = id => document.getElementById(id);

const rules = [
  ['도메인 길이 30자 이상', r => r.domainLength >= 30, 15],
  ['도메인 하이픈 2개 이상', r => r.hyphenCount >= 2, 15],
  ['도메인 점 3개 이상', r => r.dotCount >= 3, 15],
  ['도메인 숫자 3개 이상', r => r.digitCount >= 3, 10],
  ['IP 주소 사용', r => r.hasIpAddress, 30],
  ['Punycode 사용', r => r.hasPunycode, 25],
  ['의심 키워드 포함', r => r.hasSuspiciousKeyword, 20],
  ['의심 TLD 사용', r => r.hasSuspiciousTld, 20],
  ['단축 URL 서비스', r => r.hasShortUrlService, 20],
  ['브랜드 사칭 패턴', r => r.hasBrandImpersonation, 50],
  ['브랜드 사칭 + 의심 키워드',
    r => r.hasBrandImpersonation && r.hasSuspiciousKeyword, 20],
  ['서브도메인 브랜드 사칭',
    r => r.hasSubdomainBrandImpersonation, 35],
  ['서브도메인 사칭 + 의심 키워드',
    r => r.hasSubdomainBrandImpersonation && r.hasSuspiciousKeyword, 20],
  ['단축 URL + 브랜드 사칭',
    r => r.hasShortUrlService && r.hasBrandImpersonation, 15],
  ['쿼리 파라미터 3개 이상',
    r => r.queryParamCount >= 3, 10],
  ['HTTP + 도메인 점 2개',
    (r, url) => r.dotCount === 2 && url.startsWith('http:'), 10]
];

function state(message, kind = "") {
  $("status").textContent = message;
  $("status").className = "status " + kind;
}

async function analyze() {
  $("retry").disabled = true;
  $("findings").textContent = "분석 중...";
  $("score").textContent = "— / 100";
  $("fill").style.width = "0%";
  $("details").textContent = "";

  state("분석 중...");

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const url = tab?.url;
    $("url").textContent = url || "URL을 확인할 수 없습니다.";

    if (!url || !/^https?:\/\//i.test(url)) {
      throw Error("http/https 웹페이지에서만 분석할 수 있습니다.");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35000);

    let response;

    try {
      response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw Error("서버 응답 오류: HTTP " + response.status);
    }

    const data = await response.json();
    const r = data.ruleAnalysis;

    if (!r || typeof r.suspiciousScore !== "number") {
      throw Error("응답에 규칙 기반 분석 결과가 없습니다.");
    }

    const score = Math.max(0, Math.min(100, r.suspiciousScore));

    // 시연 화면용 임시 기준
    // 백엔드의 최종 위험도 기준과는 별개
    const level =
      score >= 60
        ? ["위험", "danger"]
        : score >= 20
          ? ["주의", "warning"]
          : ["안전", "safe"];

    state("규칙 기반: " + level[0], level[1]);

    $("score").textContent = score + " / 100";
    $("fill").style.width = score + "%";

    $("fill").style.background =
      level[1] === "danger"
        ? "#ef4444"
        : level[1] === "warning"
          ? "#f59e0b"
          : "#22c55e";

    if (!Array.isArray(r.findings)) {
      throw Error('백엔드 규칙 상세 결과가 없습니다. 서버를 재시작하세요.');
    }

    const found = r.findings;

    $("findings").replaceChildren();

    if (!found.length) {
      const p = document.createElement("div");
      p.className = "empty";
      p.textContent = "탐지된 위험 요소가 없습니다.";
      $("findings").append(p);
    }

    for (const [label, , points] of found) {
      const div = document.createElement('div');
      div.className = 'finding';

      const name = document.createElement("span");
      name.textContent = "✓ " + label;

      const value = document.createElement("span");
      value.textContent = "+" + points;

      div.append(name, value);
      $("findings").append(div);
    }

    $("details").textContent =
      "정규화 URL: " +
      (data.normalizedUrl || "—") +
      " · 도메인 평판: " +
      (data.reputationStatus || "미확인");
  } catch (e) {
    state("분석 실패", "error");

    $('findings').textContent =
      e.name === 'AbortError'
        ? '분석 요청 시간 초과 (15초). 서버 상태를 확인하세요.'
        : e.message;
  } finally {
    $("retry").disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("retry").addEventListener("click", analyze);
  analyze();
});

// ========================================
// RF 단독 테스트
// ========================================

async function runRfTest() {
  const button = document.getElementById("ml-test");
  const resultBox = document.getElementById("ml-test-result");

  button.disabled = true;
  resultBox.textContent = "RF 모델 분석 중...";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const url = tab?.url;

    if (!url || !/^https?:\/\//i.test(url)) {
      throw new Error("HTTP/HTTPS 페이지에서만 검사할 수 있습니다.");
    }

    const response = await fetch(
      "http://localhost:8080/api/urls/analyze/ml-test",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      },
    );

    const data = await response.json();

    if (!response.ok || data.status !== "SUCCESS") {
      throw new Error(data.message || "RF 분석 실패");
    }

    const probability = Number(data.maliciousProbability);

    if (!Number.isFinite(probability)) {
      throw new Error("RF 확률값이 올바르지 않습니다.");
    }

    const percentage = (probability * 100).toFixed(2);
    const prediction = data.prediction === 1 ? "악성 예측" : "정상 예측";

    resultBox.textContent =
      `모델: ${data.modelVersion}\n` +
      `악성 확률: ${percentage}%\n` +
      `RF 판정: ${prediction}\n` +
      `※ 테스트용 결과이며 최종 위험도는 아닙니다.`;

    resultBox.style.whiteSpace = "pre-line";
  } catch (error) {
    resultBox.textContent = `RF 검사 실패: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const button = document.getElementById("ml-test");

  if (button) {
    button.addEventListener("click", runRfTest);
  }
});
