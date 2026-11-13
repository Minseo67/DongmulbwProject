
const API_URL = "http://localhost:8080/api/urls/analyze";

const $ = (id) => document.getElementById(id);

function state(message, kind = "") {
  $("status").textContent = message;
  $("status").className = "status " + kind;
}

// 최종 통합 위험 등급 변환
function getFinalLevel(riskLevel) {
  switch (riskLevel) {
    case "SAFE":
      return ["안전", "safe"];

    case "CAUTION":
      return ["주의", "warning"];

    case "DANGER":
      return ["위험", "danger"];

    default:
      throw new Error("최종 위험 등급이 올바르지 않습니다.");
  }
}

// JEV 상태를 사용자용 문구로 변환
function getJevStatus(status) {
  switch (status) {
    case "COMPLETED":
      return "분석 완료";

    case "SKIPPED":
      return "미실행";

    case "UNAVAILABLE":
      return "분석 불가";

    case "NOT_EVALUATED":
      return "평가하지 않음";

    default:
      return "상태 미확인";
  }
}

function resetAnalysisView() {
  $("retry").disabled = true;

  $("findings").textContent = "분석 중...";
  $("score").textContent = "— / 100";
  $("fill").style.width = "0%";
  $("details").textContent = "";

  $("rule-level").textContent = "규칙 기반 등급: 확인 중";

  $("explanation-title").textContent = "분석 중...";
  $("explanation-description").textContent =
    "규칙 기반 및 AI 모델 분석을 진행하고 있습니다.";

  $("jev-status").textContent = "확인 중";
  $("rf-probability").textContent = "—";

  state("분석 중...");
}

async function analyze() {
  resetAnalysisView();

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const url = tab?.url;

    $("url").textContent =
      url || "URL을 확인할 수 없습니다.";

    if (!url || !/^https?:\/\//i.test(url)) {
      throw new Error(
        "HTTP/HTTPS 웹페이지에서만 분석할 수 있습니다."
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      35000
    );

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
      throw new Error(
        "서버 응답 오류: HTTP " + response.status
      );
    }

    const data = await response.json();

    // 1. 최종 통합 위험 등급
    const assessment = data.finalAssessment;

    if (!assessment || !assessment.riskLevel) {
      throw new Error(
        "서버 응답에 최종 통합 분석 결과가 없습니다."
      );
    }

    const [finalLabel, finalClass] =
      getFinalLevel(assessment.riskLevel);

    state("최종 위험 등급: " + finalLabel, finalClass);

    // 2. 자연어 설명
    const explanation = data.riskExplanation;

    if (explanation) {
      $("explanation-title").textContent =
        explanation.title ||
        "최종 분석 결과";

      $("explanation-description").textContent =
        explanation.description ||
        "분석 결과에 대한 설명이 없습니다.";
    } else {
      $("explanation-title").textContent =
        "최종 분석 결과";

      $("explanation-description").textContent =
        "최종 위험 등급이 산출되었으나 상세 설명이 없습니다.";
    }

    // 3. JEV 상태
    $("jev-status").textContent =
      getJevStatus(data.jevStatus);

    // 4. RF 악성 확률
    const ml = data.mlAnalysis;

    if (
      ml &&
      typeof ml.maliciousProbability === "number"
    ) {
      $("rf-probability").textContent =
        (ml.maliciousProbability * 100).toFixed(2) + "%";
    } else {
      $("rf-probability").textContent =
        "분석 불가";
    }

    // 5. 기존 규칙 기반 상세 분석
    const r = data.ruleAnalysis;

    if (!r || typeof r.suspiciousScore !== "number") {
      throw new Error(
        "응답에 규칙 기반 분석 결과가 없습니다."
      );
    }

    const score = Math.max(
      0,
      Math.min(100, r.suspiciousScore)
    );

    $("score").textContent = score + " / 100";
    $("fill").style.width = score + "%";

    // 규칙 기반 등급은 최종 통합 등급과 별도로 표시
    const ruleLevel = r.riskLevel;

    const ruleLabels = {
      SAFE: "안전",
      WARNING: "주의",
      CAUTION: "주의",
      DANGER: "위험",
    };

    $("rule-level").textContent =
      "규칙 기반 등급: " +
      (ruleLabels[ruleLevel] || "확인 불가");

    $("fill").style.background =
      ruleLevel === "DANGER"
        ? "#ef4444"
        : ruleLevel === "WARNING" ||
            ruleLevel === "CAUTION"
          ? "#f59e0b"
          : "#22c55e";

    // 6. 기존 위험 요소 출력
    if (!Array.isArray(r.findings)) {
      throw new Error(
        "백엔드 규칙 상세 결과가 없습니다."
      );
    }

    $("findings").replaceChildren();

    if (!r.findings.length) {
      const p = document.createElement("div");
      p.className = "empty";
      p.textContent =
        "탐지된 위험 요소가 없습니다.";

      $("findings").append(p);
    }

    for (const finding of r.findings) {
      const div = document.createElement("div");
      div.className = "finding";

      const name = document.createElement("span");
      name.textContent =
        "✓ " + finding.reason;

      const value = document.createElement("span");
      value.textContent =
        "+" + finding.points;

      div.append(name, value);
      $("findings").append(div);
    }

    // 7. 기존 상세 정보 유지
    $("details").textContent =
      "정규화 URL: " +
      (data.normalizedUrl || "—") +
      " · 도메인 평판: " +
      (data.reputationStatus || "미확인");

  } catch (error) {
    state("분석 실패", "error");

    $("explanation-title").textContent =
      "분석 결과를 표시할 수 없습니다.";

    $("explanation-description").textContent =
      error.name === "AbortError"
        ? "분석 요청 시간이 초과되었습니다. 서버 상태를 확인하세요."
        : error.message;

    $("jev-status").textContent = "확인 불가";

    $("findings").textContent =
      "분석을 완료하지 못했습니다.";

  } finally {
    $("retry").disabled = false;
  }
}

// ========================================
// RF 단독 테스트 (기존 기능 유지)
// ========================================

async function runRfTest() {
  const button = $("ml-test");
  const resultBox = $("ml-test-result");

  button.disabled = true;
  resultBox.textContent = "RF 모델 분석 중...";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const url = tab?.url;

    if (!url || !/^https?:\/\//i.test(url)) {
      throw new Error(
        "HTTP/HTTPS 페이지에서만 검사할 수 있습니다."
      );
    }

    const response = await fetch(
      "http://localhost:8080/api/urls/analyze/ml-test",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      }
    );

    const data = await response.json();

    if (!response.ok || data.status !== "SUCCESS") {
      throw new Error(
        data.message || "RF 분석 실패"
      );
    }

    const probability =
      Number(data.maliciousProbability);

    if (!Number.isFinite(probability)) {
      throw new Error(
        "RF 확률값이 올바르지 않습니다."
      );
    }

    const percentage =
      (probability * 100).toFixed(2);

    const prediction =
      data.prediction === 1
        ? "악성 예측"
        : "정상 예측";

    resultBox.textContent =
      `모델: ${data.modelVersion}\n` +
      `악성 확률: ${percentage}%\n` +
      `RF 판정: ${prediction}\n` +
      `※ 테스트용 결과이며 최종 위험도는 아닙니다.`;

    resultBox.style.whiteSpace = "pre-line";

  } catch (error) {
    resultBox.textContent =
      `RF 검사 실패: ${error.message}`;

  } finally {
    button.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("retry").addEventListener("click", analyze);

  const mlButton = $("ml-test");

  if (mlButton) {
    mlButton.addEventListener("click", runRfTest);
  }

  analyze();
});
