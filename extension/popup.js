const API_URL = "http://localhost:8080/api/urls/analyze";
const $ = (id) => document.getElementById(id);

// 결과 글씨 설정
function setResult(id, message, colorClass = "text-muted") {
  const element = $(id);
  element.textContent = message;
  element.className = colorClass;
}

// 최종 위험도 표시
function setStatus(level, message, kind) {
  $("status").textContent = level;
  $("status-message").textContent = message;
  $("status-box").className = "status-box " + kind;
}

// 자세히 보기 펼치기
function setupToggle(buttonId, detailId) {
  const button = $(buttonId);
  const detail = $(detailId);

  button.addEventListener("click", () => {
    const willOpen = detail.hidden;
    detail.hidden = !willOpen;

    button.textContent = willOpen ? "접기" : "자세히 보기";

    button.setAttribute("aria-expanded", String(willOpen));
  });
}

// 규칙 기반 분석 결과
function renderRuleAnalysis(rule) {
  if (!rule || typeof rule.suspiciousScore !== "number") {
    setResult("score", "검사 불가");
    $("findings").textContent = "검사 결과가 없습니다.";
    $("rule-total").textContent = "—";
    return;
  }

  const score = rule.suspiciousScore;

  setResult(
    "score",
    score + "점",
    score >= 70 ? "text-danger" : score >= 30 ? "text-warning" : "text-safe",
  );

  $("rule-total").textContent = score + " / 100점";
  $("findings").replaceChildren();

  const findings = Array.isArray(rule.findings) ? rule.findings : [];

  if (findings.length === 0) {
    $("findings").textContent = "탐지된 위험 요소가 없습니다.";
    return;
  }

  findings.forEach((finding) => {
    const row = document.createElement("div");
    row.className = "finding-row";

    const reason = document.createElement("span");
    reason.textContent = finding.reason ?? "기타 탐지";

    const points = document.createElement("strong");
    const value = Number(finding.points);

    points.textContent = Number.isFinite(value)
      ? `${value > 0 ? "+" : ""}${value}점`
      : "—";

    row.append(reason, points);
    $("findings").appendChild(row);
  });
}

// 블랙리스트 검사 결과
function renderBlacklist(data) {
  const blocked =
    data.reputationStatus === "BLACKLISTED" || data.phishingUrlMatched === true;

  if (blocked) {
    setResult("blacklist-result", "일치", "text-danger");
  } else {
    setResult("blacklist-result", "일치 없음", "text-safe");
  }

  return blocked;
}

// RF 분석 결과
function renderRfAnalysis(ml) {
  $("rf-fill").style.width = "0%";

  if (!ml || ml.status === "UNAVAILABLE") {
    setResult("rf-result", "검사 불가");
    $("rf-probability").textContent = "—";
    $("rf-description").textContent = "RF 모델 분석 결과를 가져올 수 없습니다.";
    return;
  }

  if (ml.status === "SKIPPED") {
    setResult("rf-result", "검사 생략");
    $("rf-probability").textContent = "—";
    $("rf-description").textContent =
      "블랙리스트에 일치하여 RF 검사를 생략했습니다.";
    return;
  }

  if (ml.status !== "SUCCESS") {
    setResult("rf-result", "결과 없음");
    $("rf-probability").textContent = "—";
    $("rf-description").textContent = "RF 검사 결과가 없습니다.";
    return;
  }

  const probability = Number(ml.maliciousProbability);

  if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
    setResult("rf-result", "검사 불가");
    $("rf-probability").textContent = "—";
    $("rf-description").textContent = "RF 예측 점수가 올바르지 않습니다.";
    return;
  }

  const percent = (probability * 100).toFixed(2);
  const isMalicious = ml.prediction === 1;

  setResult(
    "rf-result",
    isMalicious ? "악성 예측" : "정상 예측",
    isMalicious ? "text-danger" : "text-safe",
  );

  $("rf-probability").textContent = percent + "%";
  $("rf-fill").style.width = percent + "%";

  $("rf-description").textContent =
    `정상 예측 점수: ${(100 - probability * 100).toFixed(2)}%`;
}

// 최종 상태 표시
function renderOverallStatus(data, blocked) {
  const rule = data.ruleAnalysis;
  const ml = data.mlAnalysis;

  if (blocked) {
    setStatus(
      "위험",
      "악성 URL 목록과 일치했습니다. 접속을 권장하지 않습니다.",
      "danger",
    );
    return;
  }

  if (!rule || !["SAFE", "WARNING", "DANGER"].includes(rule.riskLevel)) {
    setStatus(
      "검사 불가",
      "규칙 기반 검사 결과를 확인할 수 없습니다.",
      "error",
    );
    return;
  }

  // 임시 UI 표시 기준: 규칙 위험도와 RF 예측을 함께 확인
  const rfMalicious = ml?.status === "SUCCESS" && ml.prediction === 1;

  if (rule.riskLevel === "DANGER") {
    setStatus("위험", "위험한 URL 특징이 다수 발견되었습니다.", "danger");
  } else if (rule.riskLevel === "WARNING" || rfMalicious) {
    setStatus(
      "주의",
      "악성 사이트일 가능성이 있으니 접속에 주의하세요.",
      "warning",
    );
  } else if (ml?.status === "UNAVAILABLE") {
    setStatus("검사 일부 실패", "RF 검사를 완료하지 못했습니다.", "error");
  } else {
    setStatus(
      "안전",
      "현재 검사에서 뚜렷한 위험 징후가 발견되지 않았습니다.",
      "safe",
    );
  }
}

// 전체 URL 분석
async function analyze() {
  $("retry").disabled = true;

  setStatus("분석 중...", "현재 사이트를 검사하고 있습니다.", "");

  setResult("blacklist-result", "검사 중");
  setResult("score", "—점");
  setResult("rf-result", "검사 중");

  $("findings").textContent = "분석 중...";
  $("rule-total").textContent = "—";
  $("rf-probability").textContent = "—";
  $("rf-description").textContent = "";
  $("rf-fill").style.width = "0%";

  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    const url = tab?.url;

    $("url").textContent = url || "URL을 확인할 수 없습니다.";

    if (!url || !/^https?:\/\//i.test(url)) {
      throw new Error("HTTP/HTTPS 웹페이지에서만 검사할 수 있습니다.");
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
      throw new Error("서버 응답 오류: HTTP " + response.status);
    }

    const data = await response.json();

    if (data.status !== "SUCCESS") {
      throw new Error("URL 분석에 실패했습니다.");
    }

    const blocked = renderBlacklist(data);
    renderRuleAnalysis(data.ruleAnalysis);
    renderRfAnalysis(data.mlAnalysis);
    renderOverallStatus(data, blocked);
  } catch (error) {
    const message =
      error.name === "AbortError"
        ? "요청 시간이 초과되었습니다."
        : error.message;

    setStatus("검사 불가", message, "error");
    setResult("blacklist-result", "확인 불가");
    setResult("score", "확인 불가");
    setResult("rf-result", "확인 불가");
    $("findings").textContent = message;
    $("rf-description").textContent = message;
  } finally {
    $("retry").disabled = false;
  }
}

// 이벤트 등록
document.addEventListener("DOMContentLoaded", () => {
  setupToggle("rule-toggle", "rule-details");
  setupToggle("rf-toggle", "rf-details");

  $("retry").addEventListener("click", analyze);

  analyze();
});
