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

function renderOverallStatus(data) {
  const score = data.finalScore;
  const level = data.finalRiskLevel;

  // 백엔드의 최종 분석 결과 확인
  if (
    typeof score !== "number" ||
    !Number.isFinite(score) ||
    score < 0 ||
    score > 100 ||
    !["SAFE", "WARNING", "DANGER"].includes(level)
  ) {
    setStatus("검사 불가", "최종 분석 결과를 확인할 수 없습니다.", "error");
    return;
  }

  // 최종 점수와 등급 일치 여부 확인
  const expectedLevel =
    score >= 60 ? "DANGER" : score >= 30 ? "WARNING" : "SAFE";

  if (level !== expectedLevel) {
    setStatus(
      "검사 불가",
      "최종 점수와 위험 등급이 일치하지 않습니다.",
      "error",
    );
    return;
  }

  const statusMap = {
    SAFE: {
      label: "안전",
      message: "뚜렷한 위험 요소가 발견되지 않았습니다.",
      kind: "safe",
    },
    WARNING: {
      label: "주의",
      message: "악성 사이트일 가능성이 있으니 주의하세요.",
      kind: "warning",
    },
    DANGER: {
      label: "위험",
      message: "위험한 URL로 분석되었습니다.",
      kind: "danger",
    },
  };

  const status = statusMap[level];

  const rfNotice = data.fusionMode === "RULE_ONLY" ? " · RF 분석 제외" : "";

  setStatus(
    status.label,
    `${status.message} (최종 ${score.toFixed(1)}점${rfNotice})`,
    status.kind,
  );
}

// 전체 URL 분석
async function analyze() {
  $("retry").disabled = true;

  setStatus("분석 중...", "현재 사이트를 검사하고 있습니다.", "");

  const detailSummary = $("detailSummary");
  const detailFormulaText = $("detailFormulaText");

  if (detailSummary) {
    detailSummary.textContent = "분석 결과를 불러오는 중입니다.";
  }

  if (detailFormulaText) {
    detailFormulaText.textContent = "";
  }

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
    const timeout = setTimeout(() => controller.abort(), 60000);

    let response;

    try {
      for (let attempt = 0; attempt < 30; attempt++) {
        response = await fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url }),
          signal: controller.signal,
        });

        // 다른 요청이 분석 중이거나 재시도 대기 중
        if (response.status === 409) {
          setStatus("분석 중...", "분석 결과를 기다리고 있습니다.", "");

          await new Promise((resolve) => setTimeout(resolve, 1500));

          continue;
        }

        // 409 이외의 서버 오류
        if (!response.ok) {
          throw new Error("서버 응답 오류: HTTP " + response.status);
        }

        break;
      }

      if (!response || response.status === 409) {
        throw new Error(
          "분석 대기 시간이 길어지고 있습니다. 잠시 후 다시 검사해 주세요.",
        );
      }
    } finally {
      clearTimeout(timeout);
    }

    const data = await response.json();

    if (data.status !== "SUCCESS") {
      throw new Error("URL 분석에 실패했습니다.");
    }

    renderOverallStatus(data);
    renderDetailExplanation(data);
  } catch (error) {
    console.error("[DONGMULBW 분석 오류]", error);

    const message =
      error.name === "AbortError"
        ? "요청 시간이 초과되었습니다."
        : error.message;

    setStatus("검사 불가", message, "error");

    const detailSummary = $("detailSummary");
    const detailFormulaText = $("detailFormulaText");

    if (detailSummary) {
      detailSummary.textContent = "분석 결과를 확인할 수 없습니다.";
    }

    if (detailFormulaText) {
      detailFormulaText.textContent = message;
    }
  } finally {
    $("retry").disabled = false;
  }
}

// 이벤트 등록
document.addEventListener("DOMContentLoaded", () => {
  // 최종 점수 설명 더보기 버튼
  initializeDetailToggle();

  // 다시 검사 버튼
  $("retry").addEventListener("click", analyze);

  // 최초 URL 분석
  analyze();
});

function renderDetailExplanation(data) {
  const detailSummary = document.getElementById("detailSummary");
  const detailFormulaText = document.getElementById("detailFormulaText");

  if (!detailSummary || !detailFormulaText) return;

  const ruleScore = Number(data?.ruleAnalysis?.suspiciousScore);
  const finalScore = Number(data?.finalScore);
  const rfProbabilityRaw =
    data?.mlAnalysis?.maliciousProbability ?? data?.mlAnalysis?.probability;

  const rfProbability = Number(rfProbabilityRaw);

  const hasRuleScore = Number.isFinite(ruleScore);
  const hasFinalScore = Number.isFinite(finalScore);
  const hasRfProbability = Number.isFinite(rfProbability);

  if (hasRuleScore && hasFinalScore && hasRfProbability) {
    const rfPercent = rfProbability <= 1 ? rfProbability * 100 : rfProbability;

    const ruleWeighted = ruleScore * 0.7;
    const rfWeighted = rfPercent * 0.3;

    detailSummary.textContent = `최종 점수는 규칙 기반 검사와 RF 검사를 함께 반영해 ${finalScore.toFixed(1)}점으로 계산되었습니다.`;

    detailFormulaText.textContent = `계산식: 규칙 기반 ${ruleScore.toFixed(1)}점 × 70% + RF ${rfPercent.toFixed(1)}% × 30% = ${finalScore.toFixed(1)}점`;
    return;
  }

  if (hasRuleScore && hasFinalScore) {
    detailSummary.textContent = `현재 최종 점수는 ${finalScore.toFixed(1)}점입니다.`;

    detailFormulaText.textContent = `RF 분석 결과를 불러오지 못해 계산식 상세 정보는 표시할 수 없습니다.`;
    return;
  }

  detailSummary.textContent = "최종 점수 산정 방식을 불러오지 못했습니다.";

  detailFormulaText.textContent =
    "규칙 기반 검사 70% + RF 검사 30% 방식으로 최종 점수를 계산합니다.";
}

function initializeDetailToggle() {
  const toggleBtn = document.getElementById("toggleDetailsBtn");
  const detailBox = document.getElementById("detailBox");

  if (!toggleBtn || !detailBox) return;

  toggleBtn.addEventListener("click", () => {
    const isHidden = detailBox.classList.contains("hidden");

    if (isHidden) {
      detailBox.classList.remove("hidden");
      toggleBtn.textContent = "접기";
    } else {
      detailBox.classList.add("hidden");
      toggleBtn.textContent = "더보기";
    }
  });
}
