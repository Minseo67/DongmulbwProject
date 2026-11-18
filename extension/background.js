const API_URL = "http://localhost:8080/api/urls/analyze";
const WARNING_PAGE = chrome.runtime.getURL("warning.html");

const lastUrls = new Map();
const analyzingTabs = new Set();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function requestAnalysis(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 35000);

  try {
    for (let attempt = 0; attempt < 5; attempt++) {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });

      // 팝업 또는 다른 요청에서 같은 URL을 분석 중
      if (response.status === 409) {
        await sleep(1500);
        continue;
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      if (data.status !== "SUCCESS") {
        throw new Error(`분석 실패: ${data.status}`);
      }

      return data;
    }

    throw new Error("분석이 계속 진행 중입니다.");
  } finally {
    clearTimeout(timeout);
  }
}

function validateFinalResult(data) {
  const score = data.finalScore;
  const level = data.finalRiskLevel;

  if (
    typeof score !== "number" ||
    !Number.isFinite(score) ||
    score < 0 ||
    score > 100
  ) {
    throw new Error("최종 점수가 올바르지 않습니다.");
  }

  const expectedLevel =
    score >= 60 ? "DANGER" : score >= 30 ? "WARNING" : "SAFE";

  if (level !== expectedLevel) {
    throw new Error("최종 점수와 등급이 일치하지 않습니다.");
  }

  return { score, level };
}

async function analyzeVisit(tabId, url) {
  if (!url || !/^https?:\/\//i.test(url)) return;

  const allowKey = `allow_${tabId}`;
  const allowed = (await chrome.storage.session.get(allowKey))[allowKey];

  // 사용자가 직접 계속 접속을 허용한 URL
  if (allowed === url) return;

  if (allowed && allowed !== url) {
    await chrome.storage.session.remove(allowKey);
  }

  if (lastUrls.get(tabId) === url) return;
  if (analyzingTabs.has(tabId)) return;

  analyzingTabs.add(tabId);

  try {
    console.log("[DONGMULBW 분석 시작]", url);

    const data = await requestAnalysis(url);
    const { score, level } = validateFinalResult(data);

    console.log("[DONGMULBW 최종 결과]", {
      url,
      score,
      level,
    });

    // 분석 완료 사이에 사용자가 다른 주소로 이동했는지 확인
    const tab = await chrome.tabs.get(tabId);

    if (tab.url !== url) return;

    const latestAllowed = (await chrome.storage.session.get(allowKey))[
      allowKey
    ];

    if (latestAllowed === url) return;

    lastUrls.set(tabId, url);

    if (level !== "DANGER") return;

    // 위험 사이트 경고에 필요한 정보 저장
    const warningKey = `warning_${tabId}`;

    await chrome.storage.session.set({
      [warningKey]: {
        url,
        score,
        level,
      },
    });

    await chrome.tabs.update(tabId, {
      url: WARNING_PAGE,
    });
  } catch (error) {
    console.error("[DONGMULBW 자동 분석 실패]", error);
    // 실패했더라도 SAFE로 판단하지 않음
  } finally {
    analyzingTabs.delete(tabId);

    // 분석 도중 다른 페이지로 이동했다면 새 URL 검사
    try {
      const currentTab = await chrome.tabs.get(tabId);

      if (
        currentTab.url !== url &&
        /^https?:\/\//i.test(currentTab.url || "")
      ) {
        analyzeVisit(tabId, currentTab.url);
      }
    } catch {
      // 이미 닫힌 탭이면 무시
    }
  }
}

// 웹사이트 이동 감지
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    analyzeVisit(details.tabId, details.url);
  }
});

// SPA 주소 변경 감지
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) {
    analyzeVisit(details.tabId, details.url);
  }
});

// 탭 활성화 시 확인
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    analyzeVisit(tabId, tab.url);
  } catch (error) {
    console.error("[탭 조회 실패]", error);
  }
});

// 탭 종료 시 기록 제거
chrome.tabs.onRemoved.addListener((tabId) => {
  lastUrls.delete(tabId);
  analyzingTabs.delete(tabId);

  chrome.storage.session.remove([`warning_${tabId}`, `allow_${tabId}`]);
});

// 경고 페이지와 메시지 통신
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.action !== "GET_WARNING" && message?.action !== "CONTINUE") {
    return;
  }

  const tabId = sender.tab?.id;

  if (!Number.isInteger(tabId) || sender.url !== WARNING_PAGE) {
    sendResponse({ error: "INVALID_WARNING_CONTEXT" });
    return;
  }

  (async () => {
    const warningKey = `warning_${tabId}`;
    const entry = (await chrome.storage.session.get(warningKey))[warningKey];

    if (!entry) {
      return { error: "WARNING_EXPIRED" };
    }

    if (message.action === "CONTINUE") {
      // 사용자가 선택한 정확한 URL만 재경고 방지
      await chrome.storage.session.set({
        [`allow_${tabId}`]: entry.url,
      });

      await chrome.storage.session.remove(warningKey);

      await chrome.tabs.update(tabId, {
        url: entry.url,
      });
    }

    return { warning: entry };
  })()
    .then(sendResponse)
    .catch((error) => sendResponse({ error: String(error) }));

  return true;
});
