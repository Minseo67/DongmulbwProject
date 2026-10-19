
const API_URL = "http://localhost:8080/api/urls/collect";

// 같은 탭에서 동일한 URL이 반복 전송되는 것을 방지
const lastUrls = new Map();

async function sendUrl(tabId, url) {
    // http, https 주소만 수집
    if (!url || !/^https?:\/\//i.test(url)) {
        return;
    }

    if (lastUrls.get(tabId) === url) {
        return;
    }

    lastUrls.set(tabId, url);

    console.log("[URL 자동 감지]", url);

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        console.log("[URL 전송 성공]", result);

    } catch (error) {
        console.error("[URL 전송 실패]", error);

        // 실패한 URL은 재시도할 수 있도록 중복 기록 제거
        if (lastUrls.get(tabId) === url) {
            lastUrls.delete(tabId);
        }
    }
}

// 웹사이트 이동 감지
chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) {
        sendUrl(details.tabId, details.url);
    }
});

// SPA 웹사이트의 주소 변경 감지
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0) {
        sendUrl(details.tabId, details.url);
    }
});

// 다른 탭으로 이동할 때 현재 URL 확인
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
        const tab = await chrome.tabs.get(tabId);
        sendUrl(tabId, tab.url);
    } catch (error) {
        console.error("[탭 조회 오류]", error);
    }
});

// 닫힌 탭 기록 제거
chrome.tabs.onRemoved.addListener((tabId) => {
    lastUrls.delete(tabId);
});
