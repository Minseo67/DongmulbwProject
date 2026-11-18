const $ = (id) => document.getElementById(id);

function disableContinue(message) {
  $("title").textContent = "분석 정보를 확인할 수 없습니다.";
  $("message").textContent = message;
  $("continue").disabled = true;
}

async function initializeWarningPage() {
  $("leave").addEventListener("click", () => {
    window.location.replace("about:blank");
  });

  try {
    const result = await chrome.runtime.sendMessage({
      action: "GET_WARNING",
    });

    if (result?.error || !result?.warning) {
      throw new Error("경고 정보가 만료되었습니다.");
    }

    const { url, score, level } = result.warning;

    if (
      !/^https?:\/\//i.test(url) ||
      typeof score !== "number" ||
      !Number.isFinite(score) ||
      !["WARNING", "DANGER"].includes(level)
    ) {
      throw new Error("올바르지 않은 경고 정보입니다.");
    }

    const isDanger = level === "DANGER";

    $("title").textContent = isDanger
      ? "위험한 사이트가 감지되었습니다!"
      : "주의가 필요한 사이트입니다.";

    $("title").className = isDanger ? "danger" : "warning";

    $("url").textContent = url;

    $("score").textContent = `최종 위험도 ${score.toFixed(1)} / 100점`;

    $("score").className = `score ${isDanger ? "danger" : "warning"}`;

    $("message").textContent = isDanger
      ? "악성 사이트일 가능성이 높습니다. 접속을 권장하지 않습니다."
      : "의심스러운 위험 요소가 발견되었습니다.";

    $("continue").disabled = false;

    $("continue").addEventListener("click", async () => {
      $("continue").disabled = true;

      try {
        const response = await chrome.runtime.sendMessage({
          action: "CONTINUE",
        });

        if (response?.error) {
          throw new Error(response.error);
        }
      } catch (error) {
        disableContinue("계속 접속 처리에 실패했습니다.");
        console.error(error);
      }
    });
  } catch (error) {
    console.error("[경고 페이지 오류]", error);
    disableContinue(error.message);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeWarningPage, {
    once: true,
  });
} else {
  initializeWarningPage();
}
