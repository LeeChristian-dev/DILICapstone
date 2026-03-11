console.log("[DILI] content script loaded");

function injectTestRiskLabel() {
  const posts = document.querySelectorAll('[role="article"]');

  posts.forEach((post, index) => {
    if (post.querySelector(".dili-post-risk-label")) return;

    const label = document.createElement("div");
    label.className = "dili-post-risk-label dili-suspicious";
    label.innerHTML = `
      <div class="dili-risk-badge">
        <span class="dili-risk-dot"></span>
        <span class="dili-risk-text">Suspicious Link Detected</span>
      </div>
      <div class="dili-risk-subtext">
        This post may contain an edited or unsafe hyperlink.
      </div>
    `;

    post.prepend(label);

    if (index >= 2) return;
  });
}

setTimeout(() => {
  injectTestRiskLabel();
}, 3000);
