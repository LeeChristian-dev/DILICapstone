console.log("[DILI] content script loaded");

function injectTestRiskLabel() {
  const posts = document.querySelectorAll('[role="article"]');

  posts.forEach((post, index) => {
    if (post.querySelector(".dili-post-risk-label")) return;

    const label = document.createElement("div");
    label.className = "dili-post-risk-label dili-suspicious";
    label.innerHTML = `
      <span class="dili-risk-icon">⚠</span>
      <span class="dili-risk-text">Suspicious Link Detected!</span>
    `;

    const linkPreview =
      post.querySelector('a[href]')?.closest("div");

    if (linkPreview) {
      linkPreview.insertAdjacentElement("afterend", label);
    } else {
      post.appendChild(label);
    }

    if (index >= 2) return;
  });
}

setTimeout(() => {
  injectTestRiskLabel();
}, 3000);
