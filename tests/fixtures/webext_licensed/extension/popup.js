// Synthetic popup — client-side entitlement gate reading from chrome.storage.local.
const TIERS = { FREE: 0, PRO: 10, PRO_PLUS: 20 };
let userLevel = 0;

chrome.storage.local.get("license", (data) => {
  userLevel = data?.license?.level || 0;
  renderSpeedButtons();
});

function renderSpeedButtons() {
  const locked = userLevel < TIERS.PRO; // entitlement enforced only in the browser
  document.getElementById("speed").disabled = locked;
}
