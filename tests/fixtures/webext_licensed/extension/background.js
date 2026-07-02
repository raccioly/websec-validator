// Synthetic WebExtension service worker — licensing patterns only (no real secrets).
const TIERS = { FREE: 0, PRO: 10, PRO_PLUS: 20 };
const SUPABASE_URL = "https://example.supabase.co";
const PRODUCTS = [
  { productId: "AAA", level: 10 },
  { productId: "BBB", level: 20 },
];

async function verifyKey(productId, licenseKey) {
  const resp = await fetch("https://api.gumroad.com/v2/licenses/verify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      product_id: productId,
      license_key: licenseKey,
      increment_uses_count: "false",
    }),
  });
  const result = await resp.json();
  return result.success; // trusts success only — no revocation state inspected
}

async function getInsights() {
  const data = await chrome.storage.local.get("license");
  const license = data.license;
  if (!license?.key) return { ok: false, error: "No license found." };
  if ((license.level || 0) < TIERS.PRO_PLUS) {
    return { ok: false, error: "Requires PRO_PLUS tier." };
  }
  const resp = await fetch(`${SUPABASE_URL}/functions/v1/get-insights`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ licenseKey: license.key }),
  });
  return resp.json();
}

async function activateLicense(licenseKey) {
  const sorted = [...PRODUCTS].sort((a, b) => b.level - a.level);
  for (const product of sorted) {
    if (await verifyKey(product.productId, licenseKey.trim())) {
      const license = { key: licenseKey.trim(), level: product.level, verifiedAt: Date.now() };
      await chrome.storage.local.set({ license });
      return { ok: true, level: product.level };
    }
  }
  return { ok: false, error: "Invalid license key." };
}
