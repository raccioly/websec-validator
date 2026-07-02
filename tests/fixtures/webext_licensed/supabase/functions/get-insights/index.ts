import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const GUMROAD_VERIFY_URL = "https://api.gumroad.com/v2/licenses/verify";
const PRODUCT_ID = "BBB";

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ ok: false }), { status: 405 });
  }
  const { licenseKey } = await req.json();
  if (!licenseKey || typeof licenseKey !== "string") {
    return new Response(JSON.stringify({ ok: false }), { status: 400 });
  }

  // Verify license with Gumroad — grant on success alone, no revocation check, no seat cap.
  const verifyResp = await fetch(GUMROAD_VERIFY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      product_id: PRODUCT_ID,
      license_key: licenseKey.trim(),
      increment_uses_count: "false",
    }),
  });
  const verifyResult = await verifyResp.json();
  if (!verifyResult.success) {
    return new Response(JSON.stringify({ ok: false }), { status: 403 });
  }

  const { data } = await supabase.from("insights").select("*");
  return new Response(JSON.stringify({ ok: true, data: data || [] }));
});
