// Tier 4 of the cascade: LLM verdict for unknown, suspicious-looking pages.
// This is the most expensive tier, so the caller only invokes it when cheaper
// tiers are inconclusive AND the page shows credential-collection signals.
//
// Uses the OpenAI Chat Completions API directly (no SDK dependency).
// Set OPENAI_API_KEY; OPENAI_MODEL defaults to a cheap, fast model.

const SYSTEM_PROMPT = `You are a phishing-detection engine. You receive a URL and lightweight signals extracted from the rendered page. Decide whether the page is a phishing / credential-harvesting page impersonating a legitimate brand or service.

Weigh signals like: the page asking for passwords or payment info; forms that submit to a different host than the page; a domain that imitates a well-known brand; urgency/lure language ("verify", "suspended", "unusual activity"); mismatch between the claimed brand and the actual domain.

Be conservative: legitimate login pages exist. Only flag as phishing when multiple signals point to impersonation or credential theft.

Respond with STRICT JSON only, no prose:
{
  "phishing": boolean,
  "confidence": number,        // 0.0 - 1.0
  "impersonated_brand": string|null,
  "reason": string             // one concise sentence for the end user
}`;

/**
 * @returns {Promise<null | {phishing:boolean, confidence:number, impersonated_brand:string|null, reason:string}>}
 *          null when the LLM tier is unavailable (no key / error).
 */
export async function classifyWithLLM({ url, page }) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) return null;
  const model = process.env.OPENAI_MODEL || "gpt-4o-mini";

  const userContent = {
    url,
    title: page?.title || "",
    visible_text_snippet: (page?.text || "").slice(0, 1200),
    password_fields: page?.passwordFields ?? 0,
    total_inputs: page?.inputs ?? 0,
    current_host: page?.currentHost || "",
    form_submit_hosts: page?.formTargets || [],
    og_site_name: page?.ogSiteName || null,
  };

  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: JSON.stringify(userContent) },
        ],
      }),
    });

    if (!res.ok) {
      console.warn("OpenAI error:", res.status, await res.text());
      return null;
    }
    const data = await res.json();
    const raw = data.choices?.[0]?.message?.content;
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return {
      phishing: !!parsed.phishing,
      confidence: clamp01(Number(parsed.confidence)),
      impersonated_brand: parsed.impersonated_brand || null,
      reason: String(parsed.reason || ""),
    };
  } catch (err) {
    console.warn("OpenAI request failed:", err.message);
    return null;
  }
}

function clamp01(n) {
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(1, n));
}
