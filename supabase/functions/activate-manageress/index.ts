import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://mithaq-platform.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token) return json({ error: "يجب تسجيل الدخول أولاً." }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    if (!url || !anonKey) return json({ error: "إعدادات الخدمة غير مكتملة." }, 500);

    const userClient = createClient(url, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    });

    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "جلسة الدخول غير صالحة." }, 401);

    const body = await req.json().catch(() => ({}));
    const code = String(body.code || "").trim();
    if (code.length < 20 || code.length > 100) {
      return json({ error: "أدخل رمز تفعيل المديرة الصحيح." }, 400);
    }

    const { data, error } = await userClient.rpc("activate_manageress_with_code", {
      p_code_hash: await sha256(code),
    });

    if (error) {
      console.warn("Manageress activation rejected:", error.message);
      return json({ error: error.message || "تعذر تفعيل صلاحيات المديرة." }, 400);
    }

    return json({ success: true, message: "تم تفعيل حسابك كمديرة وخطّابة معتمدة.", data });
  } catch (error) {
    console.error("activate-manageress failed:", error);
    return json({ error: "حدث خطأ أثناء تفعيل الحساب." }, 500);
  }
});
