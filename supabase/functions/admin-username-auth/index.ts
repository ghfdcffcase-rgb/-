import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.0";

const allowedOrigins = new Set(["https://mithaq-platform.vercel.app", "https://mithaq-platform-ghfdcffcase-3079.vercel.app"]);
const baseHeaders = {"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin","Content-Type":"application/json"};
const genericError = "اسم المستخدم أو كلمة المرور غير صحيحة.";
const attempts = new Map<string, { count: number; reset: number }>();

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (origin && !allowedOrigins.has(origin)) return new Response("Origin not allowed", { status: 403 });
  const cors = origin ? { ...baseHeaders, "Access-Control-Allow-Origin": origin } : baseHeaders;
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: cors });
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anon || !service) return json({ error: "الخدمة غير مهيأة على الخادم." }, 500);

    const body = await req.json().catch(() => ({}));
    const action = String(body.action || "login");
    const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });

    if (action === "get_username" || action === "set_username") {
      const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
      if (!token) return json({ error: "سجّل الدخول أولًا." }, 401);
      const userClient = createClient(url, anon, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
      const { data: auth, error: authError } = await userClient.auth.getUser(token);
      if (authError || !auth.user) return json({ error: "جلسة الدخول غير صالحة." }, 401);
      const { data: role, error: roleError } = await admin.from("admin_users").select("role,username").eq("user_id", auth.user.id).maybeSingle();
      if (roleError || !role || !["manager", "manageress"].includes(role.role)) return json({ error: "هذه الخاصية للمدير والمديرة فقط." }, 403);
      if (action === "get_username") return json({ username: role.username || "" });
      const username = String(body.username || "").trim().normalize("NFC");
      if (username.length < 2 || username.length > 40 || !/^[\p{L}\p{N} _.-]+$/u.test(username)) return json({ error: "اسم المستخدم يجب أن يكون من 2 إلى 40 حرفًا." }, 400);
      const { data: existing } = await admin.from("admin_users").select("user_id").ilike("username", username).limit(1).maybeSingle();
      if (existing && existing.user_id !== auth.user.id) return json({ error: "اسم المستخدم مستخدم بالفعل." }, 409);
      const { error } = await admin.from("admin_users").update({ username }).eq("user_id", auth.user.id);
      if (error) return json({ error: "تعذر حفظ اسم المستخدم." }, 500);
      return json({ success: true, username });
    }

    if (action !== "login") return json({ error: "طلب غير صالح." }, 400);
    const username = String(body.username || "").trim().normalize("NFC");
    const password = String(body.password || "");
    if (username.length < 2 || username.length > 40 || !/^[\p{L}\p{N} _.-]+$/u.test(username) || password.length < 8 || password.length > 128) {
      return json({ error: genericError }, 401);
    }
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const key = ip + ":" + username.toLocaleLowerCase();
    const now = Date.now();
    const record = attempts.get(key);
    if (record && record.reset > now && record.count >= 8) return json({ error: "محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا." }, 429);
    if (!record || record.reset <= now) attempts.set(key, { count: 1, reset: now + 10 * 60 * 1000 });
    else record.count++;

    const { data: row, error: lookupError } = await admin.from("admin_users").select("user_id").ilike("username", username).limit(1).maybeSingle();
    if (lookupError || !row) return json({ error: genericError }, 401);
    const { data: userData, error: userError } = await admin.auth.admin.getUserById(row.user_id);
    if (userError || !userData.user?.email) return json({ error: genericError }, 401);

    const response = await fetch(url + "/auth/v1/token?grant_type=password", {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: anon },
      body: JSON.stringify({ email: userData.user.email, password }),
    });
    const session = await response.json().catch(() => ({}));
    if (!response.ok || !session.access_token || !session.refresh_token) return json({ error: genericError }, 401);
    attempts.delete(key);
    return json({
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_in: session.expires_in,
      expires_at: session.expires_at,
      token_type: session.token_type || "bearer",
    });
  } catch (error) {
    console.error("admin-username-auth failed:", error);
    return json({ error: "تعذر إكمال تسجيل الدخول. حاول مرة أخرى." }, 500);
  }
});