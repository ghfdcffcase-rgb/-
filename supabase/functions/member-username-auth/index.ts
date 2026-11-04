import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.0";

const allowedOrigins = new Set(["https://mithaq-platform.vercel.app", "https://mithaq-platform-ghfdcffcase-3079.vercel.app"]);
const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "Pragma": "no-cache",
};
const genericError = "اسم المستخدم أو كلمة المرور غير صحيحة.";

// Best-effort per-instance throttling. Keep the map bounded; production should
// additionally use a shared rate limiter (for example, an atomic database/Redis counter).
const attempts = new Map<string, { count: number; reset: number }>();
function isRateLimited(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  if (attempts.size > 5000) {
    for (const [entryKey, entry] of attempts) {
      if (entry.reset <= now) attempts.delete(entryKey);
    }
  }
  const current = attempts.get(key);
  if (!current || current.reset <= now) {
    attempts.set(key, { count: 1, reset: now + windowMs });
    return false;
  }
  current.count += 1;
  return current.count > limit;
}
const validUsername = (value: string) =>
  value.length >= 3 && value.length <= 30 &&
  /^[\p{L}\p{N}_][\p{L}\p{N}_.-]*$/u.test(value);

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (origin && !allowedOrigins.has(origin)) return new Response("Origin not allowed", { status: 403 });
  const corsHeaders = origin ? { ...headers, "Access-Control-Allow-Origin": origin } : headers;
  const respond = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: corsHeaders });
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Method not allowed" }, 405);

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anon || !service) return respond({ error: "الخدمة غير مهيأة على الخادم." }, 500);
    const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || "login");

    if (action === "get_username" || action === "set_username") {
      const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
      if (!token) return respond({ error: "سجّل الدخول أولًا." }, 401);
      const userClient = createClient(url, anon, {
        global: { headers: { Authorization: `Bearer ${token}` } },
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const { data: auth, error: authError } = await userClient.auth.getUser(token);
      if (authError || !auth.user) return respond({ error: "جلسة الدخول غير صالحة." }, 401);
      if (action === "get_username") {
        const { data: current, error: readError } = await admin.from("member_usernames").select("username").eq("user_id", auth.user.id).maybeSingle();
        if (readError) return respond({ error: "تعذر قراءة اسم المستخدم." }, 500);
        return respond({ username: current?.username || "" });
      }
      const username = String(body.username || "").trim().normalize("NFC");
      if (!validUsername(username)) return respond({ error: "اسم المستخدم من 3 إلى 30 حرفًا، ويقبل الحروف والأرقام و _ . -" }, 400);
      const { data: reservedRows, error: reservedError } = await admin.from("admin_users").select("username").in("role", ["manager", "manageress"]);
      if (reservedError) return respond({ error: "تعذر التحقق من اسم المستخدم." }, 500);
      if ((reservedRows || []).some((row) => String(row.username || "").toLowerCase() === username.toLowerCase())) return respond({ error: "اسم المستخدم محجوز لحساب الإدارة." }, 409);
      const { error } = await admin.from("member_usernames").upsert(
        { user_id: auth.user.id, username, updated_at: new Date().toISOString() },
        { onConflict: "user_id" },
      );
      if (error?.code === "23505") return respond({ error: "اسم المستخدم مستخدم بالفعل." }, 409);
      if (error) return respond({ error: "تعذر حفظ اسم المستخدم." }, 500);
      return respond({ success: true, username });
    }

    const username = String(body.username || "").trim().normalize("NFC");
    const password = String(body.password || "");
    const ip = req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const normalizedUsername = username.toLowerCase();
    if (action === "signup" && isRateLimited("signup:" + ip, 5, 60 * 60 * 1000)) {
      return respond({ error: "تم تجاوز عدد محاولات إنشاء الحساب. حاول لاحقًا." }, 429);
    }
    if (action === "login" && (
      isRateLimited("login-ip:" + ip, 30, 10 * 60 * 1000) ||
      isRateLimited("login:" + ip + ":" + normalizedUsername, 8, 10 * 60 * 1000)
    )) {
      return respond({ error: "محاولات كثيرة. انتظر قليلًا ثم حاول مجددًا." }, 429);
    }
    if (!validUsername(username) || password.length < 8 || password.length > 128) return respond({ error: genericError }, 401);

    if (action === "signup") {
      const { data: reservedRows, error: reservedError } = await admin.from("admin_users").select("username").in("role", ["manager", "manageress"]);
      if (reservedError) return respond({ error: "تعذر التحقق من اسم المستخدم." }, 500);
      if ((reservedRows || []).some((row) => String(row.username || "").toLowerCase() === username.toLowerCase())) return respond({ error: "اسم المستخدم محجوز لحساب الإدارة." }, 409);
      const email = `member-${crypto.randomUUID()}@mithaq.invalid`;
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { gender: String(body.gender || ""), full_name: String(body.full_name || "").slice(0, 60), auth_method: "username" },
      });
      if (createError || !created.user) return respond({ error: "تعذر إنشاء الحساب. تحقق من البيانات وحاول مجددًا." }, 400);
      const { error: insertError } = await admin.from("member_usernames").insert({ user_id: created.user.id, username });
      if (insertError) {
        await admin.auth.admin.deleteUser(created.user.id);
        return respond({ error: insertError.code === "23505" ? "اسم المستخدم مستخدم بالفعل." : "تعذر حفظ الحساب." }, insertError.code === "23505" ? 409 : 500);
      }
    } else if (action !== "login") {
      return respond({ error: "طلب غير صالح." }, 400);
    }

    const { data: row, error: lookupError } = await admin.from("member_usernames").select("user_id").eq("username_normalized", username.toLowerCase()).maybeSingle();
    if (lookupError || !row) return respond({ error: genericError }, 401);
    const { data: userData, error: userError } = await admin.auth.admin.getUserById(row.user_id);
    if (userError || !userData.user?.email) return respond({ error: genericError }, 401);

    const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: anon },
      body: JSON.stringify({ email: userData.user.email, password }),
    });
    const session = await response.json().catch(() => ({}));
    if (!response.ok || !session.access_token || !session.refresh_token) {
      return respond({ error: action === "signup" ? "تم إنشاء الحساب، لكن تعذر بدء الجلسة. حاول تسجيل الدخول." : genericError }, 401);
    }
    return respond({
      access_token: session.access_token, refresh_token: session.refresh_token,
      expires_in: session.expires_in, expires_at: session.expires_at, token_type: session.token_type || "bearer",
    });
  } catch (error) {
    console.error("member-username-auth failed:", error);
    return respond({ error: "تعذر إكمال العملية. حاول مرة أخرى." }, 500);
  }
});