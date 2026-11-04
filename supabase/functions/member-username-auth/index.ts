import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.0";

const allowedOrigin = "https://mithaq-platform.vercel.app";
const headers = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
  "Content-Type": "application/json",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers });
const genericError = "اسم المستخدم أو كلمة المرور غير صحيحة.";
const validUsername = (value: string) =>
  value.length >= 3 && value.length <= 30 &&
  /^[\p{L}\p{N}_][\p{L}\p{N}_.-]*$/u.test(value);

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (req.headers.get("origin") && req.headers.get("origin") !== allowedOrigin) {
    return json({ error: "Origin not allowed" }, 403);
  }

  try {
    const url = Deno.env.get("SUPABASE_URL");
    const anon = Deno.env.get("SUPABASE_ANON_KEY");
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anon || !service) return json({ error: "الخدمة غير مهيأة على الخادم." }, 500);
    const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || "login");

    if (action === "set_username") {
      const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
      if (!token) return json({ error: "سجّل الدخول أولًا." }, 401);
      const userClient = createClient(url, anon, {
        global: { headers: { Authorization: `Bearer ${token}` } },
        auth: { persistSession: false, autoRefreshToken: false },
      });
      const { data: auth, error: authError } = await userClient.auth.getUser(token);
      if (authError || !auth.user) return json({ error: "جلسة الدخول غير صالحة." }, 401);
      const username = String(body.username || "").trim().normalize("NFC");
      if (!validUsername(username)) return json({ error: "اسم المستخدم من 3 إلى 30 حرفًا، ويقبل الحروف والأرقام و _ . -" }, 400);
      const { error } = await admin.from("member_usernames").upsert(
        { user_id: auth.user.id, username, updated_at: new Date().toISOString() },
        { onConflict: "user_id" },
      );
      if (error?.code === "23505") return json({ error: "اسم المستخدم مستخدم بالفعل." }, 409);
      if (error) return json({ error: "تعذر حفظ اسم المستخدم." }, 500);
      return json({ success: true, username });
    }

    const username = String(body.username || "").trim().normalize("NFC");
    const password = String(body.password || "");
    if (!validUsername(username) || password.length < 8 || password.length > 128) {
      return json({ error: genericError }, 401);
    }

    if (action === "signup") {
      const email = `member-${crypto.randomUUID()}@mithaq.invalid`;
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: {
          gender: String(body.gender || ""),
          full_name: String(body.full_name || "").slice(0, 60),
          auth_method: "username",
        },
      });
      if (createError || !created.user) return json({ error: "تعذر إنشاء الحساب. تحقق من البيانات وحاول مجددًا." }, 400);
      const { error: insertError } = await admin.from("member_usernames").insert({
        user_id: created.user.id, username,
      });
      if (insertError) {
        await admin.auth.admin.deleteUser(created.user.id);
        return json({ error: insertError.code === "23505" ? "اسم المستخدم مستخدم بالفعل." : "تعذر حفظ الحساب." }, insertError.code === "23505" ? 409 : 500);
      }
    } else if (action !== "login") {
      return json({ error: "طلب غير صالح." }, 400);
    }

    const { data: row, error: lookupError } = await admin.from("member_usernames")
      .select("user_id").eq("username_normalized", username.toLocaleLowerCase()).maybeSingle();
    if (lookupError || !row) return json({ error: genericError }, 401);
    const { data: userData, error: userError } = await admin.auth.admin.getUserById(row.user_id);
    if (userError || !userData.user?.email) return json({ error: genericError }, 401);

    const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: anon },
      body: JSON.stringify({ email: userData.user.email, password }),
    });
    const session = await response.json().catch(() => ({}));
    if (!response.ok || !session.access_token || !session.refresh_token) {
      return json({ error: action === "signup" ? "تم إنشاء الحساب، لكن تعذر بدء الجلسة. حاول تسجيل الدخول." : genericError }, 401);
    }
    return json({
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_in: session.expires_in,
      expires_at: session.expires_at,
      token_type: session.token_type || "bearer",
    });
  } catch (error) {
    console.error("member-username-auth failed:", error);
    return json({ error: "تعذر إكمال العملية. حاول مرة أخرى." }, 500);
  }
});
