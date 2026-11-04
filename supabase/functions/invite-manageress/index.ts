import { createClient } from "https://esm.sh/@supabase/supabase-js@2.105.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://mithaq-platform.vercel.app",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\\s+/i, "");
    if (!token) return json({ error: "يلزم تسجيل الدخول بحساب المدير." }, 401);

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !anonKey || !serviceKey) {
      return json({ error: "إعدادات الخدمة غير مكتملة على الخادم." }, 500);
    }

    const userClient = createClient(url, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: `Bearer ${token}` } },
    });
    const { data: authData, error: authError } = await userClient.auth.getUser(token);
    if (authError || !authData.user) return json({ error: "جلسة الدخول غير صالحة." }, 401);

    const adminClient = createClient(url, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: callerRole, error: roleError } = await adminClient
      .from("admin_users").select("role").eq("user_id", authData.user.id).maybeSingle();
    if (roleError || callerRole?.role !== "manager") {
      return json({ error: "هذه العملية متاحة للمدير الرئيسي فقط." }, 403);
    }

    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    if (email.length > 254 || !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)) {
      return json({ error: "أدخل بريدًا إلكترونيًا صحيحًا." }, 400);
    }

    const { data: inviteData, error: inviteError } =
      await adminClient.auth.admin.inviteUserByEmail(email, {
        redirectTo: "https://mithaq-platform.vercel.app/",
        data: { invited_for: "mithaq_manageress" },
      });
    if (inviteError) return json({ error: inviteError.message }, 400);
    if (!inviteData.user?.id) return json({ error: "لم يتم إنشاء دعوة للحساب." }, 502);

    const { data: existingRole, error: existingError } = await adminClient
      .from("admin_users").select("role").eq("user_id", inviteData.user.id).maybeSingle();
    if (existingError) return json({ error: "تم إرسال الدعوة لكن تعذر التحقق من الصلاحية. راجع لوحة الإدارة." }, 500);
    if (existingRole?.role === "manager") {
      return json({ success: true, message: "هذا الحساب مدير بالفعل. لم يتم تغيير صلاحياته.", email });
    }
    const { error: upsertError } = await adminClient.from("admin_users")
      .upsert({ user_id: inviteData.user.id, role: "manageress" }, { onConflict: "user_id" });
    if (upsertError) {
      return json({ error: "أُرسلت الدعوة، لكن تعذر حفظ صلاحية المديرة. أعد المحاولة من لوحة المدير." }, 500);
    }

    return json({ success: true, message: "تم إرسال دعوة المديرة وإسناد صلاحياتها المحددة.", email });
  } catch (error) {
    console.error("invite-manageress failed:", error);
    return json({ error: "حدث خطأ أثناء إنشاء الدعوة." }, 500);
  }
});
