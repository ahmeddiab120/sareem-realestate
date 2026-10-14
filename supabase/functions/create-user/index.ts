// SAREEM — create a Supabase account straight from the site's users page.
//
// This is the ONLY place the secret service key is used, and it never leaves
// Supabase's own server: the browser sends the admin's normal login token, the
// function checks that token really belongs to an admin, and only then does it
// create the account with the secret key.
//
// Deploy: Supabase dashboard -> Edge Functions -> create `create-user` ->
// paste this file -> Deploy. Then in the function's Settings turn
// "Verify JWT" OFF: the browser sends a preflight OPTIONS request that carries
// no token, and the platform would reject it before this code runs. Nothing is
// lost by turning it off — the admin check below is the real gate, and a caller
// without a valid admin token gets 401/403.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const PROJECT_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const SITE_ORIGIN = "https://ahmeddiab120.github.io";
const ALLOWED_ROLES = ["admin", "owner", "engineer", "data_entry", "pending"];

const HEADERS = {
  "Access-Control-Allow-Origin": SITE_ORIGIN,
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: HEADERS });
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: HEADERS });
  if (req.method !== "POST") return reply(405, { error: "طريقة الطلب غير مسموحة" });
  if (!SERVICE_KEY) return reply(500, { error: "الدالة غير مضبوطة — المفتاح السري مش موجود" });

  // ---- who is asking? ----
  const bearer = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!bearer) return reply(401, { error: "لازم تسجل دخول في الموقع الأول" });

  const admin = createClient(PROJECT_URL, SERVICE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: who, error: whoErr } = await admin.auth.getUser(bearer);
  if (whoErr || !who?.user) {
    return reply(401, { error: "جلسة الدخول غير صالحة — اخرج وادخل من جديد" });
  }

  const callerEmail = String(who.user.email ?? "").toLowerCase();
  const { data: me } = await admin
    .from("user_roles")
    .select("role, disabled")
    .eq("email", callerEmail)
    .maybeSingle();

  if (!me || me.disabled || me.role !== "admin") {
    return reply(403, { error: "إضافة المستخدمين للأدمن فقط" });
  }

  // ---- what is being asked? ----
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return reply(400, { error: "البيانات المرسلة غير صحيحة" });
  }

  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  const role = String(body.role ?? "");
  const projectId = body.project_id ? String(body.project_id) : null;

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return reply(400, { error: "اكتب بريداً إلكترونياً صحيحاً" });
  }
  if (!ALLOWED_ROLES.includes(role)) {
    return reply(400, { error: "الدور المطلوب غير معروف" });
  }
  if (role === "engineer" && !projectId) {
    return reply(400, { error: "اختر المشروع الخاص بمهندس الموقع" });
  }

  // ---- create the login account (skipped when it already exists) ----
  let created = false;
  if (password) {
    if (password.length < 8) {
      return reply(400, { error: "كلمة المرور لازم تكون 8 حروف على الأقل" });
    }
    const { error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (error) {
      const msg = String(error.message ?? "");
      if (!/already been registered|already registered/i.test(msg)) {
        return reply(400, { error: "تعذر إنشاء الحساب: " + msg });
      }
    } else {
      created = true;
    }
  }

  // ---- and its role ----
  const { error: roleErr } = await admin.from("user_roles").upsert(
    {
      email,
      role,
      project_id: role === "engineer" ? projectId : null,
      disabled: false,
    },
    { onConflict: "email" },
  );
  if (roleErr) {
    return reply(500, {
      error: created
        ? "الحساب اتعمل بس تعذر حفظ الدور: " + roleErr.message
        : "تعذر حفظ الدور: " + roleErr.message,
    });
  }

  return reply(200, { ok: true, created, email });
});
