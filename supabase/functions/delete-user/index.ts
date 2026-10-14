// SAREEM — permanently remove a user straight from the site's users page.
//
// Deleting the row in `user_roles` only takes the role away: the login account
// stays in Supabase Auth, and the next time that person signs in the site
// re-registers them as "pending". This function removes both, and it is the only
// place the secret service key is used — it never leaves Supabase's own server.
//
// Deploy: Supabase dashboard -> Edge Functions -> create `delete-user` ->
// paste this file -> Deploy. Then in the function's Settings turn
// "Verify JWT" OFF: the browser sends a preflight OPTIONS request that carries
// no token, and the platform would reject it before this code runs. Nothing is
// lost by turning it off — the admin check below is the real gate, and a caller
// without a valid admin token gets 401/403.

import { createClient, type SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

const PROJECT_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const SITE_ORIGIN = "https://ahmeddiab120.github.io";

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

// auth.users can only be read a page at a time, and there is no lookup by email
async function findAuthUserId(
  admin: SupabaseClient,
  email: string,
): Promise<string | null> {
  for (let page = 1; page <= 50; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });
    if (error) throw new Error(error.message);
    const users = data?.users ?? [];
    const hit = users.find(
      (u) => String(u.email ?? "").toLowerCase() === email,
    );
    if (hit) return hit.id;
    if (users.length < 100) break;
  }
  return null;
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
    return reply(403, { error: "حذف المستخدمين للأدمن فقط" });
  }

  // ---- who is being removed? ----
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return reply(400, { error: "البيانات المرسلة غير صحيحة" });
  }

  const email = String(body.email ?? "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return reply(400, { error: "اكتب بريداً إلكترونياً صحيحاً" });
  }
  if (email === callerEmail) {
    return reply(400, { error: "لا يمكنك حذف حسابك أنت" });
  }

  // re-checked here because the browser's own guards can be bypassed
  const { data: others, error: countErr } = await admin
    .from("user_roles")
    .select("email")
    .eq("role", "admin")
    .eq("disabled", false)
    .neq("email", email);
  if (countErr) return reply(500, { error: "تعذر التحقق من الأدمن: " + countErr.message });
  if ((others?.length ?? 0) === 0) {
    return reply(400, { error: "لا يمكن حذف آخر أدمن في النظام" });
  }

  // ---- the login account first, so a failure here leaves the role row behind ----
  let userId: string | null = null;
  try {
    userId = await findAuthUserId(admin, email);
  } catch (e) {
    return reply(500, { error: "تعذر البحث عن الحساب: " + String(e) });
  }

  if (userId) {
    const { error } = await admin.auth.admin.deleteUser(userId);
    if (error) {
      return reply(500, { error: "تعذر حذف الحساب: " + error.message });
    }
  }

  const { error: roleErr } = await admin
    .from("user_roles")
    .delete()
    .eq("email", email);
  if (roleErr) {
    return reply(500, {
      error: userId
        ? "الحساب اتمسح بس تعذر حذف الدور: " + roleErr.message
        : "تعذر حذف الدور: " + roleErr.message,
    });
  }

  return reply(200, { ok: true, email, account_deleted: !!userId });
});
