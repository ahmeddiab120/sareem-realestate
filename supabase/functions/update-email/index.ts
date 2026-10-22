// SAREEM — change a user's login email without losing anything attached to it.
//
// In this project the email IS the identity: `user_roles` is keyed by email,
// every RLS policy resolves the caller through `auth.jwt()->>'email'`, and the
// change log stores `actor_email`. Changing the address in Supabase Auth alone
// would therefore strip the person of their role and orphan their history. This
// function moves all three in one go, and rolls the auth change back if the role
// row refuses to move.
//
// An admin may change anyone's address; anyone signed in may change their own.
//
// Deploy: Supabase dashboard -> Edge Functions -> create `update-email` ->
// paste this file -> Deploy. Then in the function's Settings turn
// "Verify JWT" OFF: the browser sends a preflight OPTIONS request that carries
// no token, and the platform would reject it before this code runs. Nothing is
// lost by turning it off — the checks below are the real gate.

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

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// auth.users can only be read a page at a time, and there is no lookup by email
async function findAuthUserId(
  admin: SupabaseClient,
  email: string,
): Promise<string | null> {
  for (let page = 1; page <= 50; page++) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });
    if (error) throw new Error(error.message);
    const users = data?.users ?? [];
    const hit = users.find((u) => String(u.email ?? "").toLowerCase() === email);
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

  if (!me || me.disabled) {
    return reply(403, { error: "هذا الحساب موقوف أو غير معروف" });
  }
  const isAdmin = me.role === "admin";

  // ---- which account, and to what address? ----
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return reply(400, { error: "البيانات المرسلة غير صحيحة" });
  }

  // no address sent means "mine", which is what the profile page does
  const oldEmail = String(body.email ?? callerEmail).trim().toLowerCase();
  const newEmail = String(body.new_email ?? "").trim().toLowerCase();

  if (!EMAIL_RE.test(newEmail)) {
    return reply(400, { error: "اكتب بريداً إلكترونياً صحيحاً" });
  }
  if (newEmail === oldEmail) {
    return reply(400, { error: "البريد الجديد هو نفسه الحالي" });
  }

  const self = oldEmail === callerEmail;
  if (!self && !isAdmin) {
    return reply(403, { error: "تغيير بريد مستخدم آخر للأدمن فقط" });
  }

  // ---- is the new address free? ----
  const { data: taken } = await admin
    .from("user_roles")
    .select("email")
    .eq("email", newEmail)
    .maybeSingle();
  if (taken) {
    return reply(400, { error: "هذا البريد مستخدم لحساب آخر في الموقع — اختر بريداً غيره" });
  }

  let userId: string | null = null;
  try {
    userId = await findAuthUserId(admin, newEmail);
  } catch (e) {
    return reply(500, { error: "تعذر البحث في الحسابات: " + String(e) });
  }
  if (userId) {
    return reply(400, { error: "هذا البريد مسجَّل لحساب دخول آخر — اختر بريداً غيره" });
  }

  let oldUserId: string | null = null;
  try {
    oldUserId = await findAuthUserId(admin, oldEmail);
  } catch (e) {
    return reply(500, { error: "تعذر البحث عن الحساب: " + String(e) });
  }

  // ---- move the login account first, so a failure here changes nothing ----
  if (oldUserId) {
    const { error } = await admin.auth.admin.updateUserById(oldUserId, {
      email: newEmail,
      // without this the account would sit waiting for a confirmation email and
      // the new address could not sign in at all
      email_confirm: true,
    });
    if (error) {
      const msg = String(error.message ?? "");
      if (/already been registered|already registered/i.test(msg)) {
        return reply(400, { error: "هذا البريد مسجَّل لحساب دخول آخر — اختر بريداً غيره" });
      }
      return reply(500, { error: "تعذر تغيير البريد: " + msg });
    }
  }

  // ---- then the role row, which is keyed by that same address ----
  const { error: roleErr } = await admin
    .from("user_roles")
    .update({ email: newEmail })
    .eq("email", oldEmail);
  if (roleErr) {
    // the account would otherwise be reachable by an address the site knows
    // nothing about — put it back exactly as it was
    if (oldUserId) {
      await admin.auth.admin.updateUserById(oldUserId, {
        email: oldEmail,
        email_confirm: true,
      });
    }
    return reply(500, { error: "تعذر نقل الدور، وتم إرجاع البريد كما كان: " + roleErr.message });
  }

  // ---- and the change log, so past actions stay attached to the person ----
  // the log table is optional (audit-log.sql may not have been run yet), and a
  // failure here must not undo a change that already succeeded
  let historyMoved = false;
  try {
    const { error } = await admin
      .from("audit_log")
      .update({ actor_email: newEmail })
      .eq("actor_email", oldEmail);
    historyMoved = !error;
  } catch {
    historyMoved = false;
  }

  return reply(200, {
    ok: true,
    self,
    old_email: oldEmail,
    new_email: newEmail,
    account_updated: !!oldUserId,
    history_moved: historyMoved,
  });
});
