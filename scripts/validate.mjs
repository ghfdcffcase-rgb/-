import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

const root = process.cwd();
const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
  else console.log("PASS", message);
};

const htmlPath = join(root, "index.html");
check(existsSync(htmlPath), "index.html exists");
if (existsSync(htmlPath)) {
  const html = readFileSync(htmlPath, "utf8");
  const requiredIds = [
    "profileGrid", "profileForm", "adminPage", "adminDashboard",
    "audioPage", "audioStart", "audioGuestButton", "audioRoomsList",
  ];
  for (const id of requiredIds) {
    check(new RegExp('\\bid=["\\']' + id + '["\\']').test(html), `required UI element #${id} exists`);
  }

  const inlineScripts = [...html.matchAll(/<script\\b([^>]*)>([\\s\\S]*?)<\\/script>/gi)]
    .filter(([, attrs]) => !/\\bsrc\\s*=/.test(attrs))
    .map(([, attrs, source], index) => ({ attrs, source, index }));
  check(inlineScripts.length > 0, "inline application scripts are present");

  for (const script of inlineScripts) {
    try {
      new vm.Script(script.source, { filename: `index.html:inline-script-${script.index + 1}` });
      console.log("PASS", `inline script ${script.index + 1} parses`);
    } catch (error) {
      failures.push(`inline script ${script.index + 1} syntax error: ${error.message}`);
    }
  }

  check(!/service_role_[A-Za-z0-9_-]{20,}/i.test(html), "no Supabase service-role secret is embedded in the browser HTML");
  check(/auth\\.signInWithPassword\\(\\{email:address,password:secret\\}\\)/.test(html), "email/password sign-in flow is present");
  check(/functions\\.invoke\\(['"]mithaq-live-audio['"]/.test(html), "live audio calls the Supabase Edge Function");
  check(/auth\\.getSession\\(\\)/.test(html), "client checks for a valid auth session");
}

const migrationDir = join(root, "supabase", "migrations");
if (existsSync(migrationDir)) {
  const migrations = readdirSync(migrationDir).filter((name) => name.endsWith(".sql"));
  check(migrations.length > 0, "Supabase migrations directory contains SQL migrations");
  for (const name of migrations) {
    const sql = readFileSync(join(migrationDir, name), "utf8");
    if (/member_usernames/i.test(sql)) {
      check(/enable row level security/i.test(sql), `${name}: member usernames has RLS enabled`);
      check(/revoke all on public\\.member_usernames from anon, authenticated/i.test(sql), `${name}: member usernames is not directly exposed to browser roles`);
    }
  }
} else {
  check(false, "Supabase migrations directory exists");
}

if (failures.length) {
  console.error("\\nValidation failed:");
  for (const failure of failures) console.error("-", failure);
  process.exitCode = 1;
} else {
  console.log("\\nAll MITHAQ repository checks passed.");
}
