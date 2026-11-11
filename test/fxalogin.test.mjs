// Foxhole's own sign-in in a terminal (fxalogin.ts): the password stretched as Mozilla's onepw protocol has it, the
// email's case put right, a blocked sign-in's unblock code, and the session confirmed by an email's or an app's code.
import assert from "node:assert";
import { authPW, confirmLogin, login, sendUnblock } from "../dist/fxalogin.js";

// onepw's own test vector
assert.equal(await authPW("andré@example.org", "pässwörd"), "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375");

// Mozilla, stubbed: the account is Me@example.com; the first sign-in is blocked till the unblock code comes
const calls = [];
let totp = false; // the account has an authenticator app
const good = await authPW("Me@example.com", "pw");
globalThis.fetch = async (url, init) => {
  const path = new URL(url).pathname.replace("/v1", "");
  const body = JSON.parse(init.body);
  calls.push({ path, body, hawk: !!init.headers.authorization });
  const answer = (status, data) => new Response(JSON.stringify(data), { status });
  if (path === "/account/login") {
    if (body.email !== "Me@example.com") return answer(400, { errno: 120, email: "Me@example.com" });
    if (body.authPW !== good) return answer(400, { errno: 103 });
    if (body.unblockCode !== "ABCD1234") return answer(400, { errno: 125, verificationMethod: "email-captcha" });
    return answer(200, { uid: "u1", sessionToken: "ab".repeat(32), verified: false, verificationMethod: totp ? "totp-2fa" : "email-otp" });
  }
  if (path === "/account/login/send_unblock_code") return answer(200, {});
  if (path === "/session/verify_code") return body.code === "123456" ? answer(200, {}) : answer(400, { errno: 183 });
  if (path === "/session/verify/totp") return answer(200, { success: body.code === "654321" });
  return answer(404, {});
};

await assert.rejects(login("me@example.com", "wrong"), (e) => e.errno === 103 && /password isn't right/.test(e.message));
await assert.rejects(login("me@example.com", "pw"), (e) => e.errno === 125);
await sendUnblock("me@example.com");
const s = await login("me@example.com", "pw", "ABCD1234");
assert.deepEqual(s, { uid: "u1", email: "Me@example.com", sessionToken: "ab".repeat(32), confirm: "email" });
assert.ok(!calls.some((c) => "password" in c.body || JSON.stringify(c.body).includes('"pw"')), "the password itself is never sent");
await assert.rejects(confirmLogin(s, "000000"), (e) => e.errno === 183);
await confirmLogin(s, "123 456");
assert.ok(calls.at(-1).hawk, "the code is sent signed with the session");

// with an authenticator app
totp = true;
const t = await login("Me@example.com", "pw", "ABCD1234");
assert.equal(t.confirm, "totp");
await assert.rejects(confirmLogin(t, "111111"), /authenticator app/);
await confirmLogin(t, "654321");
console.log("ok - Mozilla sign-in in a terminal: the password stretched (never sent), its email's case, an unblock code, an email's and an app's code");
