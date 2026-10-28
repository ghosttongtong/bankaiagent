/**
 * 网关身份边界验证(A1–A10)——「谁的请求、谁在动谁的钱」。
 *
 * ★ 这一组验证要回答的,正是本次修补的核心问题:
 *   过去 customerId 取自**请求体**,于是任何人只要把别人的客户号写进 body,
 *   就能看别人的账单、动别人的钱 —— 这不是"没登录",而是**横向越权**。
 *
 * 验证方式刻意与前端一致:
 *   · 用**Cookie 罐**模拟浏览器(前端一行都不用改,靠的是服务端 Set-Cookie);
 *   · 不带任何自定义鉴权头(前端也没有这种东西);
 *   · CORS、CSRF、越权、回执归属,逐条用真实 HTTP 请求打。
 *
 * 用法:node tools/verify-auth.mjs
 */
import "dotenv/config";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { startServer } = await import("../packages/server/src/index.ts");

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};

/**
 * 极简 Cookie 罐 —— 就是浏览器对 Cookie 做的那件事:
 * 收到 Set-Cookie 存下来,后续同源请求自动带上。
 *
 * ★ 为什么不用手写"把令牌塞进 Authorization 头":
 *   因为前端**没有**那个头。用自定义头去验证,验证的就不是前端走的这条路。
 */
function makeJar() {
  const jar = new Map();
  return {
    apply(headers) {
      if (jar.size === 0) return;
      headers["cookie"] = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    },
    absorb(res) {
      for (const raw of res.headers.getSetCookie?.() ?? []) {
        const [pair] = raw.split(";");
        const eq = pair.indexOf("=");
        if (eq < 0) continue;
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (value === "" || /Max-Age=0/i.test(raw)) jar.delete(name);
        else jar.set(name, value);
      }
    },
    has: (name) => jar.has(name),
    names: () => [...jar.keys()],
  };
}

const dirs = () => ({
  auditDir: join(baseDir, `audit-${Math.random().toString(36).slice(2, 8)}`),
  personalizationDir: join(baseDir, `pers-${Math.random().toString(36).slice(2, 8)}`),
  sessionsDir: join(baseDir, `sess-${Math.random().toString(36).slice(2, 8)}`),
});
const baseDir = await mkdtemp(join(tmpdir(), "va-"));
const dirsMain = dirs();
const dirsStrict = dirs();

let server = await startServer({ offline: true, port: 0, ...dirsMain });
let base = `http://127.0.0.1:${server.port}`;

/** 发一个请求:jar 自动带上 Cookie,自动吸收 Set-Cookie */
async function req(jar, path, options = {}) {
  const headers = { ...(options.headers ?? {}) };
  if (options.body != null) headers["Content-Type"] = "application/json";
  jar?.apply(headers);
  if (options.origin) headers["origin"] = options.origin;
  if (options.secFetchSite) headers["sec-fetch-site"] = options.secFetchSite;
  const res = await fetch(base + path, {
    method: options.method ?? (options.body != null ? "POST" : "GET"),
    headers,
    ...(options.body != null ? { body: JSON.stringify(options.body) } : {}),
  });
  jar?.absorb(res);
  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text.slice(0, 200) };
  }
  return { status: res.status, data, headers: res.headers, res };
}

const chain = () => server.app.audit.readAll();
const denials = async (kind) => (await chain()).filter((e) => e.type === "auth_denied" && e.payload?.kind === kind);
const say = (jar, text, sessionId) => req(jar, "/api/channels/app/messages", { body: { text, ...(sessionId ? { sessionId } : {}) } });

const SPOUSE = server.app.world.spouseCustomerId;
const PRIMARY = server.app.world.primaryCustomerId;

console.log(`\n### 网关身份边界验证(base=${base},默认客户=${PRIMARY},另一客户=${SPOUSE})`);

// ============================================================================
// A1. 前端零改动:不带任何 Cookie 的首次访问能被引导出一个会话
// ============================================================================
console.log("\n1. A1 前端零改动(不带 Cookie 的首次访问)");
const anon = makeJar();
const homepage = await req(anon, "/");
check(homepage.status === 200, `GET / 未登录即可打开(App 入口在鉴权之前:`);
check(!anon.has("ba_session"), "静态页面本身不签发身份(它是公开内容)");

const p1 = await req(anon, "/api/demo/profile");
check(p1.status === 200, `首次 /api/demo/profile 成功(HTTP ${p1.status})`);
check(anon.has("ba_session"), "★ 服务端下发了 HttpOnly 会话 Cookie(身份诞生)");
check(p1.data.customerId === PRIMARY, `引导出的身份是**默认演示客户**(${p1.data.customerId})`);
const bootEvents = (await chain()).filter((e) => e.type === "auth_session_issued" && e.payload?.kind === "demo_bootstrap");
check(bootEvents.length > 0, `auth_session_issued(demo_bootstrap) 已入哈希链(${bootEvents.length} 条)`);

const who = await req(anon, "/api/auth/whoami");
check(who.data.customerIdSource === "session_token", "whoami 明确标注身份来源 = session_token");

// ============================================================================
// A2. 横向越权的正题:请求体里的 customerId 不再被采信
// ============================================================================
console.log("\n2. A2 请求体里带别人的 customerId → 拒绝 + 落审计");
const sessionId = `va-${Math.random().toString(36).slice(2, 8)}`;
const before = await req(anon, "/api/demo/profile");
const balBefore = before.data.accounts.reduce((s, a) => s + a.balance, 0);

const evilSay = await say(anon, "给老妈转500", sessionId);
check(evilSay.status === 200, "对照组:正常说一句话是通的(说明拦截的是身份,不是功能)");

const hijack = await req(anon, "/api/channels/app/messages", {
  body: { customerId: SPOUSE, text: "给老妈转500", sessionId },
});
check(hijack.status === 403, `★ 带别人 customerId 的消息被拒(HTTP ${hijack.status})`);
check(/不一致/.test(String(hijack.data.error)), `拒绝理由明确:${hijack.data.error}`);

const hijackQuery = await req(anon, `/api/demo/profile?customerId=${encodeURIComponent(SPOUSE)}`);
check(hijackQuery.status === 403, "★ 查询串里带别人 customerId 的 GET 同样被拒(不是只堵了 body)");

const hijackLedger = await req(anon, `/api/ledger/recent?customerId=${encodeURIComponent(SPOUSE)}`);
check(hijackLedger.status === 403, "★ 台账查询也拒(越权最容易被忽视的一类:只读接口)");

const crossDenials = await denials("cross_customer");
check(crossDenials.length >= 3, `auth_denied(cross_customer) 已入哈希链(${crossDenials.length} 条)`);
const first = crossDenials[0];
check(
  first?.payload?.claimedCustomerId === SPOUSE && first?.payload?.identityCustomerId === PRIMARY,
  `★ 审计里**同时**记下「声称是谁」与「令牌里其实是谁」(${first?.payload?.claimedCustomerId} vs ${first?.payload?.identityCustomerId})`,
);
check(first?.payload?.claimSource?.startsWith("body.") || first?.payload?.claimSource?.startsWith("query."), `记录声称来自哪里(${first?.payload?.claimSource})`);

const afterBlocked = await req(anon, "/api/demo/profile");
const balAfterBlocked = afterBlocked.data.accounts.reduce((s, a) => s + a.balance, 0);
check(balAfterBlocked === balBefore, "★ 越权请求没有造成任何资金变动");

// ============================================================================
// A3. 审计面板按身份过滤(看不到别人的证据链)
// ============================================================================
console.log("\n3. A3 /api/audit/recent 只返回自己的事件");
const myAudit = await req(anon, "/api/audit/recent?limit=500");
check(myAudit.data.scope === "own_customer", `scope = ${myAudit.data.scope}`);
/**
 * ★ 判据用 traceId 集合比对,而不是"文本里有没有出现另一个客户号":
 *   越权**尝试**的审计事件本来就记在发起者名下,payload 里会带"他声称是谁"。
 *   那是应该被看到的证据;要证明的是"没有别人的业务事件混进来"。
 */
const myTraceIds = new Set((await chain()).filter((e) => e.customerId === PRIMARY).map((e) => e.traceId));
const leaked = myAudit.data.events.filter((e) => !myTraceIds.has(e.traceId));
check(leaked.length === 0, `★ 返回的 ${myAudit.data.events.length} 条事件全部属于当前身份(越界 ${leaked.length} 条)`);

// ============================================================================
// A4. CORS:白名单,不再是 *
// ============================================================================
console.log("\n4. A4 CORS 白名单(不再是 *)");
const evilOrigin = await req(anon, "/api/demo/profile", { origin: "http://evil.example" });
check(evilOrigin.status === 403, `★ 白名单外来源被拒(HTTP ${evilOrigin.status})`);
check(
  !String(evilOrigin.headers.get("access-control-allow-origin") ?? "").includes("*"),
  "★ 被拒响应里没有 Access-Control-Allow-Origin: *(浏览器侧不再是'谁都能读')",
);
check((await denials("origin_not_allowed")).length > 0, "auth_denied(origin_not_allowed) 已入哈希链");
/**
 * ★ 没有身份时的拒绝记在 `anonymous` 名下 —— 它仍然进哈希链(证据不能丢),
 *   但**不会**出现在任何客户的审计面板里(否则"谁在扫我的接口"会变成"我能看别人的攻击日志")。
 */
const anonymousDenials = (await chain()).filter((e) => e.type === "auth_denied" && e.customerId === "anonymous");
const mineNow = await req(anon, "/api/audit/recent?limit=500");
check(anonymousDenials.length > 0, `匿名拒绝事件留在全局哈希链(${anonymousDenials.length} 条)`);
check(
  !mineNow.data.events.some((e) => anonymousDenials.some((a) => a.traceId === e.traceId)),
  "★ 匿名拒绝不进任何客户的审计面板(不泄露别人的攻击痕迹)",
);

const goodOrigin = await req(anon, "/api/demo/profile", { origin: base });
check(goodOrigin.status === 200, "白名单内来源正常");
check(goodOrigin.headers.get("access-control-allow-origin") === base, `白名单内来源被精确回显(${base})`);
check(String(goodOrigin.headers.get("vary") ?? "").includes("Origin"), "带 Vary: Origin(缓存不会串来源)");
check(goodOrigin.headers.get("access-control-allow-credentials") === "true", "允许携带凭据(Cookie)");

const noOrigin = await req(anon, "/api/health");
check(noOrigin.headers.get("access-control-allow-origin") == null, "没有 Origin 的请求不发 CORS 头(不是无条件发 *)");

// ============================================================================
// A5. CSRF:跨站写请求被拒
// ============================================================================
console.log("\n5. A5 CSRF(跨站写请求)");
const crossSite = await req(anon, "/api/channels/app/messages", {
  body: { text: "给老妈转500", sessionId },
  secFetchSite: "cross-site",
});
check(crossSite.status === 403, `★ Sec-Fetch-Site: cross-site 的写请求被拒(HTTP ${crossSite.status})`);
check((await denials("csrf_rejected")).some((e) => e.payload?.detail?.includes("cross-site")), "auth_denied(csrf_rejected) 已入哈希链");

const badCsrf = await req(anon, "/api/channels/app/messages", {
  body: { text: "给老妈转500", sessionId },
  headers: { "x-csrf-token": "deadbeef" },
});
check(badCsrf.status === 403, "★ 双提交令牌不匹配同样被拒(带了就必须对)");

const sameOrigin = await req(anon, "/api/channels/app/messages", {
  body: { text: "给老妈转500", sessionId },
  origin: base,
  secFetchSite: "same-origin",
});
check(sameOrigin.status === 200, "同源 + same-origin 的正常写请求不受影响(没有误伤)");

// ============================================================================
// A6. 强验证回执:只签给"本会话身份名下、未执行的待办"
// ============================================================================
console.log("\n6. A6 sign-auth-proof 不再是通用签名预言机");
/**
 * ★ 任意载荷哈希必须拿不到回执,但**拒绝的方式取决于服务端当前状态**,两种都正确:
 *   · 没有可签的待办 → 403 sign_proof_target_missing(根本无对象可签);
 *   · 有别人的待办在场 → 409 sign_proof_hash_mismatch(对象由服务端认定,提交的哈希只作核对)。
 *   关键是:**签名对象永远由服务端认定**,客户端提交的哈希改变不了它。
 */
const arbitrary = await req(anon, "/api/demo/sign-auth-proof", {
  body: { method: "biometric", payloadHash: "0".repeat(64) },
});
check(arbitrary.status === 403 || arbitrary.status === 409, `★ 任意 payloadHash 拿不到回执(HTTP ${arbitrary.status})`);
const signDenials = [
  ...(await denials("sign_proof_target_missing")),
  ...(await denials("sign_proof_hash_mismatch")),
];
check(signDenials.length > 0, `auth_denied(${signDenials[0]?.payload?.kind}) 已入哈希链`);

// 前端真实路径:发起一笔 → 按 refId 取载荷 → 签发回执 → 确认执行
const transfer = await say(anon, "给老妈转500", sessionId);
check(transfer.data.turn?.promptFor?.kind === "confirm", `发起转账产生待确认动作(${transfer.data.turn?.promptFor?.kind})`);
const refId = transfer.data.turn.promptFor.refId;
const pending = await req(anon, `/api/demo/pending?refId=${encodeURIComponent(refId)}`);
check(Boolean(pending.data.pending?.payloadHash), "按 refId 能取到冻结载荷哈希(与前端验证弹层同一条路径)");

/**
 * ★ 归属校验:另一个客户(登录成配偶)拿**我的**载荷哈希来换回执 → 必须被拒。
 *
 * 为什么用这个方向:配偶在演示数据里没有账户(所以发不出自己的转账),
 * 而"非拥有者拿别人的哈希"恰恰就是这条规则要挡的攻击 ——
 * 拿到一份合法回执再配合越权确认去动别人的钱。
 */
const spouse = makeJar();
const spouseLogin = await req(spouse, "/api/auth/login", {
  body: { customerId: SPOUSE, password: process.env.AUTH_DEMO_PASSWORD ?? "demo-pass" },
});
check(spouseLogin.status === 200, `配偶客户登录成功(HTTP ${spouseLogin.status})`);
check(spouseLogin.data.customerId === SPOUSE, "登录后身份就是该客户本人");
const spouseWho = await req(spouse, "/api/auth/whoami");
check(spouseWho.data.customerId === SPOUSE, "★ 同一个浏览器里换了个人登录,身份随之改变(令牌说了算,不是请求体)");

const stealProof = await req(spouse, "/api/demo/sign-auth-proof", {
  body: { method: "biometric", payloadHash: pending.data.pending.payloadHash },
});
check(stealProof.status === 403, `★ 拿别人的载荷哈希换不到回执(HTTP ${stealProof.status})`);
check(
  (await denials("sign_proof_not_owner")).some((e) => e.payload?.ownerCustomerId === PRIMARY),
  "auth_denied(sign_proof_not_owner) 已入哈希链(记下了待办真正的主人)",
);

// 自己那一笔:签发成功,并且能真正执行
const proof = await req(anon, "/api/demo/sign-auth-proof", {
  body: { method: "biometric", payloadHash: pending.data.pending.payloadHash },
});
check(proof.status === 200 && Boolean(proof.data.proof?.signature), "自己的待办正常签发回执");
const confirm = await req(anon, "/api/channels/app/actions", {
  body: { sessionId, action: { kind: "confirm", refId, ...(proof.data.proof ? { authProof: proof.data.proof } : {}) } },
});
check(/已向|转账成功/.test(String(confirm.data.turn?.reply ?? "")), `确认后正常执行:${String(confirm.data.turn?.reply ?? "").split("\n")[0]}`);

// ============================================================================
// A7. 登录:凭据校验 + 失败节流,且每一次拒绝都进哈希链
// ============================================================================
console.log("\n7. A7 登录与失败节流");
const attacker = makeJar();
const badPass = await req(attacker, "/api/auth/login", { body: { customerId: PRIMARY, password: "wrong-password" } });
check(badPass.status === 401, `口令错误返回 401(HTTP ${badPass.status})`);
check(/不正确/.test(String(badPass.data.error)), "对外只说「客户号或口令不正确」(不区分客户是否存在,避免账号枚举)");
check((await denials("bad_credential")).length > 0, "auth_denied(bad_credential) 已入哈希链");

const unknown = await req(attacker, "/api/auth/login", { body: { customerId: "CUST-NOT-EXIST", password: "wrong-password" } });
check(unknown.status === 401 && String(unknown.data.error) === String(badPass.data.error), "★ 不存在的客户返回**完全相同**的文案(枚举不出客户号)");

const realLogin = makeJar();
const okLogin = await req(realLogin, "/api/auth/login", {
  body: { customerId: PRIMARY, password: process.env.AUTH_DEMO_PASSWORD ?? "demo-pass" },
});
check(okLogin.status === 200, "正确凭据登录成功");
check(realLogin.has("ba_session"), "登录后拿到会话 Cookie");

const logout = await req(realLogin, "/api/auth/logout", { body: {} });
check(logout.status === 200 && logout.data.revoked === true, "登出由**服务端**撤销会话(不是让客户端自己删 Cookie)");
check((await chain()).some((e) => e.type === "auth_session_revoked"), "auth_session_revoked 已入哈希链");

// ★ 冷静期放在最后:一旦锁上,连正确口令也不该放行(否则锁定只是"少回一句话")
let lockedAt = 0;
for (let i = 0; i < 6; i++) {
  const r = await req(attacker, "/api/auth/login", { body: { customerId: PRIMARY, password: `wrong-${i}` } });
  if (r.status === 429 && lockedAt === 0) lockedAt = i + 1;
}
check(lockedAt > 0, `★ 连续失败后进入冷静期(第 ${lockedAt} 次起返回 429)`);
check((await denials("login_locked")).length > 0, "auth_denied(login_locked) 已入哈希链(拒绝也在链上,不是 HTTP 层的静默 429)");
const stillLocked = await req(attacker, "/api/auth/login", {
  body: { customerId: PRIMARY, password: process.env.AUTH_DEMO_PASSWORD ?? "demo-pass" },
});
check(stillLocked.status === 429, `★ 冷静期内**正确口令**也被拒(HTTP ${stillLocked.status})—— 锁定先于口令校验,才真正降低尝试速率`);

// ============================================================================
// A8. 严格模式:连默认演示身份也要登录
// ============================================================================
console.log("\n8. A8 严格模式(AUTH_REQUIRE_LOGIN=1)");
process.env.AUTH_REQUIRE_LOGIN = "1";
const strict = await startServer({ offline: true, port: 0, ...dirsStrict });
process.env.AUTH_REQUIRE_LOGIN = "0";
const savedBase = base;
const savedServer = server;
base = `http://127.0.0.1:${strict.port}`;
server = strict;

const strictAnon = makeJar();
const strictDenied = await req(strictAnon, "/api/demo/profile");
check(strictDenied.status === 401, `★ 严格模式下未登录请求被拒(HTTP ${strictDenied.status})`);
check(!strictAnon.has("ba_session"), "★ 严格模式下不签发任何演示身份(引导关闭)");
check((await denials("no_session")).length > 0, "auth_denied(no_session) 已入哈希链");

const strictLogin = await req(strictAnon, "/api/auth/login", {
  body: { customerId: PRIMARY, password: process.env.AUTH_DEMO_PASSWORD ?? "demo-pass" },
});
check(strictLogin.status === 200, "严格模式下登录后可用");
const strictProfile = await req(strictAnon, "/api/demo/profile");
check(strictProfile.status === 200 && strictProfile.data.customerId === PRIMARY, "登录后接口恢复正常");

// ★ 伪造令牌:改一个字符即失效,且留下证据
const forged = makeJar();
const cookieName = "ba_session";
const token = strictAnon.names().includes(cookieName) ? strictLogin.res.headers.getSetCookie().find((c) => c.startsWith(cookieName)).split(";")[0] : "";
const forgedToken = token.slice(0, -1) + (token.endsWith("a") ? "b" : "a");
const forgedRes = await fetch(`${base}/api/demo/profile`, { headers: { cookie: forgedToken } });
check(forgedRes.status === 401, `★ 篡改过的令牌被拒(HTTP ${forgedRes.status})`);
check((await denials("invalid_session")).length > 0, "auth_denied(invalid_session) 已入哈希链");

// ---- 恢复主服务器,做收尾校验 ----
await strict.close();
base = savedBase;
server = savedServer;

// ============================================================================
// A9. 哈希链完整性
// ============================================================================
console.log("\n9. A9 审计链完整性");
const verification = await server.app.audit.verifyChain();
check(verification.intact, `哈希链完整(${(await chain()).length} 条事件,链未断)`);
const auditEndpoint = await req(anon, "/api/audit/verify");
check(auditEndpoint.status === 200 && auditEndpoint.headers.get("access-control-allow-origin") !== "*", "链校验结论可全局读取,且不泄露内容");

await server.close();

console.log(`\n${failed === 0 ? "✅ 全部通过" : `❌ ${failed} 项失败`}\n`);
process.exit(failed === 0 ? 0 : 1);