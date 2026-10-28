/**
 * 会话与台账接口验证(31 文档 §9 的 S1–S12 + 两个台账接口)。
 *
 * ★ 为什么自己起一个服务(而不是连现成的 87xx 网关):
 *   ① S11 要验证"重启后仍在",必须能关掉再起一个实例;
 *   ② 验证必须用**临时目录**(红线 #9),不能污染 var/;
 *   ③ 端口用 0 让系统分配,与别的会话不抢端口。
 *
 * 用法:node tools/verify-sessions.mjs
 */
import "dotenv/config";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { startServer } = await import("../packages/server/src/index.ts");
/**
 * ★ 频次档位:验证脚本要在几十秒内连做十几笔资金/凭证操作 ——
 *   那是**脚本的节奏**,不是客户的节奏(出厂档:转账 5 分钟 ≤3 次)。
 *   于是这里显式装上叙事档(只放宽次数上限,不放宽类别/窗口/判据)。
 *
 *   为什么必须显式装、而不是"碰巧没触发就不用管":
 *   不装的话,第 4 笔转账会被 `R-FREQUENCY-LIMIT` 拦下 → 这一笔没有待办 →
 *   后面一连串「确认」相关的断言全部失败,而失败原因看起来像"会话待办丢了"。
 *   限流本身由 `tools/verify-auth.mjs` 与 redteam 的《频次硬规则》套件专门验证。
 */
const { configurePolicy, NARRATIVE_FREQUENCY_RULES } = await import("../packages/core/src/index.ts");
configurePolicy({ frequency: [...NARRATIVE_FREQUENCY_RULES] });

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};
const sid = (tag) => `vs-${tag}-${Math.random().toString(36).slice(2, 8)}`;

// ---- 一次性临时目录:三次重启共用同一组目录,才能验证"落盘" ----
const dirs = {
  auditDir: await mkdtemp(join(tmpdir(), "vs-audit-")),
  personalizationDir: await mkdtemp(join(tmpdir(), "vs-pers-")),
  sessionsDir: await mkdtemp(join(tmpdir(), "vs-sess-")),
};

let server = await startServer({ offline: true, port: 0, ...dirs });
let base = `http://127.0.0.1:${server.port}`;

async function getJson(path) {
  const res = await fetch(base + path);
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error ?? `HTTP ${res.status}`);
  return data;
}
async function postJson(path, body) {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error ?? `HTTP ${res.status}`);
  return data;
}

const say = (text, sessionId, channel = "app") =>
  postJson(`/api/channels/${channel}/messages`, { text, sessionId }).then((d) => d.turn);
const act = (action, sessionId, channel = "app") =>
  postJson(`/api/channels/${channel}/actions`, { sessionId, action }).then((d) => d.turn);

let CUST = "";
const detail = (id) => getJson(`/api/sessions/${encodeURIComponent(id)}?customerId=${encodeURIComponent(CUST)}`);
const sessionList = (extra = "") =>
  getJson(`/api/sessions?customerId=${encodeURIComponent(CUST)}${extra}`);
const totalBalance = async () => {
  const p = await getJson("/api/demo/profile");
  return p.accounts.reduce((s, a) => s + a.balance, 0);
};
/** 按 refId 取这一笔的载荷 → 请"安全环境"签发回执(与前端验证弹层同一条路径) */
async function signFor(refId) {
  const r = await getJson(`/api/demo/pending?customerId=${encodeURIComponent(CUST)}&refId=${encodeURIComponent(refId)}`);
  const s = await postJson("/api/demo/sign-auth-proof", { method: "biometric", payloadHash: r.pending.payloadHash });
  return s.proof;
}

console.log(`\n### 会话与台账验证(base=${base})`);
const profile = await getJson("/api/demo/profile");
CUST = profile.customerId;
check(Boolean(CUST), `客户身份可用(${CUST})`);

// ---- S1 / S2 / S3:跨会话的「确认」不能执行别人的待办 ----
console.log("\n1. S1–S3 会话隔离(跨会话确认一律拒绝)");
const sessionA = sid("A");
const sessionB = sid("B");
const tA = await say("给老妈转500", sessionA);
check(tA.promptFor?.kind === "confirm", `A 会话产生待确认动作(${tA.promptFor?.kind})`);
const balBefore = await totalBalance();

const b1 = await say("确认", sessionB);
check(/没有等待您确认|这个对话里没有/.test(b1.reply), `B 会话的「确认」被拒:${String(b1.reply).split("\n")[0]}`);
check((await totalBalance()) === balBefore, "★ B 会话的确认没有动钱");
check((await detail(sessionA)).session.status === "pending", "★ A 会话的待办仍在");

const b2 = await act({ kind: "confirm", refId: tA.promptFor.refId }, sessionB);
check(/另一个对话/.test(b2.reply), `S2 带 A 的 refId 在 B 会话确认被拒:${String(b2.reply).split("\n")[0]}`);
check((await totalBalance()) === balBefore, "★ 带他人 refId 的确认没有动钱");
check((await detail(sessionA)).session.status === "pending", "★ 带他人 refId 被拒后 A 的待办仍在");

const aDone = await act({ kind: "confirm", refId: tA.promptFor.refId }, sessionA);
check(/已向/.test(aDone.reply), `A 会话自己确认后执行成功:${String(aDone.reply).split("\n")[0]}`);
const balAfterA = await totalBalance();
check(balAfterA === balBefore - 500, `只扣了一笔 500(余额 ${balBefore} → ${balAfterA})`);

const b3 = await say("确认", sessionB);
check(/没有找到待确认|没有等待您确认/.test(b3.reply), "S3 办完之后 B 再确认只会得到「没有待办」");
check((await totalBalance()) === balAfterA, "★ S3 没有产生第二笔扣款");

// ---- S4:交互渠道严格、非交互渠道保留唯一待办回退 ----
console.log("\n2. S4 IM 同会话可确认;语音(非交互)保留唯一待办回退");
const sessionIm = sid("IM");
const tIm = await say("给老妈转300", sessionIm);
const imDone = await act({ kind: "confirm", refId: tIm.promptFor.refId }, sessionIm, "im");
check(/已向/.test(imDone.reply), "IM 同会话确认仍可用(严格匹配没误伤正常路径)");

const sessionVoiceA = sid("VA");
const sessionVoiceB = sid("VB");
const tVoice = await say("给老妈转200", sessionVoiceA);
check(tVoice.promptFor?.kind === "confirm", "语音场景的前置待办已创建");
const voiceDone = await say("确认", sessionVoiceB, "voice");
check(/已向/.test(voiceDone.reply), "语音渠道在全客户唯一待办时仍可确认(旧回退只留给非交互渠道)");

// ---- S8:提额(必须抢在挂失之前:挂失会冻结全部卡)----
console.log("\n3. S8 提额会话:submitted + 待银行审核");
const sessionLimit = sid("LIMIT");
const l1 = await say("帮我把尾号 3344 的额度提到 5 万", sessionLimit);
check(l1.promptFor?.kind === "strong_auth", `提额先要求强验证(${l1.promptFor?.kind})`);
const limitProof = await signFor(l1.promptFor.refId);
const l2 = await act({ kind: "confirm", refId: l1.promptFor.refId, authProof: limitProof }, sessionLimit);
check(/申请/.test(l2.reply), `提额申请已提交:${String(l2.reply).split("\n")[0]}`);
const limitDetail = await detail(sessionLimit);
check(limitDetail.session.status === "submitted", `会话状态为 submitted(${limitDetail.session.status})`);
check(/待银行审核/.test(limitDetail.session.statusLabel), `状态文案:${limitDetail.session.statusLabel}`);
const limitOp = limitDetail.session.operations.find((o) => o.capability === "card.limit_adjust");
check(Boolean(limitOp && /目标额度/.test(limitOp.detail ?? "")), `台账 detail 带目标额度:${limitOp?.detail}`);

// ---- S10:改手机号(阻断级,不代理)----
console.log("\n4. S10 改手机号会话:blocked + 未代理");
const sessionPhone = sid("PHONE");
const p1 = await say("帮我改一下手机号", sessionPhone);
check(/不能替您办|安全中心/.test(p1.reply), `改手机号被拦并给出原生入口:${String(p1.reply).split("\n")[0]}`);
const phoneDetail = await detail(sessionPhone);
check(phoneDetail.session.status === "blocked", `会话状态为 blocked(${phoneDetail.session.status})`);
check(/未代理/.test(phoneDetail.session.statusLabel), `状态文案:${phoneDetail.session.statusLabel}`);

// ---- S13 / S14:同一个对话里办多件事 = 多条业务记录 ----
//
// ★ 这一组直接钉住客户提出的那个问题:
//   "我在同一个对话里办不同业务、一天办多个业务,能不能识别成多条历史记录?"
//   答案必须落在**历史列表真正调用的那个接口**上,所以这里查的是
//   /api/ledger/recent(列表数据源),而不是只看会话详情。
console.log("\n5. S13/S14 同一对话多笔业务:一行一笔,状态互不覆盖");
const sessionMulti = sid("MULTI");
// 第 1 笔:转账 —— 它会先产生"待确认",再落定;这正是"一件事的两行事件"
const m1 = await say("给老妈转100", sessionMulti);
check(m1.promptFor?.kind === "confirm", `多业务会话的第 1 笔产生待确认(${m1.promptFor?.kind})`);
const m1done = await act({ kind: "confirm", refId: m1.promptFor.refId }, sessionMulti);
check(/已向/.test(m1done.reply), `第 1 笔办结:${String(m1done.reply).split("\n")[0]}`);
// 第 2 笔:改手机号(阻断级,没有任何副作用)
const m2 = await say("帮我改一下手机号", sessionMulti);
check(/不能替您办|安全中心/.test(m2.reply), `第 2 笔被拦:${String(m2.reply).split("\n")[0]}`);

const multiList = await getJson(
  `/api/ledger/recent?customerId=${encodeURIComponent(CUST)}&current=${encodeURIComponent(sessionMulti)}&limit=100`,
);
const mine = multiList.operations.filter((o) => o.sessionId === sessionMulti);
check(
  mine.length === 2,
  `★ 一个对话里的 2 笔业务 = 2 条记录(${mine.length} 条:${mine.map((o) => o.capability).join(", ")})`,
);
check(
  mine.filter((o) => o.capability === "transfer.submit").length === 1,
  "★ 同一笔转账只占一行(「待你确认」+「已转账成功」已折叠成一笔,没有铺成两行)",
);
check(new Set(mine.map((o) => o.opId)).size === mine.length, "每行的身份是那一笔(opId 互不相同)");
const multiTransfer = mine.find((o) => o.capability === "transfer.submit");
const multiPhone = mine.find((o) => o.capability === "security.change_phone");
check(multiTransfer?.status === "done", `第 1 笔保留自己的终态 done(${multiTransfer?.status})`);
check(/已转账成功/.test(multiTransfer?.statusLabel ?? ""), `第 1 笔的状态文案:${multiTransfer?.statusLabel}`);
check(multiPhone?.status === "blocked", `第 2 笔显示自己的状态 blocked(${multiPhone?.status})`);
check(mine.every((o) => o.isCurrent === true), "两行都被标为本次对话办的(isCurrent)");
check(mine.every((o) => o.sessionId === sessionMulti), "每行都带 sessionId —— 点进去能回放它所属的那次对话");
check(mine.every((o) => o.hasSession === true), "每行都标了 hasSession(所属对话仍在保留期内,可回放)");

const elsewhere = await getJson(
  `/api/ledger/recent?customerId=${encodeURIComponent(CUST)}&current=${encodeURIComponent(sid("OTHER"))}&limit=100`,
);
check(elsewhere.operations.every((o) => o.isCurrent === false), "isCurrent 只在传入的会话上为真");

// ---- 两个粒度并存:列表按业务,会话头仍按"最需关注的一个"聚合 ----
const multiDetail = await detail(sessionMulti);
check(multiDetail.session.status === "blocked", `会话级仍聚合为 blocked(${multiDetail.session.status})`);
check(
  (multiDetail.session.businesses ?? []).filter((o) => o.capability === "transfer.submit").length === 1,
  "详情页的业务清单同样一笔一行(businesses)",
);
check(
  (multiDetail.session.businesses ?? []).some((o) => o.status === "done"),
  "★ 会话级聚合没有吞掉那一笔「已转账成功」(两个粒度并存)",
);

// ---- S7 + S9:挂失即时生效、补卡只是"已受理" ----
console.log("\n6. S7 挂失 done;S9 补卡 submitted + 预计 N 个工作日");
const sessionLoss = sid("LOSS");
await say("卡丢了先挂失", sessionLoss);
const lossDetail = await detail(sessionLoss);
check(lossDetail.session.status === "done", `挂失会话状态为 done(${lossDetail.session.status})`);
check(/已挂失生效/.test(lossDetail.session.statusLabel), `状态文案:${lossDetail.session.statusLabel}`);

const sessionReplace = sid("REPLACE");
await say("卡丢了先挂失", sessionReplace);
await say("尾号 8888 那张补办一下", sessionReplace);
await say("保留原号", sessionReplace);
const replaceDone = await say("确认", sessionReplace);
check(/补卡申请已提交/.test(replaceDone.reply), `补卡提交成功:${String(replaceDone.reply).split("\n")[0]}`);
const replaceDetail = await detail(sessionReplace);
check(replaceDetail.session.status === "submitted", `补卡会话状态为 submitted(${replaceDetail.session.status})`);
const replaceOp = replaceDetail.session.operations.find((o) => o.capability === "card.replace");
check(Boolean(replaceOp && /预计 \d+ 个工作日/.test(replaceOp.detail ?? "")), `补卡 detail 到货时效:${replaceOp?.detail}`);

// ---- S5 / S6:列表与详情(只读、无 pendingId)----
console.log("\n7. S5/S6 列表与详情:状态口径、只读、无 pendingId");
const list = await sessionList(`&current=${encodeURIComponent(sessionA)}`);
const rowA = list.sessions.find((s) => s.sessionId === sessionA);
check(Boolean(rowA), "列表里有 A 会话");
check(rowA?.status === "done", `S5 A 会话 status=done(${rowA?.status})`);
check(rowA?.statusLabel === "已转账成功", `S5 A 会话 statusLabel=${rowA?.statusLabel}`);
check(rowA?.tone === "ok", `列表带 tone(${rowA?.tone})`);
check(rowA?.isCurrent === true, "isCurrent 按 current 参数高亮");
check((rowA?.opCount ?? 0) >= 2, `opCount 统计了台账条目(${rowA?.opCount})`);
check(/¥500\.00/.test(rowA?.summary ?? ""), `副行带金额:${rowA?.summary}`);
check(/流水号/.test(rowA?.summary ?? ""), `副行带流水号:${rowA?.summary}`);

const dA = await detail(sessionA);
check(dA.session.readonly === true, "详情标记 readonly=true");
check(dA.session.turns.length === 4, `详情回放完整(${dA.session.turns.length} 轮)`);
const badTurn = dA.session.turns.find((t) => !t.text || !t.role);
check(!badTurn, `每条 turn 都有角色与文本${badTurn ? ` —— 异常的一条:${JSON.stringify(badTurn)}` : ""}`);
check(
  dA.session.operations.every((o) => !("pendingId" in o)),
  "S6 ★ operations 里没有 pendingId(能看不能办)",
);
check(!("pendingId" in dA.session), "会话详情本身也不带 pendingId");
const doneOp = dA.session.operations.find((o) => o.status === "done" && o.capability === "transfer.submit");
check(Boolean(doneOp?.opId && doneOp?.traceId), "台账条目带 opId 与 traceId");
check(/^REF/.test(doneOp?.reference ?? ""), `台账条目带流水号:${doneOp?.reference}`);

// ---- 台账接口 ----
console.log("\n8. 台账接口(/api/ledger/recent 与 /api/ledger/:opId)");
const recent = await getJson(`/api/ledger/recent?customerId=${encodeURIComponent(CUST)}&limit=50`);
check(recent.operations.length > 0, `最近操作可读(${recent.operations.length} 条)`);
check(
  recent.operations.every((o) => o.opId && o.sessionId && o.status && o.statusLabel),
  "每条台账都带 opId/sessionId/status/statusLabel",
);
const one = await getJson(`/api/ledger/${encodeURIComponent(doneOp.opId)}?customerId=${encodeURIComponent(CUST)}`);
check(one.operation.traceId === doneOp.traceId, "按 opId 取到的就是同一条(可跳审计)");
const missingRes = await fetch(`${base}/api/ledger/OP-DOES-NOT-EXIST?customerId=${encodeURIComponent(CUST)}`);
check(missingRes.status === 404, `不存在的 opId 返回 404(${missingRes.status})`);

// ---- S11:重启进程后仍在 ----
console.log("\n9. S11 重启服务后会话与台账仍在");
await server.close();
server = await startServer({ offline: true, port: 0, ...dirs });
base = `http://127.0.0.1:${server.port}`;
CUST = (await getJson("/api/demo/profile")).customerId;

const afterRestart = await sessionList();
check(
  afterRestart.sessions.some((s) => s.sessionId === sessionA),
  "★ 重启后会话列表里仍有 A 会话(落了盘)",
);
const dA2 = await detail(sessionA);
check(dA2.session.turns.length === 4, `重启后回放仍完整(${dA2.session.turns.length} 轮)`);
const ledgerAfter = await getJson(`/api/ledger/${encodeURIComponent(doneOp.opId)}?customerId=${encodeURIComponent(CUST)}`);
check(ledgerAfter.operation.opId === doneOp.opId, "重启后台账仍可追溯");
check(
  afterRestart.sessions.every((s) => s.status && s.statusLabel && s.tone),
  "重启后每个会话都带状态与色调",
);

// ---- S12:「再办一次」= 新会话,旧会话的待办不受影响 ----
console.log("\n10. S12「再办一次」产生新会话,旧会话的待办不受影响");
const sessionOld = sid("REPLAY-OLD");
const sessionReplay = sid("REPLAY-NEW");
const oldTurn = await say("给老妈转200", sessionOld);
check(oldTurn.promptFor?.kind === "confirm", "旧会话里留下一个待确认动作");
check((await detail(sessionOld)).session.status === "pending", "旧会话状态为 pending");

// 前端"再办一次"的行为:换新 sessionId + 用最后一轮用户原话重发
const replayTurn = await say("给老妈转200", sessionReplay);
check(sessionReplay !== sessionOld, "S12 ★ 新 sessionId 与原会话不同");
check(replayTurn.promptFor?.kind === "confirm", "再办一次重新走了一遍确认流程");
check((await detail(sessionReplay)).session.status === "pending", "新会话有自己的待办");
check((await detail(sessionOld)).session.status === "pending", "★ 旧会话的待办没有被新会话影响");

await act({ kind: "confirm", refId: oldTurn.promptFor.refId }, sessionOld);
check((await detail(sessionOld)).session.status === "done", "旧会话自己确认后正常办结");
check((await detail(sessionReplay)).session.status === "pending", "★ 旧会话的确认没有动到新会话的待办");

await server.close();

console.log("");
if (failed === 0) {
  console.log("全部通过 ✓");
  process.exit(0);
}
console.log(`${failed} 项未通过 ✗`);
process.exit(1);
