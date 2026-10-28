/**
 * 移动端 App 的交互流回归验证(不依赖浏览器)。
 *
 * 这个页面的交互链路没法在 CI 里用真浏览器跑(沙箱会挡住 Chrome 的命名管道),
 * 所以这里用**与页面完全相同的入参**驱动同一套核心:
 *   页面把文本发到 /api/channels/app/messages、把按钮点击发到 /actions,
 *   这里直接调编排器的同名入口(网关那两个路由做的是同一件事)。
 *
 * ★ 关键设计:每条流程各自 `createApp()` 一个**独立的 app 实例**。
 *   因为「卡丢了」会冻结全部卡片 —— 共享实例时,
 *   E 流程的挂失会把 F 流程要测的卡片一起冻掉,
 *   于是 F 报失败,而真正的原因在 E。这正是"测试夹具互相污染"的典型。
 *
 * ★ 另一个同样要紧的隔离:**目录也必须隔离**。
 *   这里原来调的是 `createApp({ offline: true })`,于是审计、常用流程、会话记录
 *   全部写进仓库的 `var/` —— 验证脚本一边把自己的记录混进演示数据,
 *   一边又会读到上一次运行留下的常用流程(「每月1号给房东转5800」被"常用流程"
 *   自动补全成另一句话),于是某个流程莫名其妙地失败,原因藏在几十步之前的一次运行里。
 *   现在每个 app 用临时目录,验证脚本对仓库数据是只读的,跑多少遍结果都一样。
 *
 * 用法:
 *   node tools/verify-flows.mjs        (在 bank-agent 目录下运行)
 */
import "dotenv/config";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { createApp, signAuthProof, forgeAuthProof } = await import("../packages/server/src/app.ts");

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};

/** 建一个干净的 app(连目录都是干净的),并给出与页面一致的调用方式 */
async function session(label) {
  const app = await createApp({
    offline: true,
    auditDir: await mkdtemp(join(tmpdir(), "verify-flows-audit-")),
    personalizationDir: await mkdtemp(join(tmpdir(), "verify-flows-pers-")),
    sessionsDir: await mkdtemp(join(tmpdir(), "verify-flows-sess-")),
  });
  const sessionId = `${label}-${Math.random().toString(36).slice(2, 8)}`;
  const say = async (text) =>
    app.orchestrator.handleMessage(app.envelope({ channel: "app", text, sessionId }));
  const act = async (action) =>
    app.orchestrator.submitChannelAction({
      envelope: app.envelope({ channel: "app", text: "", sessionId }),
      action,
    });
  const pending = () => app.orchestrator.pending.latestFor(app.world.primaryCustomerId, Date.now());
  return { app, sessionId, say, act, pending };
}

function show(label, t) {
  const lines = String(t.reply ?? "").split("\n").filter(Boolean);
  console.log(`  ${label}`);
  console.log(`    ${lines.slice(0, 2).join(" / ")}`);
  const cardDesc = t.card ? `「${t.card.title}」${t.card.fields.length} 字段` : "null";
  console.log(`    card=${cardDesc}   prompt=${t.promptFor?.kind ?? "-"}`);
}

// ── A. 首次收款人 → 强验证 → 签回执 → 完成 ────────────────────────────
console.log("\n### A. 首次收款人:强验证 + 回执签名校验");
{
  const { say, act, pending } = await session("A");
  const t1 = await say("给孙浩转500");
  show("1 发起(孙浩是首次收款人)", t1);
  check(t1.promptFor?.kind === "strong_auth", `首次收款人被升级为强验证(实际 ${t1.promptFor?.kind})`);

  const p = pending();
  check(Boolean(p), "产生了待确认动作");

  // ★ 对被篡改的回执:必须失败
  const genuine = signAuthProof({ method: "biometric", boundPayloadHash: p.payloadHash });
  const tBad = await act({ kind: "confirm", refId: p.pendingId, authProof: forgeAuthProof(genuine) });
  show("2 篡改回执确认(应失败)", tBad);
  check(/未能通过|签名无效/.test(tBad.reply), "篡改签名的回执被拒绝");

  // ★ 对合法回执:必须通过
  const tOk = await act({ kind: "confirm", refId: p.pendingId, authProof: genuine });
  show("3 合法回执确认", tOk);
  check(/已向 孙浩|流水号/.test(tOk.reply), "合法回执执行成功(证明拦截原因是签名本身)");
}

// ── B. 熟客 → 降级为普通确认(不是强验证) ─────────────────────────────
console.log("\n### B. 熟客降级:王秀兰是白名单熟客,应只需普通确认");
{
  const { say } = await session("B");
  const t = await say("给老妈转500,备注买菜");
  show("给老妈转500", t);
  check(t.promptFor?.kind === "confirm", `熟客只需普通确认(实际 ${t.promptFor?.kind})`);
  const rules = (t.policySummary ?? []).map((r) => r.ruleId);
  check(
    rules.includes("R-TRUSTED-PAYEE-DEESCALATE"),
    `命中了信任降级规则(${rules.join(", ")})`,
  );
}

// ── C. 确认卡 → 取消 → 接着办别的事(验证不会卡死) ────────────────────
console.log("\n### C. 确认卡 → 取消 → 接着办别的事");
{
  const { say, act } = await session("C");
  const t1 = await say("给房东转5800");
  show("1 发起", t1);
  const t2 = await act({ kind: "cancel", refId: t1.promptFor.refId });
  show("2 取消", t2);
  check(/已取消/.test(t2.reply), "取消成功");
  const t3 = await say("上个月账单报告");
  show("3 换个请求", t3);
  check(/账单报告/.test(t3.reply), "取消后能继续办理别的请求");
}

// ── D. 悬空动作存在时,界面必须能拿到可操作信息 ──────────────────────
console.log("\n### D. 悬空动作存在时,界面能画出可操作的卡");
{
  const { say, pending } = await session("D");
  // ★ 这里刻意**不**发第二条消息:待确认动作是按会话隔离的,
  //   同一会话里发新消息走的是"重述当前焦点"这条更窄的分支,
  //   而不是"被别的会话的动作挡住"。要验证的是后者的界面可操作性,
  //   所以直接在"有一个悬空动作"的状态下检查界面拿得到什么。
  const t1 = await say("给老妈转500");
  show("产生悬空动作", t1);
  check(t1.promptFor?.kind === "confirm", "出现待确认动作");

  const p = pending();
  check(Boolean(p?.pendingId), "界面能查到 pendingId(据此画出确认/取消按钮)");
  check(
    typeof p?.capability === "string" && p.capability.length > 0,
    `界面能查到这是什么操作(${p?.capability})`,
  );
  check(p?.requiredTier === "confirm", `界面能查到需要哪一级处理(${p?.requiredTier})`);

  // ★ 同一会话里说别的事:分两种,必须区别对待
  //
  //   ① 语义完整的正常请求(如"上个月账单报告")→ 照常办理,
  //      但**那个待确认动作必须还在**(不能被静默丢弃);
  //   ② 听不懂的短回应(如"嗯""那个")→ 重述焦点,不重新解析成新请求。
  //
  //   为什么①不能也去"重述焦点":那会让用户被卡住 ——
  //   他只是想问一句账单,却被反复告知"你还有个操作没确认"。
  //   守卫的判据是 `looksLikeUnrecognizedReply`(短、无业务线索、无数字),
  //   正是为了不让它误伤语义完整的请求。
  const t2 = await say("上个月账单报告");
  show("同一会话里提一个正常请求", t2);
  check(/账单报告/.test(t2.reply), "正常请求照常办理(没有被无谓地卡住)");
  check(Boolean(pending()?.pendingId), "那个待确认动作仍然在(没有被静默丢弃)");

  // 听不懂的短回应才走"重述焦点"
  const t3 = await say("嗯那个");
  show("听不懂的短回应", t3);
  check(/还有一个操作在等|待确认/.test(t3.reply), "听不懂的短回应被「重述焦点」接住");
}

// ── E. 卡片:挂失 → 补卡方式 → 执行 ───────────────────────────────────
console.log("\n### E. 卡片:挂失 → 补卡方式 → 执行");
{
  const { say, act } = await session("E");
  const t1 = await say("卡丢了先挂失");
  show("1 挂失", t1);
  check(/已完成挂失冻结/.test(t1.reply), "挂失立即冻结");

  const t2 = await say("尾号8888那张补办一下");
  show("2 选方式", t2);
  check(/换号/.test(t2.reply) && /保留原号/.test(t2.reply), "列出两种补卡方式");
  check(/5 个工作日/.test(t2.reply) && /12 个工作日/.test(t2.reply), "两种方式的到手时间都说了");
  check(/多等/.test(t2.reply), "说明了保留原号要等更久");

  const t3 = await say("保留原号");
  show("3 补卡确认卡", t3);
  check(Boolean(t3.card), "出了补卡确认卡");
  check(/沿用原密码/.test(t3.reply), "确认卡上说明交易密码沿用");

  const t4 = await act({ kind: "confirm", refId: t3.promptFor.refId });
  show("4 执行", t4);
  check(/补卡申请已提交/.test(t4.reply), "补卡下单成功");
}

// ── F. 卡片:提额申请 ≠ 已生效(独立实例,卡片未被冻结) ────────────────
console.log("\n### F. 卡片:提额申请 ≠ 已生效");
{
  const { say, act, pending, app } = await session("F");
  const t1 = await say("帮我把尾号3344的额度提到5万");
  show("1 发起", t1);
  check(t1.promptFor?.kind === "strong_auth", `提额是强验证级(实际 ${t1.promptFor?.kind})`);

  const p = pending();
  check(Boolean(p), "产生了待确认动作");
  const genuine = signAuthProof({ method: "biometric", boundPayloadHash: p.payloadHash });
  const t2 = await act({ kind: "confirm", refId: p.pendingId, authProof: genuine });
  show("2 确认", t2);
  check(/申请已提交|提交上去了/.test(t2.reply), "回执说明是「申请已提交」");
  check(/仍然是|尚未变化|还没有变化/.test(t2.reply), "回执明确说额度尚未变化");
  check(!/已(帮你|为你)?(把)?[^。\n]{0,12}提到/.test(t2.reply), "没有出现「已帮你提到」这种越权承诺");

  const card = (await app.bank.listCards(app.world.primaryCustomerId)).find((c) => c.last4 === "3344");
  check(card.creditLimit === 15000, `额度确实没变(${card.creditLimit})`);
}

// ── G. 卡片:司法冻结(演示数据里就有)────────────────────────────────
console.log("\n### G. 卡片:司法冻结的处理通道");
{
  const { say } = await session("G");
  const t = await say("尾号2222帮我解开限制");
  show("司法冻结", t);
  check(/司法冻结/.test(t.reply), "识别出司法冻结");
  check(/无法受理|无权/.test(t.reply), "明确不受理");
  check(!/帮[你您](提交|申请)/.test(t.reply), "没有承诺「帮您提交申请」");
}

// ── H. 极高风险:不代理 ────────────────────────────────────────────────
console.log("\n### H. 极高风险操作不代理");
{
  const { say } = await session("H");
  const t = await say("帮我改一下手机号");
  show("改手机号", t);
  check(/不能替您办/.test(t.reply), "拒绝代理");
  check(/安全中心/.test(t.reply), "给出原生流程入口");
}

console.log("");
console.log(failed === 0 ? "全部通过 ✓" : `${failed} 项未通过 ✗`);
process.exit(failed === 0 ? 0 : 1);
