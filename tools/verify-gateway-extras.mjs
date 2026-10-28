/**
 * 通过 HTTP 网关验证"四项交互体验扩展"的端到端行为。
 *
 * 与 verify-extras.mjs 的分工:
 *   · verify-extras.mjs 直接调编排器(纯核心行为,不依赖网络);
 *   · 本脚本走**渠道网关的真实 HTTP 接口**(与 App 前端完全同一条路径),
 *     验证 turn 视图里确实带出了 flow / citations / suggestions,
 *     以及常用流程的三个接口(列表 / 实例化 / 保存)真的能用。
 *
 * 用法:node tools/verify-gateway-extras.mjs [baseUrl]
 */
import "dotenv/config";

const base = process.argv[2] ?? "http://127.0.0.1:8792";

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};

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

const say = (text, sessionId) =>
  postJson("/api/channels/app/messages", { text, sessionId }).then((d) => d.turn);
const act = (action, sessionId) =>
  postJson("/api/channels/app/actions", { sessionId, action }).then((d) => d.turn);

const sid = `gw-${Math.random().toString(36).slice(2, 8)}`;

console.log(`\n### 网关 HTTP 接口验证(base=${base})`);
const health = await getJson("/api/health");
check(health.ok === true, `网关健康(mode=${health.model.mode})`);

/** 场景开始时的常用流程条数(用于断言"没有自动新增") */
const flowsBefore = (await getJson("/api/personalization")).flows.length;

// ---- 1. 一轮回复里带出流程 / 出处 / 建议 ----
console.log("\n1. turn 视图带出交互体验数据");
const t1 = await say("给老妈转500,备注买菜", sid);
check(Boolean(t1.flow && t1.flow.steps.length >= 3), `flow 结构已返回(${t1.flow?.steps.length} 步)`);
check(t1.flow.steps.some((s) => s.lane === "customer"), "待客户确认的步骤标了 lane=customer");
check(Array.isArray(t1.citations) && t1.citations.length > 0, `citations 已返回(${t1.citations.length} 条)`);
check(
  t1.citations.every((c) => c.source && c.subject && c.effective),
  "每条出处都有来源/主体/时效",
);
// ★ 富渠道不再把流程/出处/建议写进文本,交给结构化控件
check(!/【办理流程/.test(t1.reply), "App 渠道文本里不再重复流程");
check(!/【数字与规则的出处】/.test(t1.reply), "App 渠道文本里不再重复出处");

const t2 = await act({ kind: "confirm", refId: t1.promptFor.refId }, sid);
check(/已向/.test(t2.reply), "确认后执行成功");
check(Boolean(t2.flow?.template), "办结后带回可保存的常用流程模板");
check(t2.flow?.saveable === true, "标记为可保存");
// ★ 同一业务线程:界面据此原地更新同一张卡(而不是再画一张"进行中")
check(t2.flow.threadId === t1.flow.threadId, "确认后续接同一个 flow.threadId");

// ---- 2. 常用流程三接口 ----
console.log("\n2. 常用流程接口(列表 / 实例化 / 保存)");
// ★ 不再自动保存:办完事之后,常用流程的**条数不应变化**(允许之前跑测留下的条目)
const p0 = await getJson("/api/personalization");
check(
  p0.flows.length === flowsBefore,
  `办完事不会自动塞进常用服务(场景开始 ${flowsBefore} 条 → 现在 ${p0.flows.length} 条)`,
);

// 点「存为常用流程」→ 走保存接口(带 sessionId,服务端按会话找回确认卡)
const saveResp = await postJson("/api/flows/save", { traceId: t2.traceId, sessionId: sid });
check(saveResp.ok === true, "手动保存接口可用");
check(Boolean(saveResp.savedTo), `返回了落盘位置:${saveResp.savedTo}`);
check(/personalization/.test(saveResp.savedTo), "保存位置是 var/personalization 下的客户文件");
check(Boolean(saveResp.flow?.params?.some((p) => p.key === "amount")), "手动保存的模板带上了金额参数");
check(
  Boolean(saveResp.flow?.sentence && !/\{收款人/.test(saveResp.flow.sentence)),
  `手动保存的模板句不是空壳:${saveResp.flow?.sentence}`,
);
check(Boolean(saveResp.whereToFind), `接口明确告诉客户去哪找:${saveResp.whereToFind}`);

const p1 = await getJson("/api/personalization");
check(p1.flows.length >= 1, `列表里有 ${p1.flows.length} 条常用流程`);
const saved = p1.flows.find((f) => /王秀兰|老妈/.test(f.name));
check(Boolean(saved), `刚才那笔已进常用流程(${p1.flows.map((f) => f.name).join(" | ")})`);
check(Boolean(saved?.say && /\{/.test(saved.say)), `快捷入口文案保留参数占位符:${saved?.say}`);

const inst = await postJson("/api/flows/instantiate", { templateId: saved.templateId, values: { amount: "888" } });
check(/888/.test(inst.text), `实例化时能替换参数:${inst.text}`);

/**
 * ★ 手动保存接口必须产出**完整**模板(带上对象与参数),而不是空壳。
 *
 *   实测踩到过:这个接口只拿"执行那一轮"的事件,取不到上一轮的确认卡,
 *   于是存下「给 {收款人} 转 {金额} 元」,还会按 templateId 覆盖掉好的那条。
 *   修法:按 sessionId 去审计链里把上一轮那张卡找回来,与自动保存共用派生实现。
 */
const manualSession = `gw-manual-${Math.random().toString(36).slice(2, 8)}`;
/**
 * ★ 金额与收款人刻意随机化:脚本会被反复运行,而"同一收款人、短时间内多笔"
 *   本身就会命中策略引擎的拆分交易检测 —— 那样失败的是**测试自己的重复运行**,
 *   不是产品行为。随机金额让每次运行都是"一笔新的转账"。
 */
const manualAmount = 100 + Math.floor(Math.random() * 400);
const m1 = await say(`给房东转${manualAmount}`, manualSession);
check(m1.promptFor?.kind === "confirm" || m1.promptFor?.kind === "strong_auth", `产生待确认动作(${m1.promptFor?.kind})`);
const m2 = await act({ kind: "confirm", refId: m1.promptFor.refId }, manualSession);
check(/已向|流水号/.test(m2.reply), `第二轮确认后执行成功(跨两轮的资金操作):${String(m2.reply).split("\n")[0]}`);
const manual = await postJson("/api/flows/save", {
  traceId: m2.traceId,
  sessionId: manualSession,
});
check(manual.ok === true, "手动保存接口可用(跨两轮的资金操作)");
check(Boolean(manual.flow && manual.flow.params.some((p) => p.key === "amount")), "手动保存的模板带上了金额参数");
check(
  Boolean(manual.flow?.sentence && !/\{收款人/.test(manual.flow.sentence)),
  `手动保存的模板句不是空壳:${manual.flow?.sentence}`,
);
// 保存后首页立刻能读到它(且没有重复条目)
const p2 = await getJson("/api/personalization");
check(
  p2.flows.some((f) => f.templateId === manual.flow.templateId),
  "保存后首页常用服务里立刻出现这条入口",
);
check(
  new Set(p2.flows.map((f) => f.templateId)).size === p2.flows.length,
  "常用流程没有重复条目(同一条套路只有一个入口)",
);

// ---- 3. 首页 profile 里带出个性化视图 ----
console.log("\n3. 首页数据(/api/demo/profile)");
const profile = await getJson("/api/demo/profile");
check(Array.isArray(profile.personalization?.flows), "profile 带出常用流程");
check(Array.isArray(profile.personalization?.suggestions), "profile 带出主动建议");
check(Array.isArray(profile.personalization?.history), "profile 带出历史业务记录");
console.log(`    常用流程 ${profile.personalization.flows.length} 条 · 建议 ${profile.personalization.suggestions.length} 条 · 历史 ${profile.personalization.history.length} 条`);

// ---- 4. 人工审批:材料清单必须出现在客户看到的文本里 ----
console.log("\n4. 敏感流程:已转人工审批 + 材料清单");
const s2 = `gw2-${Math.random().toString(36).slice(2, 8)}`;
const a1 = await say("帮我把尾号3344的额度提到5万", s2);
check(a1.promptFor?.kind === "strong_auth", "提额先要求强验证");
const pend = await getJson(`/api/demo/pending?customerId=CUST-DEMO-001`);
const proof = await postJson("/api/demo/sign-auth-proof", { method: "biometric", payloadHash: pend.pending.payloadHash });
const a2 = await act({ kind: "confirm", refId: pend.pending.pendingId, authProof: proof.proof }, s2);
check(/已转人工审批/.test(a2.reply), "明确提示已转人工审批");
check(/请提交以下材料/.test(a2.reply), "给出材料清单");
check(a2.flow?.handedToHuman === true, "流程结构标记 handedToHuman");
check(a2.citations.some((c) => (c.id ?? "").startsWith("human_review:")), "人工审批通道作为规则出处列出");

// ---- 5. 预算规划能力(个性化建议的落点) ----
console.log("\n5. 预算规划能力(建议点进去真的能办)");
const b1 = await say("帮我规划这个月剩余预算", s2);
check(/已支出/.test(b1.reply) && /预算/.test(b1.reply), "没说预算额时先报已支出并追问预算");
check((b1.flow?.steps ?? []).length > 0, "预算问答同样带出流程链路(全自主执行)");
const b2 = await say("预算 5000", s2);
check(/还剩|已经超了/.test(b2.reply), "给出预算后算出剩余");
check(
  (b2.citations ?? []).some((c) => (c.calculation ?? []).some((l) => /剩余\s*=/.test(l))),
  "计算过程可核对(剩余 = 预算 − 已支出)",
);
// 一句话直接给预算(就是首页建议按钮发出的那句话)也要能办
const b3 = await say("帮我规划这个月剩余预算,预算 5000", `gw3-${Math.random().toString(36).slice(2, 8)}`);
check(/还剩|已经超了/.test(b3.reply), "一句话同时给预算也能直接算出来(建议按钮的真实用法)");
check((b3.citations ?? []).length > 0, "该轮带出来源标注");

// ---- 6. 强验证按钮"一按即失效"(按 refId 精确取待办,不取最新那条)----
console.log("\n6. 强验证按钮一按即失效(按 refId 精确取待办)");
{
  const s3 = `gw4-${Math.random().toString(36).slice(2, 8)}`;
  const c1 = await say("我想办一张新卡", s3);
  check(c1.promptFor?.kind === "strong_auth", `办新卡先要求强验证(${c1.promptFor?.kind})`);
  const refId = c1.promptFor?.refId;
  check(Boolean(refId), "待办带 refId(验证按钮据此签发回执)");

  /**
   * ★ 前端点「完成身份验证」时,必须按 refId 取**这一笔**的载荷,
   *   而不是永远取"最新那一条" —— 否则先验证 A、中途又发起 B,
   *   再点 A 的按钮就会给 B 盖章。
   */
  const target = await getJson(
    `/api/demo/pending?customerId=${encodeURIComponent(profile.customerId)}&refId=${encodeURIComponent(refId)}`,
  );
  check(target.pending?.pendingId === refId, "按 refId 取到的是同一笔待办(不是「最新那一条」)");

  const proof2 = await postJson("/api/demo/sign-auth-proof", {
    method: "biometric",
    payloadHash: target.pending.payloadHash,
  });
  const done = await act({ kind: "confirm", refId, authProof: proof2.proof }, s3);
  check(/申请已提交/.test(done.reply), `验证后申请提交:${String(done.reply).split("\n")[0]}`);
  check(done.promptFor?.kind === "none", "办完之后不再要求验证(按钮的使命结束)");

  // ★ 一按即失效:同一个 refId 再取一次必须是 null —— 界面据此不再签发回执
  const again = await getJson(
    `/api/demo/pending?customerId=${encodeURIComponent(profile.customerId)}&refId=${encodeURIComponent(refId)}`,
  );
  check(again.pending === null, "★ 按过的 refId 取不到待办(按钮不能再用)");

  // 即使前端被改、把旧动作重放一遍,也不能执行第二次
  const replay = await act({ kind: "confirm", refId, authProof: proof2.proof }, s3);
  check(
    /没有找到待确认|已经过期|已经处理/.test(replay.reply),
    `重放旧动作被拒:${String(replay.reply).split("\n")[0]}`,
  );

  /**
   * ★ 签名端点不是"通用签名预言机"。
   *
   *   它曾经给任意 payloadHash 就回一份**签名合法**的回执,而 CORS 是 `*`、无鉴权 ——
   *   任何能访问回环端口的调用者都能"发起一笔红色档操作 → 取 payloadHash → 换真回执 → 执行",
   *   强验证这道闸门在交付物里等于不存在。现在它只为本进程真实存在、尚未执行的待办签发。
   */
  const forged = await fetch(`${base}/api/demo/sign-auth-proof`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method: "biometric", payloadHash: "deadbeef".repeat(8) }),
  });
  check(
    forged.status === 403,
    `★ 凭空编造的载荷哈希必须换不到回执(实际 HTTP ${forged.status})`,
  );
  const forgedBody = await forged.json().catch(() => ({}));
  check(
    forgedBody.ok !== true && !forgedBody.proof,
    "★ 拒绝时不能夹带任何回执材料",
  );
}

// ---- 7. 上游中止意图经网关透传:只在提交点之前有效(第 3 项)----
console.log("\n7. 上游中止意图透传(提交点之前的中断)");
{
  const s4 = `gw5-${Math.random().toString(36).slice(2, 8)}`;

  /**
   * ★ 这一段验证的是"取消意图能不能从**真实 HTTP 入口**进来"。
   *
   *   之前的实现里,`MessageEnvelope.cancellation` 根本不在网关的白名单里 ——
   *   也就是说"客户端按下取消""上游超时"这类中止意图**永远到不了提交点**,
   *   第 3 项那条链路只有测试和 demo 能触发。现在请求体可以带 `cancel`。
   *
   *   断言口径刻意选"客户能看见的后果",而不是内部字段:
   *     · 回复必须如实说"提交前取消、什么都没发生";
   *     · 业务台账里**不能**多出一笔已完成的转账(execution_cancelled 不进台账);
   *     · 审计里必须有一条 execution_cancelled 且 phase=before_commit。
   */
  const ledgerBefore = (await getJson(`/api/ledger/recent?current=${encodeURIComponent(s4)}`)).operations;
  /**
   * ★ 计数必须用**增量**:链是历史累积的,前面几场 demo/回归早就写过
   *   execution_cancelled。用绝对值判断会"因为历史里恰好有一条"而假通过 ——
   *   实测第一次跑就踩到了(那条 11 字的 reason 来自 demo 场景,不是本次)。
   */
  const before7 = (await getJson("/api/audit/recent?limit=500")).events;
  const cancelledBefore = before7.filter((e) => e.type === "execution_cancelled").length;

  const asked = await say("给老妈转500", s4);
  check(asked.promptFor?.kind === "confirm", `这笔应当停在确认关卡(${asked.promptFor?.kind})`);

  // ★ reason 故意超长 + 带控制字符:网关必须收窄(否则审计链体积与内容由调用方决定)
  const longReason = `${"接管".repeat(200)}\u0007`;
  const cancelledTurn = await postJson("/api/channels/app/messages", {
    text: "确认",
    sessionId: s4,
    cancel: { requested: true, reason: longReason, source: "timeout" },
  }).then((d) => d.turn);

  check(/已取消|没有执行/.test(cancelledTurn.reply), `回复要用客户能懂的取消话术:${cancelledTurn.reply}`);
  check(!/已向/.test(cancelledTurn.reply), "★ 中止的这一步绝不能报告成功");
  // ★ 对客文案红线:内部词与上游 reason 不得出现在客户看到的回复里
  //   ("提交点/提交前"是架构内部概念;"接管"来自本段故意塞的超长 reason)
  check(!/提交点|提交前/.test(cancelledTurn.reply), "★ 回复里不得出现「提交点/提交前」这类内部词");
  check(!cancelledTurn.reply.includes("接管"), "★ 上游 reason 不得回显给客户(完整值只进审计链)");

  const ledgerAfter = (await getJson(`/api/ledger/recent?current=${encodeURIComponent(s4)}`)).operations;
  check(
    ledgerAfter.length === ledgerBefore.length,
    `★★ 提交前中止不得产生业务台账记录(客户历史里不能出现一笔没发生的转账):${ledgerBefore.length} → ${ledgerAfter.length}`,
  );

  const audit = (await getJson("/api/audit/recent?limit=500")).events;
  const fresh = audit.filter((e) => e.type === "execution_cancelled").slice(cancelledBefore);
  check(fresh.length === 1, `本次应恰新增一条 execution_cancelled(实际 ${fresh.length})`);
  check(fresh[0]?.payload?.phase === "before_commit", "审计要标明停在提交点之前");
  check(
    String(fresh[0]?.payload?.reason ?? "").length === 120,
    `★ reason 必须被截断到 120 字(实际 ${String(fresh[0]?.payload?.reason ?? "").length} 字)`,
  );
  check(
    !/[\u0000-\u001f\u007f]/.test(String(fresh[0]?.payload?.reason ?? "")),
    "★ 控制字符必须被清掉(它会跟着事件进哈希链)",
  );
  check(fresh[0]?.payload?.cause === "timeout", `source 要如实归类(实际 ${fresh[0]?.payload?.cause})`);

  /**
   * ★ 反向验证:`requested` 为假 = **没有**中止意图。
   *   多一个字段绝不能把正常操作全废掉 —— 否则"取消"这个字段本身就成了拒绝服务。
   *
   *   ★ 这里**不**断言"必须停在确认关卡":实测本段跑到这里时,频次护栏已经生效
   *   (5 分钟内转账次数超限 → 这一笔被确定性拒绝,promptFor=none)。
   *   那是护栏在正常工作,不是本功能的问题。所以断言只取**与状态无关**的两条:
   *     ① 不得新增 execution_cancelled(没有被当成中止);
   *     ② 回复里不得出现任何"已取消/提交前取消"的字样。
   *   "不带 cancel 字段时一切照旧"由第 1–6 段自己证明(它们都不带这个字段)。
   */
  const s5 = `gw6-${Math.random().toString(36).slice(2, 8)}`;
  const beforeFalse = (await getJson("/api/audit/recent?limit=500")).events.filter(
    (e) => e.type === "execution_cancelled",
  ).length;
  const notCancelled = await postJson("/api/channels/app/messages", {
    text: "给我妈转200",
    sessionId: s5,
    cancel: { requested: false, reason: "客户端随手带上的字段" },
  }).then((d) => d.turn);
  const afterFalse = (await getJson("/api/audit/recent?limit=500")).events.filter(
    (e) => e.type === "execution_cancelled",
  ).length;
  check(afterFalse === beforeFalse, `requested=false 不得产生中止事件(${beforeFalse} → ${afterFalse})`);
  check(
    !/提交前取消|已取消/.test(notCancelled.reply),
    `requested=false 时不得出现任何「已取消」的字样:${String(notCancelled.reply).split("\n")[0]}`,
  );
}

console.log("");
console.log(failed === 0 ? "全部通过 ✓" : `${failed} 项未通过 ✗`);
process.exit(failed === 0 ? 0 : 1);
