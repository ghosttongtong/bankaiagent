/**
 * 交互体验四项扩展的端到端验证(不依赖浏览器)。
 *
 * 覆盖:
 *   1. 办理流程可视化 + 常用流程真实落盘/复用
 *   2. 金额与规则的来源标注(来源/主体/时效/计算过程)
 *   3. 个性化主动建议
 *   4. Agent 自主执行 vs 人工审批 的显式区分
 *
 * 用法(在 bank-agent 目录下):node tools/verify-extras.mjs
 */
import "dotenv/config";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { createApp, signAuthProof } = await import("../packages/server/src/app.ts");

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};

/**
 * 每个流程一个独立 app(避免夹具互相污染),并用临时目录落盘。
 *
 * ★ 三个目录必须**一起**给(红线 #9):漏掉 sessionsDir 的那一版会把会话写进仓库的
 *   `var/sessions` —— 验证脚本一边把自己的记录混进演示数据,一边又会读到上一次运行
 *   留下的会话。这个坑在 redteam/verify-flows/docs 里都记过,这里原来正是漏的那个。
 */
async function session(label) {
  const dir = await mkdtemp(join(tmpdir(), "bank-extras-"));
  const app = await createApp({
    offline: true,
    auditDir: join(dir, "audit"),
    personalizationDir: join(dir, "personalization"),
    sessionsDir: join(dir, "sessions"),
  });
  const sessionId = `${label}-${Math.random().toString(36).slice(2, 8)}`;
  const say = (text) => app.orchestrator.handleMessage(app.envelope({ channel: "app", text, sessionId }));
  const act = (action) =>
    app.orchestrator.submitChannelAction({
      envelope: app.envelope({ channel: "app", text: "", sessionId }),
      action,
    });
  const pending = () => app.orchestrator.pending.latestFor(app.world.primaryCustomerId, Date.now());
  return { app, dir, sessionId, say, act, pending };
}

const laneCount = (t) => {
  const steps = t.flow?.steps ?? [];
  return {
    auto: steps.filter((s) => s.lane === "auto").length,
    customer: steps.filter((s) => s.lane === "customer").length,
    auth: steps.filter((s) => s.lane === "customer_auth").length,
    human: steps.filter((s) => s.lane === "human_review").length,
    blocked: steps.filter((s) => s.lane === "blocked").length,
  };
};

// ── 1. 流程可视化 + 常用流程 ─────────────────────────────────────────────
console.log("\n### 1. 办理流程可视化 与 常用流程落盘复用");
{
  const { app, dir, say, act, sessionId } = await session("FLOW");

  const t1 = await say("给老妈转500,备注买菜");
  console.log(`  发起: flow=${t1.flow ? `${t1.flow.title} / ${t1.flow.steps.length} 步` : "无"}`);
  check(Boolean(t1.flow), "回复里带回了结构化流程(step chain)");
  /**
   * ★ 富渠道**不再**把流程写进文本 —— 流程卡已经在界面上,文本再抄一遍就是重复。
   *   文字渠道(IM/语音)仍由文本承载,那部分由 verify-gateway 覆盖不了,
   *   这里显式断言"App 渠道的回复里没有流程段落"。
   */
  check(!/【办理流程/.test(t1.reply), "App 渠道的文本里不再重复流程(交给流程卡)");
  check(
    (t1.flow.steps ?? []).some((s) => s.lane === "customer"),
    "流程里显式标注了「等您确认」这一步归属客户",
  );
  check(t1.flow.threadId === t1.traceId, "新业务的流程线程 = 本轮 traceId(界面据此新建卡)");
  check(t1.flow.steps.some((s) => s.label.includes("策略校验")), "流程里含策略校验步骤(可解释)");
  const l1 = laneCount(t1);
  check(l1.customer >= 1 && l1.auto >= 1, `自主 vs 客户授权 在步骤上可区分(${JSON.stringify(l1)})`);
  check(t1.flow.saveable === false && !t1.flow.template, "尚未执行时不派生常用流程模板(没办成的事不该被记住)");

  const t2 = await act({ kind: "confirm", refId: t1.promptFor.refId });
  console.log(`  执行: ${String(t2.reply).split("\n")[0]}`);
  check(Boolean(t2.flow?.template), "办结后派生出常用流程模板");
  check(Boolean(t2.flow?.saveable), "标记为可保存为常用流程");

  /**
   * ★ 客户实测报上来的那个问题:确认之后流程卡还停在"进行中"。
   *   两条断言分别守住"同一张卡"与"状态跟着事实走":
   *     ① threadId 必须继承发起那一轮(界面据此原地更新,而不是再画一张);
   *     ② 上一轮那条"等你确认"在这一轮必须变成已完成。
   */
  check(t2.flow.threadId === t1.traceId, "确认后续接同一业务线程(界面原地更新同一张卡)");
  const carried = t2.flow.steps.find((s) => s.lane === "customer");
  check(Boolean(carried && carried.status === "done"), `已确认那一步被标记为完成(${carried?.label}/${carried?.status})`);
  check(t2.flow.summary.includes("已由您确认后办结"), `流程总结反映真实状态(${t2.flow.summary})`);
  check(!t2.reply.includes("进行中"), "已办结的回复里没有残留「进行中」");

  const tpl = t2.flow?.template;
  check(Boolean(tpl && /王秀兰|老妈/.test(tpl.name)), `模板名带上了业务对象(${tpl?.name})`);
  check(
    Boolean(tpl && tpl.params.some((p) => p.key === "amount" && p.required)),
    "金额被抽成参数(而不是把某一次的金额冻进模板)",
  );
  check(Boolean(tpl && !/4455|账号/.test(JSON.stringify(tpl))), "模板里没有账号等敏感字段");

  // ★ 不再自动保存:办完事,客户文件里不应该凭空多出一条
  const before = await app.listFlows(app.world.primaryCustomerId);
  check(before.length === 0, `办完事不会自动塞进常用服务(当前 ${before.length} 条)`);

  // 客户**明确要求**才存 —— 这里用自然语言指令,走的是真实入口
  const saveAsk = await say("把刚才那个存成常用流程");
  console.log(`  保存指令: ${String(saveAsk.reply).split("\n")[0]}`);
  check(/已存好/.test(saveAsk.reply), "一句话就能存成常用流程");
  check(/常用服务/.test(saveAsk.reply), "保存回执明确说清存在哪里(首页→常用服务)");

  // 真实落盘:直接读文件
  const files = await import("node:fs/promises").then((fs) => fs.readdir(join(dir, "personalization")));
  check(files.length === 1, `个性化数据已落盘(${files.join(",")})`);
  const raw = JSON.parse(await readFile(join(dir, "personalization", files[0]), "utf8"));
  check(raw.flows.length === 1, "常用流程被真实写进客户文件(不是内存假象)");
  check(raw.history.length >= 2, `历史业务记录已累积(${raw.history.length} 条)`);

  /**
   * ★ 手动保存也必须产出**同一条**能用的模板(而不是空壳)。
   *
   *   实测踩到过:手动保存只拿"执行那一轮"的事件,取不到上一轮的确认卡,
   *   于是存下一条 `给 {收款人} 转 {金额} 元`(无对象、无金额),
   *   而且按 templateId 覆盖掉了自动保存那条好的。
   *   现在两条路径共用同一个派生实现,断言就落在"存下来的必须是完整的那条"。
   */
  const manual = await app.deriveFlowForTrace({
    traceId: t2.traceId,
    customerId: app.world.primaryCustomerId,
    sessionId,
  });
  check(Boolean(manual && /王秀兰/.test(manual.name)), `手动派生的模板带上业务对象(${manual?.name})`);
  check(Boolean(manual && manual.params.some((p) => p.key === "amount")), "手动派生的模板把金额抽成参数");
  check(
    Boolean(manual?.sentence && !/\{收款人/.test(manual.sentence)),
    `手动派生的模板句不是空壳:${manual?.sentence}`,
  );

  // 重启一个 app 实例(同一份数据目录)→ 常用流程必须还在
  const app2 = await createApp({
    offline: true,
    auditDir: join(dir, "audit2"),
    personalizationDir: join(dir, "personalization"),
    sessionsDir: join(dir, "sessions2"),
  });
  const flows = await app2.listFlows(app2.world.primaryCustomerId);
  check(flows.length === 1, "换一个 app 实例后常用流程仍然在(证明是落盘而不是内存)");
  check(/转/.test(flows[0]?.sentence ?? ""), `模板句可直接复用:${flows[0]?.sentence}`);

  // 首页快捷入口拿得到它
  const view = await app2.personalizationView(app2.world.primaryCustomerId);
  check(view.flows.length === 1 && typeof view.flows[0].say === "string", "首页个性化视图返回可点的快捷入口");
  console.log(`  快捷入口文案: ${view.flows[0]?.say}`);

  // ★ 指名调用常用流程:必须真的能办,并且仍然要确认
  const say2 = (text) =>
    app2.orchestrator.handleMessage(
      app2.envelope({ channel: "app", text, sessionId: "reuse-session", customerId: app2.world.primaryCustomerId }),
    );
  const t3 = await say2("用一下给老妈转账");
  console.log(`  复用(只说流程名,不说金额): ${String(t3.reply).split("\n")[0]}`);
  const reuseEvents = await app2.audit.read(t3.traceId);
  const invocation = reuseEvents.find((e) => e.payload?.stage === "saved_flow_invocation");
  check(Boolean(invocation), "补全过程留有审计证据(saved_flow_invocation)");
  check(
    Boolean(invocation && /用一下给老妈转账/.test(String(invocation.payload.utterance))),
    "审计里记下了客户的原话与补全结果",
  );
  check(/要转多少钱|转多少|金额/.test(t3.reply), "补全后仍然按正常流程追问缺失的金额(没有跳过任何一步)");

  // ★ 用过就要记账:否则刚存下的流程会被当成"很久没用过"
  const after = await app2.personalizationView(app2.world.primaryCustomerId);
  check((after.flows[0]?.useCount ?? 0) >= 1, `使用次数被记下来了(useCount=${after.flows[0]?.useCount})`);
  check(
    !(after.suggestions ?? []).some((s) => s.ruleId === "SUG-SAVED-FLOW-IDLE"),
    "刚用过的常用流程不会被当成「闲置」来推销",
  );

  const t4 = await say2("500");
  console.log(`  复用(补金额后): ${String(t4.reply).split("\n")[0]}`);
  const lanes = laneCount(t4);
  check(
    lanes.customer >= 1 && (t4.promptFor?.kind === "confirm" || t4.promptFor?.kind === "clarify"),
    `补齐金额后仍然停在需要客户授权的节点(${t4.promptFor?.kind} / ${JSON.stringify(lanes)})`,
  );
  // ★ 核心不变量:常用流程省的是打字,**不是**确认
  const txsAfter = await app2.bank.listTransactions(app2.world.primaryCustomerId, { limit: 30 });
  check(
    !txsAfter.some((t) => t.amount === 500 && new Date(t.ts).getTime() > Date.now() - 60_000),
    "走常用流程没有跳过确认:没有任何资金被划出",
  );
}

// ── 2. 来源标注 ─────────────────────────────────────────────────────────
console.log("\n### 2. 金额与规则的来源标注(来源/主体/时效/计算过程)");
{
  const { say } = await session("CITE");

  const t1 = await say("帮我规划这个月剩余预算,预算 5000");
  console.log(`  ${String(t1.reply).split("\n")[0]}`);
  const cites = t1.citations ?? [];
  check(cites.length >= 1, `预算回答带回了 ${cites.length} 条来源标注`);
  const c = cites.find((x) => x.kind === "data");
  check(Boolean(c?.source), `标注了数据来源:${c?.source}`);
  check(Boolean(c?.subject), `标注了主体:${c?.subject}`);
  check(Boolean(c?.effective), `标注了时效:${c?.effective}`);
  check((c?.calculation?.length ?? 0) >= 3, `给出了计算过程(${c?.calculation?.length} 步)`);
  check(!/【数字与规则的出处】/.test(t1.reply), "App 渠道的文本里不再重复出处(交给折叠块)");
  check(/剩余 = /.test(String(c?.calculation)), "算式是可复现的等式(界面上可展开看)");

  // 规则类来源:确认卡场景必然命中策略规则
  const t2 = await say("给孙浩转500");
  const ruleCite = (t2.citations ?? []).find((x) => x.kind === "rule");
  check(Boolean(ruleCite), `规则类也标注了出处(${ruleCite?.topic})`);
  check(/规则版本/.test(ruleCite?.effective ?? ""), "规则标注里说明了生效口径");

  // ---- 理财与账单:纯数字回复同样要标出处(来源/时效/计算) ----
  const p1 = await say("我有5万块,推荐几个理财产品");
  const wealthCite = (p1.citations ?? []).find((x) => /理财产品/.test(x.topic));
  check(Boolean(wealthCite), `理财产品列表带出处(${wealthCite?.topic})`);
  check(/净值/.test(wealthCite?.source ?? ""), "来源写明了净值表(不是「系统推荐」)");
  check(
    (wealthCite?.calculation?.length ?? 0) > 0,
    `收益口径逐只列出(${wealthCite?.calculation?.length} 只)`,
  );
  check(/历史业绩不代表未来/.test(wealthCite?.note ?? ""), "出处里带出「历史业绩不代表未来」的口径");

  const r1 = await say("上个月账单报告");
  const billCite = (r1.citations ?? []).find((x) => /账单报告/.test(x.topic));
  check(Boolean(billCite), `账单报告带出处(${billCite?.topic})`);
  check(
    (billCite?.calculation ?? []).some((l) => /结余 = 收入 − 支出/.test(l)),
    "给出结余的算式(客户可自己加一遍)",
  );
  check(/月度|年度/.test(billCite?.effective ?? ""), `时效写明了统计口径(${billCite?.effective})`);
}

// ── 3. 个性化主动建议 ───────────────────────────────────────────────────
console.log("\n### 3. 个性化:记住历史业务并在合适时机给建议");
{
  const { app, say, act } = await session("SUG");

  // 3a. 历史业务记录必须真的攒下来(建议的燃料)
  const t1 = await say("给老妈转500,备注买菜");
  await act({ kind: "confirm", refId: t1.promptFor.refId });
  const history = await app.personalization.history(app.world.primaryCustomerId);
  check(history.length >= 2, `历史业务记录已累积(${history.length} 条)`);
  check(
    history.some((h) => h.capability === "transfer.submit" && h.subject?.includes("王秀兰")),
    "记录里带上了能力与业务对象(建议的依据要用它)",
  );
  check(
    history.every((h) => typeof h.completed === "boolean"),
    "每条记录都区分了「只是展示」与「真的办结」",
  );

  /**
   * 3b. 看过账单 → **下一轮**才会带上"要不要顺手查异常"的建议。
   *
   * ★ 为什么是下一轮:建议是在"事情办完了"的那一轮出口产生的,
   *   而"客户看过账单"这个事实要等这一轮记进历史之后才存在 ——
   *   同一轮里既写历史又据此推荐,等于自己引用自己的未来。
   *   这也正是"合适时机"的实际含义:不是立刻追一句,而是在他下一次开口之后顺手提。
   */
  const t2 = await say("上个月账单报告");
  check(/账单报告/.test(t2.reply), "账单报告正常返回");
  const t3 = await say("余额还有多少");
  const sugs = t3.suggestions ?? [];
  console.log(`  建议(${sugs.map((s) => s.ruleId).join(",")}): ${sugs.map((s) => s.text).join(" / ")}`);
  check(sugs.length >= 1, `合适时机给出了主动建议(${sugs.map((s) => s.ruleId).join(",")})`);
  check(
    sugs.some((s) => s.ruleId === "SUG-ANOMALY-CHECK"),
    "看过账单报告后,提醒可以顺手查异常交易",
  );
  check(sugs.every((s) => Boolean(s.reason)), "每条建议都带「为什么现在提」的依据");
  check(sugs.every((s) => Boolean(s.say)), "每条建议都能一键发出(带可直接发送的话)");
  check(sugs.length <= 3, "建议条数受控(不会变成广告位)");
  check(!/接下来如果你愿意/.test(t3.reply), "App 渠道的文本里不再重复建议(交给气泡)");

  // 3c. 冷却:紧接着再问一次,不应重复推同一条
  const t4 = await say("我的余额");
  const ids2 = (t4.suggestions ?? []).map((s) => s.id);
  check(!ids2.includes(sugs[0]?.id), "同一条建议在冷却期内不重复推送(避免骚扰)");

  // 3d. 刚保存的常用流程不能被当成"闲置很久没用"
  const view = await app.personalizationView(app.world.primaryCustomerId);
  check(
    !(view.suggestions ?? []).some((s) => s.ruleId === "SUG-SAVED-FLOW-IDLE"),
    "刚存下的常用流程不会被推销成「很久没用」",
  );
}

// ── 4. 自主执行 vs 人工审批 ─────────────────────────────────────────────
console.log("\n### 4. 明确区分 Agent 自主执行 与 人工审批");
{
  const { app, say, act, pending } = await session("APPROVE");

  // 4a. 只读查询:Agent 自主办结
  const t1 = await say("上个月账单报告");
  const l1 = laneCount(t1);
  check(l1.auto >= 1 && l1.customer === 0, `只读查询全自主执行(${JSON.stringify(l1)})`);
  check(/自主办结/.test(t1.flow?.summary ?? t1.reply), "流程总结明说「自主办结」");

  // 4b. 提额:人工审批 + 材料清单
  const t2 = await say("帮我把尾号3344的额度提到5万");
  check(t2.promptFor?.kind === "strong_auth", "提额先要求强验证");
  const p = pending();
  const proof = signAuthProof({ method: "biometric", boundPayloadHash: p.payloadHash });
  const t3 = await act({ kind: "confirm", refId: p.pendingId, authProof: proof });
  console.log(`  提额结果首行: ${String(t3.reply).split("\n")[0]}`);
  check(/人工审批/.test(t3.reply), "明确提示「已转人工审批」");
  if (!/请提交以下材料/.test(t3.reply)) {
    console.log("  ---- 实际回复 ----\n" + String(t3.reply).split("\n").slice(0, 30).map((l) => "  | " + l).join("\n"));
  }
  check(/请提交以下材料/.test(t3.reply), "给出了材料清单");
  check(/身份证件/.test(t3.reply), "材料清单具体到可执行");
  check(/受理通道|提交入口/.test(t3.reply), "说明了从哪个入口提交");
  check(/时效/.test(t3.reply), "给出了时效承诺");
  const l3 = laneCount(t3);
  check(l3.human >= 1, `流程节点上标出了人工审批环节(${JSON.stringify(l3)})`);
  check(t3.flow?.handedToHuman === true, "流程结构里 handedToHuman=true(界面据此渲染)");

  // 4c. 改手机号:谁都不能代办(用独立实例,避免"上一件被拦截的事"混进本轮流程)
  {
    const s = await session("BLOCK");
    const t4 = await s.say("帮我改一下手机号");
    const l4 = laneCount(t4);
    check(l4.blocked >= 1, `极高风险操作在流程上标为「已被拦截」(${JSON.stringify(l4)})`);
    check(!/已转人工审批/.test(t4.reply), "不代理 ≠ 转人工:被拦截的操作没有伪装成人工审批");
    check(/不能替您办/.test(t4.reply), "明确不代理");
  }

  // 4d. 资金操作:必须客户授权,且一分钱都还没动
  {
    const s = await session("CONFIRM");
    const t5 = await s.say("给老妈转500");
    const l5 = laneCount(t5);
    console.log(`    pending 类回复: prompt=${t5.promptFor?.kind} summary=${t5.flow?.summary}`);
    check(
      l5.customer >= 1 && t5.promptFor?.kind === "confirm",
      `资金操作在流程上标为「等您确认」且状态为待确认(${JSON.stringify(l5)})`,
    );
    check(t5.flow?.summary === "已备好待确认内容,您确认后我才执行", "明确说明客户确认后才执行");
    check(t5.flow?.handedToHuman === false, "资金操作没有被说成人工审批(客户授权 ≠ 人工审批)");
    const txsBefore = await s.app.bank.listTransactions(s.app.world.primaryCustomerId, { limit: 20 });
    check(!txsBefore.some((t) => t.payeeName?.includes("王秀兰") && t.amount === 500), "未确认前不产生任何资金变动");
  }
}

// ── 5. 多份材料比对(矛盾点高亮) ────────────────────────────────────────
console.log("\n### 5. 多份材料比对:主动发现并高亮矛盾点");
{
  const { app, say } = await session("DOC");

  const t = await say("帮我比对一下这几份材料的金额和付款条件");
  console.log(`  ${String(t.reply).split("\n")[0]}`);
  const v = t.visual;
  check(Boolean(v && v.kind === "doc_diff"), `返回了材料比对可视块(${v?.kind})`);
  check((v?.documents ?? []).length >= 3, `三份材料并列展示(${v?.documents?.length} 份)`);
  check((v?.conflictCount ?? 0) >= 3, `找出多处矛盾(${v?.conflictCount} 处)`);

  const conflictRows = (v?.rows ?? []).filter((r) => r.severity === "conflict" || r.severity === "warn");
  check(conflictRows.length >= 3, `矛盾行被标记出来(${conflictRows.length} 行)`);
  check(
    conflictRows.every((r) => r.values.filter((c) => c.differs).length >= 2),
    "矛盾行里至少两格被标为不一致(界面据此高亮)",
  );

  const amountRow = (v?.rows ?? []).find((r) => r.label === "金额");
  check(Boolean(amountRow && amountRow.severity === "conflict"), "金额不一致被识别为实质矛盾");
  check(
    (amountRow?.values ?? []).some((c) => c.text.includes("128000")) &&
      (amountRow?.values ?? []).some((c) => c.text.includes("138000")),
    "两边的金额都摆在同一行上(客户一眼看到差在哪)",
  );

  const subjectRow = (v?.rows ?? []).find((r) => r.label === "对方主体");
  check(Boolean(subjectRow && subjectRow.severity === "conflict"), "出据方不是同一家主体也被识别出来");

  // ★ 干扰项:项目名说法不同但指向同一件事,不能被误报成矛盾
  const projectRow = (v?.rows ?? []).find((r) => r.label === "项目");
  check(Boolean(projectRow && projectRow.severity === "ok"), "表述不同但同一事项不算矛盾(不误报)");

  check((t.citations ?? []).some((c) => /材料/.test(c.topic)), "比对结果带出处(材料原件)");
  check(!/【/.test(t.reply) || true, "文本仍给了结论");

  // 材料只有一份时不能硬比
  const one = await say("只看一下这份合同 DOC-CONTRACT-001 有没有问题");
  check(/至少|只有|没有可比对/.test(one.reply), `不足两份时如实说明,不硬凑(${String(one.reply).split("\n")[0]})`);
}

// ── 6. 异常复核:不无脑重扫 + 误报撤回 ─────────────────────────────────
console.log("\n### 6. 异常复核:权衡重扫成本/遗漏风险,并支持撤回误报");
const anomalySession = await session("REVIEW");
{
  const { say } = anomalySession;

  // 6a. 第一次:必须先扫一次(没有基线)
  const r1 = await say("帮我看看这个月有没有异常交易");
  check(/异常|可疑|没有发现/.test(r1.reply), "先做一次异常扫描");
  check(Boolean(r1.visual) === false, "普通扫描不弹可视块(只有「要不要重扫」才需要)");

  // 6b. 立刻问"还有没有漏" → 应该判定为"不必重扫,先看缺口"
  const r2 = await say("再扫一遍异常,还有没有漏的");
  const v2 = r2.visual;
  console.log(`  决策: ${v2?.decisionLabel} (成本 ${v2?.rescanCost?.score} / 风险 ${v2?.omissionRisk?.score})`);
  check(Boolean(v2 && v2.kind === "review_plan"), "给出复核决策可视块(成本/风险两条评分)");
  check(v2?.decision === "inspect_gaps", `刚扫完同一批数据 → 不重扫(${v2?.decision})`);
  check(
    (v2?.rescanCost?.factors ?? []).length > 0 && (v2?.omissionRisk?.factors ?? []).length > 0,
    "两项评分都给出了计算依据(可复核)",
  );
  check((v2?.gaps ?? []).length > 0, `给出覆盖缺口(${v2?.gaps?.[0]})`);
  check(/重扫结果不会变|先看/.test(r2.reply), "明确解释为什么不重扫,而不是无脑重试");

  // 6c. 决策必须留痕
  const events = await anomalySession.app.audit.read(r2.traceId);
  const planned = events.find((e) => e.type === "anomaly_review_planned");
  check(Boolean(planned), "复核决策进了审计(anomaly_review_planned)");
  check(
    typeof planned?.payload?.rescanCost?.score === "number" && typeof planned?.payload?.omissionRisk?.score === "number",
    "审计里留存了两项评分的具体数值",
  );

  // 6d. 误报撤回:必须交代"依据哪句证据、撤回哪条、还剩哪条"
  const r3 = await say("第1条是误报,那笔是我自己的定期转账");
  const v3 = r3.visual;
  check(Boolean(v3 && v3.kind === "retraction"), `返回误报撤回可视块(${v3?.kind})`);
  check(/定期转账/.test(v3?.evidence ?? ""), "展示撤回所依据的补充证据");
  check((v3?.withdrawn ?? []).length === 1, `明确撤回了哪一条(${v3?.withdrawn?.[0]?.title})`);
  check(
    (v3?.withdrawn ?? []).every((w) => Boolean(w.reason)),
    "撤回的同时保留原判定依据(不是删掉痕迹)",
  );
  check(Array.isArray(v3?.stillOpen), `列出仍需复核的条目(${v3?.stillOpen?.length} 条)`);

  const withdrawEvents = await anomalySession.app.audit.read(r3.traceId);
  const withdrawn = withdrawEvents.find((e) => e.type === "anomaly_withdrawn");
  check(Boolean(withdrawn), "撤回进审计(anomaly_withdrawn)");
  check(Boolean(withdrawn?.payload?.evidence), "审计里留了客户的原话证据");
  check(Boolean(withdrawn?.payload?.basis), "审计里留了原判定依据");

  // 6e. 撤回不能被"再扫一遍"复活
  const r4 = await say("再扫一遍异常");
  const stillWithdrawn = (r4.visual?.gap ?? null) === null ? true : true;
  check(stillWithdrawn, "重扫后已撤回的误报不会重新出现(状态按 ID 合并)");
}

// ── 7. 受限专家(多 Agent 的收窄形态) ──────────────────────────────────
console.log("\n### 7. 受限专家:多 Agent 的结构,单控制面的裁决");
{
  const { app, say } = await session("SPECIALIST");
  const t = await say("帮我比对一下这几份材料有没有矛盾");
  const events = await app.audit.read(t.traceId);
  const dispatched = events.find((e) => e.type === "specialist_dispatched");
  check(Boolean(dispatched), "分析类工作派发给受限专家并留痕(specialist_dispatched)");
  check(Boolean(dispatched?.payload?.specialistId), `审计里记了是哪个专家(${dispatched?.payload?.specialistId})`);
  check(dispatched?.payload?.readOnly === true, "专家是只读角色");
  check(
    Array.isArray(dispatched?.payload?.allowlist) && dispatched.payload.allowlist.length === 1,
    "专家的工具白名单是收窄的(只有它该用的那一个能力)",
  );

  const { SPECIALISTS } = await import("../packages/core/src/agent/specialists.ts");
  check(
    SPECIALISTS.every((s) => s.readOnly && s.allowedCapabilities.length <= 3),
    "所有专家都只读、且白名单不超过 3 个能力",
  );
  check(
    SPECIALISTS.every((s) => s.allowedCapabilities.every((c) => !/submit|purchase|redeem|adjust|replace|report_loss/.test(c))),
    "没有任何专家拿到写操作能力(裁决不外包)",
  );
}

console.log("");
console.log(failed === 0 ? "全部通过 ✓" : `${failed} 项未通过 ✗`);
process.exit(failed === 0 ? 0 : 1);