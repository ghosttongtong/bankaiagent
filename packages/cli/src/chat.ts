#!/usr/bin/env node
/**
 * 交互模式 —— 和 Agent 真人对聊
 *
 * ★ 为什么这个模式对比赛至关重要:
 *   脚本化演示只能证明"这 13 句话能跑通",无法证明**自主理解**。
 *   评委自己打字、说一句脚本里没有的话,才是真正的检验。
 *   请务必在答辩时留出 1–2 分钟让评委自由输入。
 *
 * 用法:
 *   node packages/cli/src/chat.ts              用 .env 里配置的模型
 *   node packages/cli/src/chat.ts --offline    强制离线(不调模型)
 *   node packages/cli/src/chat.ts --im         以 IM 渠道身份进入(体验渠道降级)
 *
 * 交互命令(直接输入即可):
 *   确认 / 取消 / 1 / 2       —— 确认操作、取消、选择候选收款人
 *   :trace                    —— 查看本轮完整决策链路
 *   :audit                    —— 查看审计事件
 *   :verify                   —— 校验审计哈希链
 *   :policy                   —— 查看当前策略配置
 *   :limits                   —— 查看权限分级矩阵
 *   :balance                  —— 查看账户余额
 *   :help                     —— 帮助
 *   :quit                     —— 退出
 */

import "dotenv/config";
import { createInterface } from "node:readline";
import { randomUUID } from "node:crypto";

import { createApp, signAuthProof, CHANNEL_CAPABILITIES } from "../../server/src/app.ts";
import { getPolicyConfig } from "../../core/src/index.ts";
import { fmtYuan } from "../../core/src/util/format.ts";
import type { AgentTurnResult, Channel } from "../../core/src/index.ts";

// ============================================================================
// 终端样式
// ============================================================================

const C = {
  reset: "\u001b[0m",
  dim: "\u001b[2m",
  bold: "\u001b[1m",
  red: "\u001b[31m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  blue: "\u001b[34m",
  magenta: "\u001b[35m",
  cyan: "\u001b[36m",
  gray: "\u001b[90m",
};

function line(char = "─", width = 76): string {
  return char.repeat(width);
}

function print(text: string): void {
  process.stdout.write(text + "\n");
}

// ============================================================================
// 主流程
// ============================================================================

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const offline = args.includes("--offline");
  const channel: Channel = args.includes("--im") ? "im" : args.includes("--web") ? "web" : "app";

  const app = await createApp({ offline });
  const sessionId = `chat-${randomUUID().slice(0, 8)}`;
  const caps = CHANNEL_CAPABILITIES[channel];

  print("");
  print(C.bold + C.cyan + line("═") + C.reset);
  print(C.bold + C.cyan + "  银行 AI 智能体 —— 交互模式" + C.reset);
  print(C.bold + C.cyan + line("═") + C.reset);
  print("");
  print(`  ${C.bold}模型${C.reset}      ${app.llm.mode === "deepseek" ? C.green : C.yellow}${app.llm.provider.name}${C.reset} / ${app.llm.provider.model}`);
  print(`  ${C.dim}${app.llm.reason}${C.reset}`);
  print(`  ${C.bold}渠道${C.reset}      ${channel}(${C.gray}风险等级 ${caps.risk},富卡片 ${caps.richCard ? "支持" : "不支持"}${C.reset})`);
  print(`  ${C.bold}会话${C.reset}      ${sessionId}`);
  print("");

  // 账户概况
  const accounts = await app.bank.listAccounts(app.world.primaryCustomerId);
  print(`  ${C.bold}账户${C.reset}`);
  for (const a of accounts) {
    const label = { current: "活期", savings: "储蓄", credit: "信用卡", ewallet: "电子钱包" }[a.type] ?? a.type;
    print(
      `    ${label.padEnd(5)} ${a.maskedNo}  余额 ${C.bold}${fmtYuan(a.balance)}${C.reset}` +
        (a.creditLimit ? `${C.gray}(额度 ¥${a.creditLimit.toLocaleString("zh-CN")})${C.reset}` : ""),
    );
  }

  // 收款人概况
  print("");
  print(`  ${C.bold}收款人名单${C.reset}`);
  const payees = [...app.world.payees.values()].filter((p) => p.ownerCustomerId === app.world.primaryCustomerId);
  for (const p of payees) {
    const alias = p.aliases.length > 0 ? `${C.gray}别名:${p.aliases.join("/")}${C.reset}` : "";
    const history = p.successHistory.length > 0 ? `${C.gray}转过 ${p.successHistory.length} 次${C.reset}` : `${C.yellow}首次${C.reset}`;
    const flag = p.listFlag ? ` ${C.red}[${p.listFlag.listType} 名单]${C.reset}` : "";
    print(`    ${p.name.padEnd(6)} ${p.bankName.padEnd(8)} ${history} ${alias}${flag}`);
  }

  print("");
  print(C.bold + "  怎么对话" + C.reset);
  print(C.gray + "    直接说人话,例如:「给老妈转500,备注买菜」" + C.reset);
  print(C.gray + "    需要确认时会给出一张卡片 → 回复「确认」执行 / 「取消」放弃" + C.reset);
  print(C.gray + "    同名收款人时会给候选 → 回复序号「1」,或说特征如「张伟设计」「招行那个」「尾号1222」" + C.reset);
  print(C.gray + "    要求强验证时 → " + C.reset + C.cyan + "回复「验证」" + C.reset + C.gray + "(等价于真实环境的人脸识别)" + C.reset);
  print(C.gray + "    不想继续时 → 回复「取消」放弃,或回复「转人工」转接坐席" + C.reset);
  print("");
  print(C.bold + "  账单分析(第二个场景)" + C.reset);
  print(C.gray + "    试试:「上个月账单报告」「有没有异常交易」「我有哪些订阅」" + C.reset);
  print(C.gray + "         「这半年收支怎么样」「给我点省钱建议」「这个月餐饮花了多少」" + C.reset);
  print("");
  print(C.bold + "  理财(第三个场景)" + C.reset);
  print(C.gray + "    试试:「我有5万块,推荐几个理财产品」「这个和那个比哪个收益高」" + C.reset);
  print(C.gray + "         「我风险承受能力怎么样,能买股票型吗」「我的理财赚了多少」" + C.reset);
  print(C.gray + "         「帮我买1万块纯债添利」→ 回复「确认」执行" + C.reset);
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "未测评时申购会被拦下 → 回复「做风险测评」,再答「b c c c b d」" +
      C.reset,
  );
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "★ 买超出自己风险等级的产品 → 必须先回复「签确认书」," +
      C.reset +
      C.gray +
      "「确认」不能替代它" +
      C.reset,
  );
  print("");
  print(C.bold + "  卡片(第四个场景)" + C.reset);
  print(C.gray + "    试试:「我有哪些卡」「我的卡都什么状态」「尾号8888那张额度多少」" + C.reset);
  print(C.gray + "         「信用卡额度太低能不能提额」「尾号2026那张能提额吗」" + C.reset);
  print(C.gray + "         「卡为什么被限制」「卡被限制了帮我解开」" + C.reset);
  print(C.gray + "         「卡丢了先挂失」「补办这张卡」→ 换号 5 天 / 保留原号 12 天" + C.reset);
  print(C.gray + "         「尾号1145那张激活一下」「想办一张新卡」" + C.reset);
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "★ 挂失会立即冻结、不等您确认;而提额只能提交申请 —— 额度审核通过前不会变化" +
      C.reset,
  );
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "★ 改手机号 / 改密码一律不代理:这两件事只能在 App 安全中心由您本人完成" +
      C.reset,
  );
  print("");
  print(C.bold + "  订阅代扣(第五个场景)" + C.reset);
  print(C.gray + "    试试:「帮我看看哪些是自动扣费的」「我签了哪些代扣」" + C.reset);
  print(C.gray + "         「我有哪些快到期了」「下次什么时候扣钱」「爱奇艺会员多少钱」" + C.reset);
  print(C.gray + "         「把爱奇艺会员关了」「退订网易云音乐」「别再扣了」→ 先看金额与日期,再确认" + C.reset);
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "★ 识别与提醒是绿色(只读直接执行);取消是黄色(必须确认)—— 商户侧自动续费本行关不了,会如实说" +
      C.reset,
  );
  print("");
  print(C.bold + "  跨场景事件联动(第六个场景)" + C.reset);
  print(C.gray + "    试试:「我下个月15号有个重要纪念日帮我规划下」「最近有什么大额支出需要提前准备」" + C.reset);
  print(C.gray + "         「下周发工资,帮我规划一下」「您能帮我规划什么」「我有哪些重要日子」" + C.reset);
  print(C.gray + "         「执行资金操作」→ 黄色确认;「帮我订花」→ 红色强验证(两步永远分开确认)" + C.reset);
  print(
    C.gray +
      "    " +
      C.reset +
      C.yellow +
      "★ 方案生成是绿色(只读:一步都不执行);资金操作黄色;外部订购红色 —— 每一笔钱的去向与金额必须先摆出来" +
      C.reset,
  );
  print(C.gray + "    输入 :help 查看全部命令,输入 :quit 退出" + C.reset);
  print("");

  // ---- 待确认动作的上下文 ----
  // ★ 不在这里缓存待办的哈希/ID::auth 命令实时取当前待办(见 case "auth"),
  //   缓存只写不读,而且拿旧哈希签回执是错的 —— 强验证必须绑定当前这一笔。

  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });

  const prompt = (): void => {
    process.stdout.write(C.bold + C.green + "\n  您 > " + C.reset);
  };

  prompt();

  let handled = false;

  for await (const rawLine of rl) {
    const input = String(rawLine).trim();
    if (input.length === 0) {
      prompt();
      continue;
    }

    // ---- 内置命令 ----
    if (input.startsWith(":")) {
      handled = await handleCommand(input, app);
      if (handled === false) break; // :quit
      prompt();
      continue;
    }

    const envelope = app.envelope({ channel, text: input, sessionId });

    let result: AgentTurnResult;
    try {
      // 说明:「确认」「取消」「第一个」这些口语回应由 **编排器核心** 识别并路由
      //(见 orchestrator.ts 的步骤 0a)。渠道适配层不重复实现该逻辑 ——
      // 这样新增渠道时不需要再写一遍,行为也天然一致。
      result = await app.orchestrator.handleMessage(envelope);
    } catch (err) {
      print(`\n  ${C.red}执行出错:${(err as Error).message}${C.reset}`);
      prompt();
      continue;
    }

    renderTurn(result);

    /**
     * ★ 这里不再"记住"待确认动作的哈希与 ID。
     *
     *   原来记下来是为了让 `:auth` 模拟强验证;但 `:auth` 是**实时**取当前待办
     *   (见下方 latestFor),那两个变量从来没被读过 —— 只写不读。
     *   而"用记下来的旧哈希去签回执"本身是危险的:待办过期或已被替换后,
     *   旧哈希对应的操作可能已经不存在,签出来的回执指向的是空气。
     *   强验证必须绑定**当前**这一笔,所以这里直接删掉。
     */

    // 若需要强验证,明确告诉用户怎么做
    if (result.promptFor?.kind === "strong_auth") {
      print("");
      print(C.cyan + "  ⓘ 本演示环境用模拟方式完成强验证:直接回复「验证」即可(等价于真实环境的人脸识别)。" + C.reset);
      print(C.cyan + "     想看到内部细节可用 :auth 命令,它会打印回执签发与验签的完整过程。" + C.reset);
    }

    prompt();
  }

  print("");
  print(C.gray + `  会话结束。审计事件 ${app.audit.size} 条。` + C.reset);
  const verification = await app.audit.verifyChain();
  print(
    C.gray +
      `  审计链校验:${verification.intact ? C.green + "✓ 完整,未被篡改" : C.red + `✗ 断点 seq=${verification.brokenAtSeq}`}${C.reset}`,
  );
  print("");
  process.exit(0);
}

// ============================================================================
// 回合渲染
// ============================================================================

/**
 * 渲染一个回合。
 *
 * ★ 不再接收渠道能力参数:这个渲染器只服务于终端演示,输出的是纯文本,
 *   与"该渠道能不能出卡片"无关 —— 传进来也没用过(参数只写不读)。
 *   渠道能力的差异由服务端下发的结构性字段决定,不由渲染器再判一次。
 */
function renderTurn(result: AgentTurnResult): void {
  print("");

  // ★ 兜底:绝不输出空内容。
  //   曾经的缺陷:某些路径(命令处理、卡片型回复)下 reply 为空,
  //   终端上就是"输入之后什么都没有" —— 用户完全不知道系统是收到了、
  //   在处理、还是崩了。在安全相关的系统里,静默是最坏的一种失败:
  //   用户会重复操作、重复转账,或者干脆以为钱已经转出去了。
  const text = result.reply?.trim();
  if (!text) {
    if (result.card) {
      // 只有卡片没有文本 → 把卡片渲染成文本兜底
      for (const l of renderCardAsPlainText(result.card, result.terminal?.kind)) {
        print(C.magenta + "  Agent > " + C.reset + l);
      }
    } else {
      print(
        C.yellow +
          "  Agent > (这一步没有可显示的内容)" +
          C.reset +
          C.gray +
          `  [turnId=${result.turnId} 状态=${result.promptFor?.kind ?? "none"}]` +
          C.reset,
      );
      print(
        C.gray +
          "          这通常是内部状态异常。请输入 :trace 查看本轮的决策链路,便于定位。" +
          C.reset,
      );
    }
  } else {
    for (const l of text.split("\n")) {
      print(C.magenta + "  Agent > " + C.reset + l);
    }
  }

  // 策略裁决明细
  const significant = (result.policySummary ?? []).filter(
    (r) =>
      r.effect === "escalate" ||
      r.effect === "deny" ||
      r.ruleId.startsWith("R-VELOCITY") ||
      r.ruleId.startsWith("SEC-") ||
      r.ruleId.startsWith("R-FRAUD") ||
      r.ruleId === "R-USER-HANDOFF",
  );
  if (significant.length > 0) {
    print("");
    print(C.gray + "  ┌─ 策略裁决(纯确定性规则,无 LLM 参与)" + line("─", 32) + C.reset);
    for (const r of significant) {
      const icon = r.effect === "deny" ? "🛑" : r.effect === "escalate" ? "⬆️ " : "•";
      print(C.gray + `  │ ${icon} [${r.ruleId}] ${r.message}` + C.reset);
    }
    print(C.gray + "  └" + line("─", 60) + C.reset);
  }

  if (result.terminal?.kind === "denied") {
    print(C.red + `  ⛔ 已阻断:${result.terminal.detail ?? ""}` + C.reset);
  }
  if (result.terminal?.kind === "handoff") {
    print(C.yellow + `  ☎️  已转人工(状态:${result.terminal.detail ?? "已受理"})` + C.reset);
  }
  if (result.terminal?.kind === "completed") {
    print(C.green + `  操作已完成` + C.reset);
  }
  print(C.gray + `  trace: ${result.traceId.slice(0, 22)}…  (输入 :trace 查看决策链路)` + C.reset);
}

/** 把确认卡渲染为终端文本(空回复时的兜底渲染) */
function renderCardAsPlainText(
  card: { title: string; fields: Array<{ label: string; value: string }>; warning?: string; reversibility?: string },
  terminal?: string,
): string[] {
  const lines = [`【${card.title}】`];
  for (const f of card.fields) lines.push(`${f.label}:${f.value}`);
  if (card.reversibility) {
    lines.push("");
    lines.push(`可撤销:${card.reversibility}`);
  }
  if (card.warning) {
    lines.push("");
    lines.push(`请注意:${card.warning}`);
  }
  if (terminal === "completed") lines.push("", "操作已完成");
  return lines;
}

// ============================================================================
// 内置命令
// ============================================================================

async function handleCommand(
  input: string,
  app: Awaited<ReturnType<typeof createApp>>,
): Promise<boolean> {
  const cmd = input.slice(1).toLowerCase();

  switch (cmd) {
    case "quit":
    case "exit":
    case "q":
      return false;

    case "help":
      print("");
      print(C.bold + "  可用命令" + C.reset);
      print(`    :trace     查看最近一轮的完整决策链路(审计事件)`);
      print(`    :audit     查看全部审计事件(${app.audit.size} 条)`);
      print(`    :verify    校验审计哈希链完整性`);
      print(`    :policy    查看当前策略配置(阈值、窗口)`);
      print(`    :limits    查看权限分级矩阵`);
      print(`    :balance   查看账户余额`);
      print(`    :auth      展示强验证的完整内部过程(回执签发与验签细节)并执行`);
      print(`    :handoff   模拟用户请求人工协助(转人工)`);
      print(`    :clear     清屏`);
      print(`    :quit      退出`);
      print("");
      print(C.gray + "  自然语言示例:" + C.reset);
      print(C.gray + "    给老妈转500,备注买菜" + C.reset);
      print(C.gray + "    给张伟转1500                      (触发同名消歧)" + C.reset);
      print(C.gray + "    给孙浩转50                        (首次收款人 → 强验证)" + C.reset);
      print(C.gray + "    每月1号给房东转5800,房租           (定时转账)" + C.reset);
      print(C.gray + "    昨天聚餐我垫了600,和李明、王秀兰AA  (拆分收款)" + C.reset);
      print(C.gray + "    我这个月餐饮花了多少?               (消费分析)" + C.reset);
      print(C.gray + "    快转5万给周慧,是投资平台保证金,别告诉银行的人 (反诈干预)" + C.reset);
      print(C.gray + "    我有5万块,推荐几个理财产品          (理财 · 金额是预算不是转账)" + C.reset);
      print(C.gray + "    帮我买1万块那个稳健型的              (理财申购 → 需确认)" + C.reset);
      print(C.gray + "    帮我买2万块科技成长精选              (超风险等级 → 必须先「签确认书」)" + C.reset);
      print(C.gray + "    把我上次买的那个理财赎回             (多只持仓 → 列候选让您选)" + C.reset);
      print(C.gray + "    签确认书 / 做风险测评 / 我的理财赚了多少" + C.reset);
      print(C.gray + "    我有哪些卡                          (卡片 · 带编号的清单)" + C.reset);
      print(C.gray + "    信用卡额度太低能不能提额             (卡片 · 只答资格,不提交申请)" + C.reset);
      print(C.gray + "    帮我把尾号3344的额度提到5万          (卡片 · 强验证 → 申请≠已生效)" + C.reset);
      print(C.gray + "    卡被限制了帮我解开                   (卡片 · 先查原因再给方案)" + C.reset);
      print(C.gray + "    卡丢了先挂失                         (卡片 · ★ 立即冻结,不等确认)" + C.reset);
      print(C.gray + "    尾号8888那张补办一下 → 换号补卡/保留原号 (卡片 · 5 天 vs 12 天)" + C.reset);
      print(C.gray + "    尾号1145那张激活一下                 (卡片 · 激活 + 交易密码规则)" + C.reset);
      print(C.gray + "    帮我改一下手机号                     (★ 阻断级:只引导,不代理)" + C.reset);
      print(C.gray + "    帮我看看哪些是自动扣费的             (订阅 · 自动识别,含识别依据)" + C.reset);
      print(C.gray + "    我有哪些快到期了                     (订阅 · 续费提醒:金额+日期+倒计时)" + C.reset);
      print(C.gray + "    把爱奇艺会员关了                     (订阅 · 黄色:先看金额与时间再确认)" + C.reset);
      print(C.gray + "    把 iCloud 云空间关了                 (订阅 · ★ 本行没有协议:如实说关不了)" + C.reset);
      print(C.gray + "    我下个月15号有个重要纪念日帮我规划下   (事件联动 · 绿色:只出方案,一步都不执行)" + C.reset);
      print(C.gray + "    最近有什么大额支出需要提前准备        (事件联动 · 账单+资金+商户一次汇总)" + C.reset);
      print(C.gray + "    执行资金操作                        (事件联动 · 黄色:只锁自己的钱,不碰外部)" + C.reset);
      print(C.gray + "    帮我订花                            (事件联动 · 红色:外部订购,强制强验证)" + C.reset);
      print(C.gray + "    您能帮我规划什么                     (事件联动 · 可挂载的触发器清单)" + C.reset);
      print(C.gray + "    验证 / 转人工 / 取消                     (对待确认操作的回应)" + C.reset);
      print("");
      return true;

    case "balance": {
      const accounts = await app.bank.listAccounts(app.world.primaryCustomerId);
      print("");
      for (const a of accounts) {
        const label = { current: "活期", savings: "储蓄", credit: "信用卡", ewallet: "电子钱包" }[a.type] ?? a.type;
        print(`    ${label.padEnd(5)} ${a.maskedNo}  ${fmtYuan(a.balance)}`);
      }
      print("");
      return true;
    }

    case "policy": {
      const c = getPolicyConfig();
      print("");
      print(C.bold + "  策略配置(可调整,见 configurePolicy)" + C.reset);
      print(`    新收款人单笔强验证下限      ¥${c.strongAuthAbove.toLocaleString("zh-CN")}`);
      print(`    已建立信任收款人档位        ¥${c.knownPayeeStrongAuthAbove.toLocaleString("zh-CN")}`);
      print(`    长期高频收款人档位          ¥${c.trustedPayeeStrongAuthAbove.toLocaleString("zh-CN")}`);
      print(`    本人账户互转档位            ¥${c.selfOwnedStrongAuthAbove.toLocaleString("zh-CN")}`);
      print(`    单日累计限额                ¥${c.dailyLimit.toLocaleString("zh-CN")}`);
      print(`    可撤销窗口                  ${c.cancellableWindowMs / 60000} 分钟`);
      print(`    确认载荷有效期              ${c.confirmTtlMs / 1000} 秒`);
      print(`    强验证令牌有效期            ${c.actionTokenTtlMs / 1000} 秒`);
      print("");
      return true;
    }

    case "limits":
      print("");
      print(C.bold + "  权限分级矩阵" + C.reset);
      print("");
      print(C.green + "  绿 / 自动执行(无副作用,仅限本人数据域)" + C.reset);
      print("    余额查询 · 交易流水 · 消费分析 · 收款人检索 · 转账试算 · 定时任务查询");
      print("");
      print(C.yellow + "  黄 / 用户确认(载荷冻结 + 展示完整详情)" + C.reset);
      print("    小额转账 · 定时转账创建/取消 · 转账撤销 · AA 收款 · 信用卡还款");
      print("");
      print(C.red + "  红 / 强验证(人脸/短信/U盾,回执绑定载荷)" + C.reset);
      print("    大额转账 · 首次向新收款人转账(任意金额) · 跨境汇款 · 理财申购");
      print("");
      print(C.magenta + "  黑 / 阻断级(Agent 不经手,仅引导官方流程)" + C.reset);
      print("    修改绑定手机号/邮箱 · 修改各类密码 · 更换安全介质 · 关闭风控开关");
      print("");
      print(C.gray + "  演进原则:安全方向的操作(降额/冻结/取消)降级;" + C.reset);
      print(C.gray + "            扩权方向的操作(提额/新增/变更凭证)升级。" + C.reset);
      print("");
      return true;

    case "verify": {
      const v = await app.audit.verifyChain();
      print("");
      print(
        v.intact
          ? `    ${C.green}✓ 哈希链完整,${app.audit.size} 条事件均未被篡改${C.reset}`
          : `    ${C.red}✗ 检篡改!断点位于 seq=${v.brokenAtSeq}${C.reset}`,
      );
      print("");
      return true;
    }

    case "audit": {
      const events = await app.audit.readAll();
      print("");
      print(C.bold + `  审计事件(${events.length} 条,哈希链)` + C.reset);
      for (const e of events.slice(-25)) {
        const time = new Date(e.ts).toLocaleTimeString("zh-CN");
        print(
          C.gray +
            `    #${String(e.seq).padStart(3)} ${time} ${e.type.padEnd(24)} ${e.hash.slice(0, 10)}… ← ${e.prevHash.slice(0, 10)}…` +
            C.reset,
        );
      }
      if (events.length > 25) print(C.gray + `    … 仅显示最近 25 条,共 ${events.length} 条` + C.reset);
      print("");
      return true;
    }

    case "trace": {
      const events = await app.audit.readAll();
      const lastTrace = events[events.length - 1]?.traceId;
      if (!lastTrace) {
        print(C.gray + "    暂无事件" + C.reset);
        return true;
      }
      const traceEvents = events.filter((e) => e.traceId === lastTrace);
      print("");
      print(C.bold + `  本轮决策链路(trace ${lastTrace.slice(0, 24)}…)` + C.reset);
      print("");
      for (const e of traceEvents) {
        const time = new Date(e.ts).toLocaleTimeString("zh-CN");
        print(`    ${C.gray}${time}${C.reset} ${C.cyan}${e.type}${C.reset}`);
        const keys = Object.keys(e.payload).filter((k) => !k.startsWith("__"));
        for (const k of keys.slice(0, 6)) {
          const v = e.payload[k];
          const vs = typeof v === "object" ? JSON.stringify(v) : String(v);
          print(`      ${C.gray}${k}:${vs.length > 110 ? vs.slice(0, 110) + "…" : vs}${C.reset}`);
        }
      }
      print("");
      return true;
    }

    case "auth": {
      const pending = app.orchestrator.pending.latestFor(app.world.primaryCustomerId, Date.now());
      if (!pending) {
        print("");
        print(C.yellow + "  ⓘ 当前没有待确认的操作,无需验证。" + C.reset);
        print(C.gray + "     先发起一笔需要强验证的操作,例如:「给孙浩转50」(首次收款人会触发强验证)" + C.reset);
        print("");
        return true;
      }

      const input = pending.input;
      const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : null;
      const payeeName = input["payeeName"] ? String(input["payeeName"]) : "(未记录)";

      print("");
      print(C.cyan + "  ┌─ 模拟操作:完成强验证 " + line("─", 40) + C.reset);
      print(C.cyan + "  │ 真实环境下这一步发生在手机银行的原生安全环境中:" + C.reset);
      print(C.cyan + "  │   1. 弹出系统级人脸/指纹识别界面" + C.reset);
      print(C.cyan + "  │   2. 识别通过后,由安全环境用**它自己的密钥**签发验证回执" + C.reset);
      print(C.cyan + "  │   3. 回执被绑定到本次操作的载荷哈希,回跳到对话继续" + C.reset);
      print(C.cyan + "  │" + C.reset);
      print(C.cyan + "  │ Agent 全程接触不到生物特征数据,也不持有签发密钥 ——" + C.reset);
      print(C.cyan + "  │ 所以即使 Agent 被攻破,也无法伪造一份验证回执。" + C.reset);
      print(C.cyan + "  │" + C.reset);
      print(C.cyan + `  │ 本次将验证的操作:向「${payeeName}」${amount != null ? `转账 ¥${amount.toLocaleString("zh-CN")}` : pending.capability}` + C.reset);
      print(C.cyan + `  │ 载荷哈希(前 16 位):${pending.payloadHash.slice(0, 16)}…` + C.reset);
      print(C.cyan + "  └" + line("─", 62) + C.reset);
      print("");
      print(C.gray + "  ▶ 正在签发验证回执…" + C.reset);

      const proof = signAuthProof({ method: "biometric", boundPayloadHash: pending.payloadHash });
      print(C.gray + `  ▶ 已签发:method=${proof.method} issuer=${proof.issuer} nonce=${proof.nonce.slice(0, 8)}…` + C.reset);
      print(C.gray + "  ▶ 提交回执,继续执行…" + C.reset);

      const result = await app.orchestrator.confirm({
        envelope: app.envelope({ channel: "app", text: "确认", sessionId: "chat-auth" }),
        refId: pending.pendingId,
        authProof: proof,
      });
      renderTurn(result);
      return true;
    }

    case "handoff": {
      print("");
      print(C.gray + "  ▶ 模拟用户请求人工协助…" + C.reset);
      const result = await app.orchestrator.handleMessage(
        app.envelope({ channel: "app", text: "转人工", sessionId: "chat-handoff" }),
      );
      renderTurn(result);
      return true;
    }

    case "clear":
      // 大多数终端支持 ANSI 清屏
      process.stdout.write("\u001b[2J\u001b[H");
      return true;

    default:
      print(C.yellow + `    未知命令:${input}。输入 :help 查看可用命令。` + C.reset);
      return true;
  }
}

main().catch((err) => {
  console.error(C.red + "启动失败:" + C.reset, err);
  process.exit(1);
});
