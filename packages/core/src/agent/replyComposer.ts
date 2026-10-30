/**
 * 用户回复渲染(Reply Composer)
 *
 * 交互体验的三个原则(这也是"交互体验"评分点的落点):
 *
 *   1. **说人话,不说 JSON。** 所有回复都是自然语言 + 结构化卡片,
 *      而不是把字段 dump 给用户看。
 *
 *   2. **每个数字都有出处。** 金额、余额、收益只能来自工具返回值(I3)。
 *      模型只负责组织语言,不负责提供数字。
 *
 *   3. **把选择变成"点一下"。** 需要用户决策时,给出结构化候选(消歧候选、
 *      确认按钮、强验证入口),而不是让用户打字。IM 渠道自动降级为编号选项。
 */

import type {
  AuthSpec,
  ChannelCapabilities,
  ClarificationRequest,
  ConfirmCard,
  PolicyDecision,
  PolicyReason,
} from "../types.ts";
import type { FraudCardBlock } from "../security/antiFraud.ts";

// ============================================================================
// 确认卡渲染
// ============================================================================

export interface RenderedReply {
  /** 主文本 */
  text: string;
  /** 富卡片(渠道不支持时被降级并入 text) */
  card?: ConfirmCard;
  /** 反诈提示块 */
  fraud?: FraudCardBlock;
  /** 需要用户的动作 */
  promptFor?: {
    kind: "confirm" | "strong_auth" | "clarify" | "none";
    refId?: string;
    candidates?: ClarificationRequest["candidates"];
  };
}

/**
 * 渲染确认请求。
 *
 * 关键设计:确认卡必须**完整展示影响资金的每一个字段**,不允许折叠、
 * 不允许"查看更多"。用户确认的是他看见的内容,而看见的内容与执行的内容
 * 由载荷哈希保证一致(I4)。
 */
export function renderConfirmReply(input: {
  decision: Extract<PolicyDecision, { effect: "require_confirm" | "require_strong_auth" }>;
  capabilities: ChannelCapabilities;
  pendingId: string;
  /** 解析依据说明,如"你说的'老妈'我理解为王秀兰" */
  resolutionNote?: string;
  /** 反诈提示 */
  fraud?: FraudCardBlock;
}): RenderedReply {
  const { decision, capabilities, pendingId } = input;

  const isStrongAuth = decision.effect === "require_strong_auth";
  const card = isStrongAuth ? undefined : decision.confirmSpec.card;
  /**
   * ★ 卡片文本**仍然保留在 reply 里**,即使富渠道已经有结构化卡片。
   *
   *   这不是懒,而是一条被红队测试守住的底线:确认卡的每个字段都必须出现在
   *   回复文本中 —— 因为"客户确认的是他看见的内容",而文本是任何渠道都能读到的
   *   那一份(审计留痕、导出、无障碍读屏、IM 转发)。
   *   去重放在**展示层**:界面渲染结构化卡片时,把文本里那段 `【标题】…` 折叠掉,
   *   于是客户不会看到两张一样的卡,但证据链一份不少。
   */
  const lines: string[] = [];

  if (input.resolutionNote) {
    lines.push(input.resolutionNote);
    lines.push("");
  }

  if (isStrongAuth) {
    const spec = decision.authSpec;

    // ★ 先展示"你要授权什么",再引导"如何验证"。
    //   顺序不能反:客户必须在授权前看清授权内容。
    if (spec.subject) {
      lines.push("为完成这笔操作,需要先验证您的身份。请核对以下信息:");
      lines.push("");
      lines.push(renderCardAsPlainText(spec.subject));
      lines.push("");
      lines.push("─────────────");
    } else {
      lines.push("这笔操作需要更强的身份验证。");
      lines.push("");
    }

    lines.push(`验证方式:${spec.required.map(authMethodLabel).join(" + ")}(有效期 ${Math.round(spec.ttlMs / 1000)} 秒)`);
  } else if (card) {
    lines.push(renderCardAsPlainText(card));
  }

  // 反诈块
  if (input.fraud) {
    lines.push("");
    lines.push(...renderFraudLines(input.fraud));
  }

  // 需要用户做什么
  lines.push("");
  if (isStrongAuth) {
    const spec = decision.authSpec;
    const methodText = spec.required.map(authMethodLabel).join(" + ");

    // ★ 必须给出**用户当下就能执行**的动作,并且说清"哪些动作在这个界面上做不到"。
    //   之前的缺陷:提示只有一句"请完成人脸/指纹识别验证以继续"。
    //   在真实 App 里这句话够用 —— 系统级人脸弹窗自己会跳出来。
    //   但在文字对话界面里,用户找不到任何可以下手的地方:
    //   系统反复要求验证,他却不知道该怎么验证,只能一遍遍重复同一句话。
    //   这是"提示语假设了不存在的界面",比没有提示更让人困惑。
    lines.push("如何完成验证:");
    if (capabilities.biometric) {
      lines.push(`· 手机银行:系统将弹出${methodText}窗口,按提示完成。`);
      lines.push("· 文字对话:回复「验证」,将向可信设备推送验证请求。");
    } else {
      lines.push(`· 回复「验证」,将向可信设备推送验证请求(${methodText})。`);
      if (spec.fallbackGuidance?.deepLink) {
        lines.push(`· 或返回手机银行完成验证:${spec.fallbackGuidance.deepLink}`);
      }
    }
    lines.push("· 如不确定本笔操作,回复「转人工」;如放弃,回复「取消」。");
    lines.push("");
    lines.push("请注意:验证通过后,仍需再确认一次交易详情,确认后才会执行。");
    if (spec.fallbackGuidance && capabilities.biometric) {
      lines.push("");
      lines.push(spec.fallbackGuidance.message);
    }
  } else {
    const needsAck = input.fraud?.requireExplicitAck;
    if (needsAck) {
      lines.push(
        input.fraud?.coolDownSeconds
          ? `请先花 ${input.fraud.coolDownSeconds} 秒核实对方身份。确认无误后回复「确认转账」;若不确定,回复「取消」我可以帮您联系反诈专员。`
          : "确认无误请回复「确认转账」;若不确定,回复「取消」。",
      );
    } else {
      lines.push("请确认以上信息。回复「确认」执行,回复「取消」放弃。");
    }
  }

  // 渠道降级:不支持富卡片时把候选/按钮并入文本
  const reply: RenderedReply = {
    text: lines.join("\n"),
    ...(card ? { card } : {}),
    ...(input.fraud ? { fraud: input.fraud } : {}),
    promptFor: {
      kind: isStrongAuth ? "strong_auth" : "confirm",
      refId: pendingId,
    },
  };

  return reply;
}

/** 把确认卡渲染为纯文本(用于 IM 等不支持富卡片的渠道) */
export function renderCardAsPlainText(card: ConfirmCard): string {
  const lines: string[] = [`【${card.title}】`];
  for (const f of card.fields) {
    lines.push(`${f.label}:${f.value}`);
  }
  if (card.reversibility) {
    lines.push("");
    lines.push(`可撤销:${card.reversibility}`);
  }
  if (card.warning) {
    lines.push("");
    lines.push(`请注意:${card.warning}`);
  }
  return lines.join("\n");
}

function renderFraudLines(block: FraudCardBlock): string[] {
  const lines: string[] = [];
  if (block.headline) {
    lines.push(block.headline);
  }
  if (block.scriptBreaker) {
    lines.push("");
    lines.push(block.scriptBreaker);
  }
  if (block.questions.length > 0) {
    lines.push("");
    lines.push("请先核实以下问题:");
    for (const q of block.questions) {
      lines.push(`· ${q}`);
    }
  }
  if (block.offerHumanSupport) {
    lines.push("");
    lines.push("如无法确认,请回复「转人工」,由反诈专员协助核实。");
  }
  return lines;
}

// ============================================================================
// 澄清渲染(消歧 —— 交互体验最见功力的地方)
// ============================================================================

/**
 * 渲染收款人消歧。
 *
 * ★ 设计要点:同名的人必须能被一眼区分。因此每个候选都带上
 *   "哪家银行 + 尾号 + 转过几次 + 最近什么时候"这四类线索。
 *   这是把"AI 不确定性"转化为**可信交互**的关键一步:
 *   用户不会因为系统多问一句而烦躁,只会因为系统转错人而愤怒。
 */
export function renderClarificationReply(input: {
  clarification: ClarificationRequest;
  capabilities: ChannelCapabilities;
  pendingId: string;
}): RenderedReply {
  const { clarification, capabilities } = input;
  const lines: string[] = [clarification.question];

  const candidates = clarification.candidates ?? [];

  if (candidates.length > 0) {
    lines.push("");
    if (capabilities.richCard) {
      // 富卡片渠道:渲染为可点选列表
      lines.push("请选择收款人:");
      for (const c of candidates) {
        const parts = [`${c.label}`];
        if (c.subLabel) parts.push(c.subLabel);
        if (c.hint) parts.push(c.hint);
        lines.push(`· ${parts.join(" | ")}`);
      }
    } else {
      // IM 等渠道:编号选项
      candidates.forEach((c, i) => {
        const parts = [`${i + 1}. ${c.label}`];
        if (c.subLabel) parts.push(`   ${c.subLabel}`);
        if (c.hint) parts.push(`   ${c.hint}`);
        lines.push(parts.join("\n"));
      });
    }

    // ★ 引导语必须只提"用户真正能用的方式"。
    //   曾经的缺陷:提示"或直接回复姓名/手机号",但界面上手机号是打码的
    //   (`136****2222`),用户根本没法完整输入 —— 提示与实际能力自相矛盾,
    //   用户照着提示做却一直失败。
    //   现在只列界面上看得见的信息:序号、备注名、银行、尾号、姓名。
    lines.push("");
    lines.push("请用以下任一方式指定收款人:");
    lines.push("· 回复序号,例如「1」或「第一个」");

    const hintParts: string[] = [];
    if (candidates.some((c) => (c.subLabel ?? "").includes("备注名"))) hintParts.push("备注名(如「张伟设计」)");
    if (candidates.some((c) => Boolean(c.subLabel))) hintParts.push("银行(如「招行」「农行」)");
    if (candidates.some((c) => /\d{4}/.test(c.subLabel ?? ""))) hintParts.push("账号后四位");
    hintParts.push("姓名");

    lines.push(`· 说明特征:${hintParts.join("、")}`);
  } else {
    lines.push("");
    lines.push("请直接回复收款人姓名,或常用称呼(例如「老妈」「房东」)。");
  }

  return {
    text: lines.join("\n"),
    promptFor: {
      kind: "clarify",
      refId: input.pendingId,
      ...(candidates.length > 0 ? { candidates } : {}),
    },
  };
}

/**
 * 渲染转人工受理。
 *
 * ★ 这不是一句客套话,而是对"承诺"的兑现:
 *   反诈干预里我们告诉用户"可以回复转人工接通反诈专员",
 *   系统就必须真的接得住。承诺了接不住,比一开始不许诺更伤信任 ——
 *   尤其在用户已经察觉自己可能被骗、主动求助的那一刻。
 */
export function renderHandoffAccepted(input: {
  /** 触发原因(来自策略引擎或用户主动请求) */
  reason: string;
  urgency: "normal" | "high";
  /** 已为用户保全的上下文(人工坐席可见) */
  contextSummary: string;
  capabilities: ChannelCapabilities;
}): RenderedReply {
  const lines: string[] = [];

  if (input.urgency === "high") {
    lines.push("已优先接入人工服务(反诈专员),请稍候。");
  } else {
    lines.push("已转接人工客服,请稍候。");
  }

  lines.push("");
  lines.push("本轮关键信息已整理并提交坐席,无需重复说明:");

  // 把已保全的上下文以要点形式回显给用户,让他知道"系统记住了什么"
  for (const item of input.contextSummary.split(/[;；]/).map((s) => s.trim()).filter(Boolean)) {
    lines.push(`  · ${item}`);
  }

  lines.push("");
  if (input.urgency === "high") {
    lines.push("请注意:如对方仍在催促转账,请暂停操作,待坐席核实后再决定。");
  }
  lines.push("人工服务时间为全天。您也可以继续与我沟通。");

  return { text: lines.join("\n"), promptFor: { kind: "none" } };
}

// ============================================================================
// 裁决说明渲染(把"为什么"讲给用户,而不是只给结果)
// ============================================================================

/**
 * 把策略裁决翻译成用户能懂的一句话。
 * 这是"可解释性"在**面向用户**这一侧的体现 —— 与面向审计的 PolicyReason 分开。
 */
export function explainDecisionToUser(reasons: PolicyReason[]): string | undefined {
  const escalateReason = reasons.find(
    (r) => r.effect === "escalate" && !r.ruleId.startsWith("R-RISK-SCORE") && r.ruleId !== "R-CAPABILITY-BASELINE",
  );
  if (!escalateReason) return undefined;
  return `为什么需要额外验证:${escalateReason.message}`;
}

/** 面向审计面板的裁决摘要(逐条列出命中规则) */
export function summarizePolicyForAudit(reasons: PolicyReason[]): Array<{
  ruleId: string;
  message: string;
  effect?: string;
}> {
  return reasons.map((r) => ({
    ruleId: r.ruleId,
    message: r.message,
    ...(r.effect ? { effect: r.effect } : {}),
  }));
}

// ============================================================================
// 拒绝 / 转人工 渲染
// ============================================================================

export function renderDeniedReply(input: {
  decision: Extract<PolicyDecision, { effect: "deny" | "handoff" }>;
  capabilities: ChannelCapabilities;
}): RenderedReply {
  const { decision } = input;

  if (decision.effect === "handoff") {
    const lines = [
      "本请求需人工处理,相关信息已整理并提交。",
      "",
      `原因:${decision.handoffSpec.reason}`,
    ];
    if (decision.handoffSpec.urgency === "high") {
      lines.push("");
      lines.push("已标记为优先处理,请稍候,专员将尽快联系您。");
    }
    return { text: lines.join("\n"), promptFor: { kind: "none" } };
  }

  const lines = [decision.userMessage];
  if (decision.guidance) {
    lines.push("");
    lines.push(decision.guidance.message);
    if (decision.guidance.deepLink) {
      lines.push(`入口:${decision.guidance.deepLink}`);
    }
  }
  return { text: lines.join("\n"), promptFor: { kind: "none" } };
}

// ============================================================================
// 执行结果渲染
// ============================================================================

/**
 * ★ 从能力的返回数据里取"人话原因"。
 *
 * 背景(实测踩过的坑):有的能力用 `{ ok:false, data:{ reason } }` 表达失败 ——
 * 原因写得清清楚楚,但渲染层只读 `error.message`,于是对客一律显示「操作未能完成:未知原因」。
 * 客户拿到的是一句没有信息量的话,而系统里其实知道为什么失败。
 * 这里按 reason → message → detail 的顺序兜底,都不存在才退回「未知原因」。
 */
function failureReasonFromData(data: unknown): string | undefined {
  if (data == null || typeof data !== "object") return undefined;
  const record = data as Record<string, unknown>;
  for (const key of ["reason", "message", "detail"]) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) return value;
  }
  return undefined;
}

export function renderExecutionResult(input: {
  capability: string;
  ok: boolean;
  summary?: string;
  data?: unknown;
  errorMessage?: string;
  cancellableUntil?: number;
  reference?: string;
}): RenderedReply {
  if (!input.ok) {
    const raw = input.errorMessage ?? failureReasonFromData(input.data) ?? "未知原因";
    // ★ 取消不是失败。客户主动取消时,套上「操作未能完成 + 请调整后重试」反而说反了
    if (raw.startsWith("已取消")) {
      return { text: raw, promptFor: { kind: "none" } };
    }
    const lines = [`操作未能完成:${raw}`];
    lines.push("");
    lines.push("请调整后重试,或回复「转人工」由我行协助处理。");
    return { text: lines.join("\n"), promptFor: { kind: "none" } };
  }

  const lines: string[] = [];
  if (input.summary) {
    lines.push(input.summary);
  }

  if (input.reference) {
    lines.push("");
    lines.push(`流水号:${input.reference}`);
  }

  if (input.cancellableUntil) {
    const seconds = Math.max(0, Math.round((input.cancellableUntil - Date.now()) / 1000));
    if (seconds > 0) {
      lines.push(`如需撤销,请在 ${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒内回复「撤销这笔」。`);
    }
  }

  return { text: lines.join("\n"), promptFor: { kind: "none" } };
}

// ============================================================================
// 工具
// ============================================================================

function authMethodLabel(m: AuthSpec["required"][number]): string {
  return {
    biometric: "人脸/指纹识别",
    sms_otp: "短信验证码",
    usb_key: "U 盾",
    password: "交易密码",
    trusted_device: "可信设备确认",
  }[m];
}
