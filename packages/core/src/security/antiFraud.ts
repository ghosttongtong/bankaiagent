/**
 * 反诈干预模块(Anti-Fraud Intervention)
 *
 * ★ 为什么这是本项目最有价值的创新点:
 *
 *   在真实世界里,银行的转账拦截几乎全部发生在**事后**(账户已被标记、资金已流出),
 *   或者依赖客户自己意识到被骗。而受害者被深度话术控制时,
 *   **客户自己是最不可靠的那道防线** —— 他会主动配合骗子完成验证。
 *
 *   真正的干预窗口只有转账前的那几秒。而这几秒里,传统的
 *   "弹窗提示:谨防诈骗"已经完全失效 —— 受害者会毫不犹豫地点确定。
 *
 *   本模块的做法不是"再弹一个窗",而是:
 *     1. 从**用户的自然语言**里识别受骗话术特征(被催促/被要求保密/被指导操作)
 *        —— 这是对话式 Agent 独有的信号,传统 App 根本拿不到;
 *     2. 区分"该客户是不是受骗者"(需要保护)与"该客户是不是骗子"(需要拦截);
 *     3. 对受骗者使用**打破话术控制**的干预,而不是单纯警告:
 *        冷静期(剥离紧迫感)+ 关键提问(引导其自己发现矛盾)+ 具体话术拆解(点名骗局);
 *     4. 全程**不指责客户**:被指责的受害者会为了维护自尊而坚持转账。
 *
 *   这套设计对应真实反诈工作的成熟经验,可直接写进答辩材料。
 */

import type { PolicyReason } from "../types.ts";
import type { FraudSignals } from "../intent/schema.ts";

/**
 * 反诈信号的宽松输入形态。
 * 允许调用方传入只带部分字段的对象(例如从入参中恢复的即时信号),
 * 缺失字段按"未命中"处理。
 */
export interface FraudSignalsLike {
  urgency?: boolean | undefined;
  secrecy?: boolean | undefined;
  guided?: boolean | undefined;
  keywords?: string[] | undefined;
  note?: string | undefined;
}

// ============================================================================
// 风险等级
// ============================================================================

export type FraudRiskLevel = "none" | "low" | "medium" | "high";

/** 命中的诈骗类型画像 */
export type ScamProfile =
  | "investment" // 虚假投资理财(杀猪盘)
  | "impersonation_authority" // 冒充公检法
  | "fake_customer_service" // 冒充电商/物流客服退款
  | "brushing" // 刷单返利
  | "romance" // 婚恋交友
  | "impersonation_acquaintance" // 冒充亲友/领导
  | "loan_fee" // 贷款先收费
  | "unknown";

export interface FraudAssessment {
  level: FraudRiskLevel;
  /** 0–100 干预强度分 */
  score: number;
  profile: ScamProfile;
  /** 命中的特征(可解释) */
  indicators: Array<{ id: string; label: string; detail: string }>;
  /** 建议的干预动作 */
  intervention: Intervention;
  reasons: PolicyReason[];
}

export interface Intervention {
  /** 是否要求冷静期 */
  coolDown: { required: boolean; seconds: number; reason: string };
  /** 强提示文案(确认卡顶部) */
  headline?: string;
  /** 具体话术拆解 —— 点名骗局套路,这是打破控制的关键 */
  scriptBreaker?: string;
  /** 引导客户自证的提问(开放式,不指责) */
  reflectionQuestions: string[];
  /** 是否建议转人工反诈专员 */
  suggestHumanSupport: boolean;
  /** 是否建议延迟执行(而非直接拒绝) */
  suggestDelay: boolean;
}

// ============================================================================
// 输入
// ============================================================================

export interface FraudCheckInput {
  /** 模型/规则提取的话术信号。宽松形态:缺失字段按"未命中"处理 */
  signals?: FraudSignalsLike | FraudSignals;
  /** 转账金额与客户画像 */
  amount: number;
  amountRatioToBaseline: number;
  /** 收款人特征 */
  payee: {
    name: string;
    isFirstTime: boolean;
    isSelfOwned: boolean;
    successCount: number;
    bankName: string;
  };
  /** 客户话语原文(用于补充关键词判断) */
  userText: string;
  /** 备注内容(骗子常要求备注"借款""还款""货款"等) */
  memo?: string;
  /** 客户年龄(如有,高龄是受骗高风险因子) */
  customerAge?: number;
  /** 近期是否已有多次向同一收款人的转账 */
  recentTransfersToPayee?: number;
}

// ============================================================================
// 主评估函数
// ============================================================================

/** 诈骗场景关键词库 —— 按画像分类 */
const PROFILE_KEYWORDS: Array<{ profile: ScamProfile; label: string; keywords: string[] }> = [
  {
    profile: "investment",
    label: "虚假投资理财",
    keywords: ["投资平台", "导师", "内幕", "稳赚", "收益率", "数字货币", "炒币", "期货", "内部渠道", "跟着老师", "入金", "出金", "保证金", "解冻费"],
  },
  {
    profile: "impersonation_authority",
    label: "冒充公检法",
    keywords: ["安全账户", "资金清查", "洗钱", "涉案", "公检法", "警察", "检察院", "法院", "通缉", "配合调查", "资金公证"],
  },
  {
    profile: "fake_customer_service",
    label: "冒充电商物流客服",
    keywords: ["客服退款", "快递理赔", "订单异常", "会员扣费", "退款要交", "验证资金", "屏幕共享"],
  },
  {
    profile: "brushing",
    label: "刷单返利",
    keywords: ["刷单", "返利", "垫付", "做任务", "佣金", "抢单", "连单"],
  },
  { profile: "romance", label: "婚恋交友", keywords: ["网恋", "相亲对象", "交友软件", "异地恋"] },
  {
    profile: "impersonation_acquaintance",
    label: "冒充亲友领导",
    keywords: ["领导", "老板", "换号了", "新号码", "我是你", "借钱应急", "救急"],
  },
  { profile: "loan_fee", label: "贷款先收费", keywords: ["贷款", "放款", "包装费", "手续费", "刷流水"] },
];

/** 备注里的危险信号:骗子常要求填写特定备注以规避风控 */
const RISKY_MEMO_PATTERNS = [
  { re: /借款|还款|欠款|还钱/, label: "备注为借贷名义", detail: "骗子常要求填写「借款/还款」以伪装成正常资金往来" },
  { re: /货款|定金|尾款|合同款/, label: "备注为商业名义", detail: "骗子常要求填写「货款/定金」以规避风控识别" },
  { re: /彩礼|礼金|赠与|红包/, label: "备注为赠与名义", detail: "此类名义事后难以追回" },
  { re: /投资|理财|入金|保证金/, label: "备注涉及投资", detail: "正规投资不会要求向个人账户转账" },
];

export function assessFraudRisk(input: FraudCheckInput): FraudAssessment {
  const indicators: FraudAssessment["indicators"] = [];
  const reasons: PolicyReason[] = [];
  let score = 0;

  const signals = input.signals;
  const text = input.userText;

  // ---- 特征 1–3:话术控制特征(权重最高,因为这是"正在被骗"的直接证据) ----
  if (signals?.urgency) {
    score += 30;
    indicators.push({
      id: "F-URGENCY",
      label: "被催促",
      detail: "对方要求立刻、马上转账,制造时间压力是话术控制的核心手段",
    });
  }
  if (signals?.secrecy) {
    score += 35;
    indicators.push({
      id: "F-SECRECY",
      label: "被要求保密",
      detail: "「不要告诉别人」是诈骗最典型的特征 —— 正常交易从不需要保密",
    });
  }
  if (signals?.guided) {
    score += 25;
    indicators.push({
      id: "F-GUIDED",
      label: "被指导操作",
      detail: "对方在指导您如何操作转账,这是典型的远程操控手法",
    });
  }

  // ---- 特征 4:诈骗场景关键词 → 判定画像 ----
  const hitsByProfile: Array<{ profile: ScamProfile; label: string; matched: string[] }> = [];
  for (const def of PROFILE_KEYWORDS) {
    const matched = def.keywords.filter((k) => text.includes(k));
    if (matched.length > 0) hitsByProfile.push({ profile: def.profile, label: def.label, matched });
  }
  const profile: ScamProfile = hitsByProfile[0]?.profile ?? "unknown";
  if (hitsByProfile.length > 0) {
    score += 30;
    indicators.push({
      id: "F-SCENE",
      label: `疑似${hitsByProfile[0]!.label}骗局`,
      detail: `话语中出现:${hitsByProfile.map((h) => h.matched.join("、")).join(";")}`,
    });
  }

  // ---- 特征 5:备注中的危险名义 ----
  if (input.memo) {
    for (const p of RISKY_MEMO_PATTERNS) {
      if (p.re.test(input.memo)) {
        score += 12;
        indicators.push({ id: "F-MEMO", label: p.label, detail: `${p.detail}(当前备注:「${input.memo}」)` });
        break;
      }
    }
  }

  // ---- 特征 6:大额 + 首次收款人(受骗资金流出的典型形态) ----
  if (input.payee.isFirstTime && !input.payee.isSelfOwned) {
    if (input.amountRatioToBaseline >= 1.5 || input.amount >= 10_000) {
      score += 20;
      indicators.push({
        id: "F-AMOUNT-NOVEL",
        label: "大额且收款人为首次",
        detail: "大额资金流向一个从未交易过的账户,是受骗资金外流的典型形态",
      });
    }
  }

  // ---- 特征 7:向同一新收款人连续转账 ----
  if ((input.recentTransfersToPayee ?? 0) >= 2) {
    score += 22;
    indicators.push({
      id: "F-REPEAT",
      label: "向同一收款人连续转账",
      detail: `近期已向该收款人转账 ${input.recentTransfersToPayee} 次,骗局常以「还需补一笔」为由持续索要`,
    });
  }

  // ---- 特征 8:高龄客户 ----
  if (input.customerAge != null && input.customerAge >= 65) {
    score += 10;
    indicators.push({
      id: "F-AGE",
      label: "高龄客户",
      detail: `${input.customerAge} 岁客户是电诈重点目标群体,建议提高干预强度`,
    });
  }

  // ---- 汇总结论 ----
  const realControlSignals = [signals?.urgency, signals?.secrecy, signals?.guided].filter(Boolean).length;
  let level: FraudRiskLevel = "none";
  if (score >= 70 || realControlSignals >= 3 || (realControlSignals >= 2 && hitsByProfile.length > 0)) {
    level = "high";
  } else if (score >= 40) {
    level = "medium";
  } else if (score >= 15) {
    level = "low";
  }

  const intervention = buildIntervention(level, profile, indicators, input);

  if (level !== "none") {
    reasons.push({
      ruleId: "R-FRAUD-INTERVENE",
      message: `反诈评估:${level}(评分 ${score});命中 ${indicators.length} 项特征:${
        indicators.map((i) => i.label).join("、")
      }`,
      effect: level === "high" ? "escalate" : "pass",
      evidence: { level, score, profile, indicatorIds: indicators.map((i) => i.id) },
    });
  }

  return { level, score, profile, indicators, intervention, reasons };
}

// ============================================================================
// 干预设计
// ============================================================================

/**
 * 干预强度的设计逻辑:
 *
 *   low    → 提示 + 一个引导性问题(不打断,尊重客户自主)
 *   medium → 强制冷静期 + 话术拆解(打断紧迫感,但不阻止)
 *   high   → 长冷静期 + 强提示 + 建议转反诈专员;若客户仍坚持,允许执行但留下完整审计
 *
 * ★ 设计立场:我们**不替客户做决定**,而是**确保他在不被话术控制的状态下做决定**。
 *   直接拒绝会导致客户转向其他渠道(甚至线下),反而失去干预机会。
 *   这是真实反诈工作的共识,也是本方案与"一刀切拦截"的本质区别。
 */
function buildIntervention(
  level: FraudRiskLevel,
  profile: ScamProfile,
  indicators: FraudAssessment["indicators"],
  input: FraudCheckInput,
): Intervention {
  if (level === "none") {
    return { coolDown: { required: false, seconds: 0, reason: "" }, reflectionQuestions: [], suggestHumanSupport: false, suggestDelay: false };
  }

  const profileName = PROFILE_KEYWORDS.find((p) => p.profile === profile)?.label;
  const controlIndicators = indicators.filter((i) => ["F-URGENCY", "F-SECRECY", "F-GUIDED"].includes(i.id));

  const questions: string[] = [];
  if (controlIndicators.some((i) => i.id === "F-SECRECY")) {
    questions.push("对方是不是要求您不要告诉任何人,包括家人和银行工作人员?");
  }
  if (controlIndicators.some((i) => i.id === "F-GUIDED")) {
    questions.push("是不是对方在电话或聊天里,一步一步教您怎么操作转账的?");
  }
  if (profile === "investment") {
    questions.push("这个投资机会,是不是只通过一个群或一个 App 了解到的?有没有在证监会官网查到它的资质?");
  }
  if (profile === "impersonation_authority") {
    questions.push("对方有没有提到「安全账户」或者要您把钱转到某个账户接受「审查」?公检法从不会电话要求转账。");
  }
  if (profile === "fake_customer_service") {
    questions.push("对方有没有让您开通屏幕共享,或者先转一笔钱才能拿到退款?");
  }
  if (input.payee.isFirstTime) {
    questions.push(`您之前有没有和「${input.payee.name}」有过资金往来?这次是第一次,对吗?`);
  }
  if (questions.length === 0) {
    questions.push("这笔转账的收款人,您能通过独立渠道(比如直接打电话)确认一下身份吗?");
  }

  const parts: string[] = [];
  if (controlIndicators.some((i) => i.id === "F-SECRECY")) {
    parts.push("「不要告诉别人」是诈骗最典型的特征。任何正当的交易都不会要求您保密。");
  }
  if (controlIndicators.some((i) => i.id === "F-URGENCY")) {
    parts.push("「必须马上转,否则就来不及」是在刻意制造紧迫感,让您没时间思考 —— 这是话术,不是事实。");
  }
  if (controlIndicators.some((i) => i.id === "F-GUIDED")) {
    parts.push("让您按对方指示一步步操作,是为了绕开银行的安全提醒。");
  }
  if (profileName) {
    parts.push(`您描述的情形与「${profileName}」类诈骗的典型手法高度一致。`);
  }

  if (level === "high") {
    return {
      coolDown: {
        required: true,
        seconds: 60,
        reason: "系统检测到较强受骗风险特征,建议您利用这段时间独立核实对方身份",
      },
      headline: "请注意:这笔转账存在较高受骗风险,请先阅读以下内容。",
      scriptBreaker: parts.join(" "),
      reflectionQuestions: questions.slice(0, 3),
      suggestHumanSupport: true,
      suggestDelay: true,
    };
  }

  if (level === "medium") {
    return {
      coolDown: {
        required: true,
        seconds: 30,
        reason: "为避免您在他人催促下做决定,系统设置了短暂确认间隔",
      },
      headline: "请先确认一下:这笔转账是否经过独立核实?",
      scriptBreaker: parts.join(" "),
      reflectionQuestions: questions.slice(0, 2),
      suggestHumanSupport: false,
      suggestDelay: true,
    };
  }

  return {
    coolDown: { required: false, seconds: 0, reason: "" },
    headline: "转账前提醒:请确认收款人身份",
    scriptBreaker: parts.length > 0 ? parts.join(" ") : undefined,
    reflectionQuestions: questions.slice(0, 1),
    suggestHumanSupport: false,
    suggestDelay: false,
  };
}

// ============================================================================
// 把干预渲染进确认卡(交互体验的关键:不指责、给台阶、留下核实路径)
// ============================================================================

export interface FraudCardBlock {
  /** 卡片顶部的强提示 */
  headline?: string;
  /** 话术拆解 */
  scriptBreaker?: string;
  /** 引导性问题 */
  questions: string[];
  /** 冷静期秒数 */
  coolDownSeconds: number;
  /** 是否提供转人工入口 */
  offerHumanSupport: boolean;
  /** 是否提供"我确认没被骗"的显式确认(而非默认通过) */
  requireExplicitAck: boolean;
}

export function buildFraudCardBlock(assessment: FraudAssessment): FraudCardBlock | null {
  if (assessment.level === "none") return null;
  const iv = assessment.intervention;
  return {
    ...(iv.headline ? { headline: iv.headline } : {}),
    ...(iv.scriptBreaker ? { scriptBreaker: iv.scriptBreaker } : {}),
    questions: iv.reflectionQuestions,
    coolDownSeconds: iv.coolDown.required ? iv.coolDown.seconds : 0,
    offerHumanSupport: iv.suggestHumanSupport,
    requireExplicitAck: assessment.level !== "low",
  };
}
