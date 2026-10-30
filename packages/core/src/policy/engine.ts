/**
 * 策略引擎(Policy Engine)
 *
 * ★ 核心不变量 I1:模型永不做裁决。本文件是**纯确定性函数**,零 LLM 参与。
 *   这是系统能够通过真实审计的前提 —— 审计员可以逐条读完这里每一条规则。
 *
 * 分级不是静态阈值,而是多维风险评分 → 分级映射:
 *   风险分 = f(金额, 收款人新颖度, 画像偏离度, 渠道, 设备, 时段, 名单, 频次)
 *   静态阈值只作为兜底下限(对应 1.docx 的 1000 元线,我们把它保留为可配置下限)。
 *
 * 演进原则:凡"安全方向"的操作(降额、冻结、取消)降级;
 *          凡"扩权方向"的操作(提额、新增、变更凭证)升级。
 */

import { createHash } from "node:crypto";

import type {
  AuthSpec,
  CapabilitySpec,
  ChannelCapabilities,
  ConfirmCard,
  ConfirmSpec,
  ExecutionContext,
  Guidance,
  PolicyDecision,
  PolicyReason,
  Tier,
} from "../types.ts";
import {
  PRODUCT_RISK_LABELS,
  RISK_LEVEL_LABELS,
} from "../capabilities/wealth.ts";
import { REPLACEMENT_ETA_DAYS } from "../capabilities/card.ts";
import { EVENT_FUND_STEP_WARN_AMOUNT } from "../capabilities/eventPlan.ts";
import { capabilityLabel } from "../agent/capabilityLabels.ts";
import { fmtMoney } from "../util/format.ts";
import { LEGACY_SCORER_ID, assertModelMatchesFeatureNames, scoreWithModel, type LinearScorerModel } from "./scorer.ts";
import { LOGISTIC_V1_MODEL } from "./model/logisticV1.ts";

// ============================================================================
// 策略请求
// ============================================================================

/**
 * 由业务层提供的展示信息。
 *
 * ★ 为什么需要它:策略引擎能算出"要不要确认",但**只有业务层知道该怎么展示** ——
 *   定时转账要展示周期与下次执行时间,AA 收款要展示参与人与各自分摊额。
 *   如果让策略引擎从原始入参反推展示内容,就会出现"确认卡上只有收款人和手续费"
 *   这种空洞的卡片,用户在不知情的情况下点了确认。而"用户确认的内容必须完整"
 *   是 I4 的前提。
 */
export interface ConfirmPresentation {
  card: ConfirmCard;
  /** 与 card 严格对应的冻结载荷(参与哈希计算,保证展示与执行一致) */
  frozenPayload: Record<string, unknown>;
  /** 可选:覆盖确认卡标题 */
  title?: string;
}

export interface PolicyRequest {
  capability: CapabilitySpec;
  /** 已通过 Schema 校验的入参 */
  input: Record<string, unknown>;
  ctx: ExecutionContext;
  /** 本次会话中已意图执行的敏感动作集合(用于组合阻断) */
  sessionIntents?: string[];
  /** 是否已持有针对本载荷的有效动作令牌(强验证回执) */
  hasValidActionToken?: boolean;
  /** 业务层提供的展示内容(优先于引擎自动生成的卡片) */
  presentation?: ConfirmPresentation;
  /**
   * 频次快照(由调用方用 FrequencyLedger.observe 算好后传入)。
   *
   * ★ 为什么是"传进来"而不是引擎自己去数:
   *   evaluatePolicy 是**纯函数** —— 同一个请求任何时候算都得到同一个结论。
   *   一旦它自己去读全局计数器,同一笔操作"第一次判 allow、第二次判 blocked",
   *   裁决就变得不可复现,也就没法回归测试。
   *   计数发生在编排器(它知道这是第几次请求),判定仍然在引擎(它知道规则)。
   *   缺省(null/undefined)时所有频次规则视为未命中 —— 只读用途(如卡片预演)
   *   不需要也不应该消耗额度。
   */
  frequency?: FrequencySnapshot;
}

/** 分级强度序,用于比较与提升 */
const TIER_ORDER: Record<Tier, number> = {
  auto: 0,
  confirm: 1,
  strong_auth: 2,
  blocked: 3,
};

/** 取两个分级中更严格的一个 */
export function escalate(a: Tier, b: Tier): Tier {
  return TIER_ORDER[a] >= TIER_ORDER[b] ? a : b;
}

// ============================================================================
// 风险评分模型
// ============================================================================

export interface RiskFactor {
  /** 因子名(可解释) */
  name: string;
  /** 权重区间内的贡献值 */
  contribution: number;
  /** 因子取值说明 */
  detail: string;
}

export interface RiskAssessment {
  /** 总分 0–100 */
  score: number;
  factors: RiskFactor[];
  /** 由分数映射的基础分级 */
  tierFromScore: Tier;
  /**
   * ★ 评分**输入**快照(第 4 项)。
   *
   * 为什么必须一起返回并落审计:历史记录里原来只有 score/factors —— 那是输出。
   * 换评分器时要回答"同一批请求在新旧模型下档位分布如何",就必须能用**当时的输入**
   * 重算;事后结局标签也要挂到"当时那一笔请求"上。缺了它,所谓"新旧对比"
   * 只能拿旧分数当输入,那是自欺。
   */
  features?: RiskFeatures;
  /** 做出本次裁决的评分器标识(legacy / logistic),影子模式下这里是**裁决者**而非挑战者 */
  scorer?: ScorerStamp;
  /**
   * ★ 影子评分(第 4 项第 3 步):线上仍由当前评分器裁决,
   *   同时用 challenger 评分器并行算一遍,分歧落审计。
   *   它**不参与裁决** —— 这一点是硬约束,否则影子模式一上线就变成了灰度发布。
   */
  shadow?: ShadowScore;
  /** 切换到新评分器后,把 legacy 分一并留下:同一批请求的前后对比靠它 */
  legacyScore?: number;
}

/** 评分器标识(审计用) */
export interface ScorerStamp {
  id: string;
  /** legacy=手调线性 · logistic=训练出的逻辑回归 · shadow 模式下 scorer 始终是**裁决者** */
  mode: "legacy" | "logistic";
  /** 一句话说明这次是哪个评分器在裁决(落审计,便于事后追责) */
  note?: string;
}

/** 影子评分结果:只用于对比与审计,绝不参与裁决 */
export interface ShadowScore {
  scorerId: string;
  score: number;
  tier: Tier;
  legacyScore: number;
  /** 与裁决者档位是否分歧 —— 分歧率就是"换模型前"最该看的那个数 */
  divergent: boolean;
  note?: string;
}

/**
 * 风险分 → 分级映射阈值
 *
 * 校准依据(重要,答辩会被追问):
 *   模型必须能区分"熟客小额"与"生客大额",否则安全机制会退化成
 *   "每次都强验证",用户会在第三笔就卸载 App。
 *   安全与体验的平衡点在这里,不在提示词里。
 */
export const RISK_THRESHOLDS = {
  /** < 28:低风险,可直接展示确认(仍不接受自动执行) */
  auto: 28,
  /** < 62:中风险,用户确认 */
  confirm: 62,
  /** >= 62:高风险,强验证 */
} as const;

/** 权重表 —— 集中定义,便于答辩时逐项解释 */
export const RISK_WEIGHTS = {
  /** 金额绝对敞口(按客户画像 P95 归一化) */
  amountExposure: 24,
  /** 收款人新颖度 —— 权重最高,因为它是真实欺诈的最强单点预测因子 */
  payeeNovelty: 26,
  /** 画像偏离度(时段等行为异常) */
  profileDeviation: 6,
  /** 渠道风险 */
  channelRisk: 16,
  /** 设备可信度 */
  deviceTrust: 10,
  /** 时段异常 */
  timeAnomaly: 6,
  /** 名单命中 —— 单因子直接顶格,不做线性叠加 */
  watchlist: 100,
  /** 拆分交易特征 */
  structuring: 30,
  /** ★ 信任降级:已建立信任的收款人可显著降低风险分 */
  trustedPayeeCredit: 30,
  /**
   * ★ 会话可疑度(连续注入命中)。
   *
   * 为什么它只能占**中等权重**,而不是"命中即顶格":
   *   注入命中说明"这个会话的输入里有诱导我违反规则的语句",
   *   但**不说明这一笔操作本身危险** —— 客户可能正在转述一条诈骗短信。
   *   顶格会让"转述骗局"的客户直接被强验证甚至阻断,而真正该被拦的是
   *   攻击者后续的那笔资金操作;中等权重足以把一笔本来"低风险"的操作
   *   推到需要确认/强验证的档位,同时保留可解释性。
   *   真正"必须拦下"的那一档由硬规则 R-INJECTION-COOLDOWN 负责 ——
   *   评分负责"更谨慎",硬规则负责"停下"。两者的分工就在这里。
   */
  sessionSuspicion: 18,
} as const;

/** 渠道风险 → 分值 */
const CHANNEL_RISK_SCORE: Record<ChannelCapabilities["risk"], number> = {
  low: 0,
  medium: 0.5,
  high: 1,
};

/**
 * 计算风险分。**纯函数,可单测**。
 *
 * 这是本系统区别于"给 LLM 一堆工具然后祈祷"的关键:
 * 任何一个场景都能回答"为什么这笔转账被判成红色"。
 */
export function assessRisk(request: PolicyRequest): RiskAssessment {
  const { input, ctx } = request;
  const factors: RiskFactor[] = [];

  const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;
  const profile = ctx.profile.riskProfile;
  const hour = new Date(ctx.now).getHours();

  // ---- 因子 1:金额敞口(相对客户画像归一化) ----
  // 归一化基准取 max(P95, 1) 避免除零;比值 > 1 表示超出客户历史 95 分位
  const baseline = Math.max(profile.transferAmountP95, 1);
  const amountRatio = amount / baseline;
  const amountContribution = clamp01(amountRatio / 2) * RISK_WEIGHTS.amountExposure;
  factors.push({
    name: "amount_exposure",
    contribution: amountContribution,
    detail: `金额 ${amount} / 客户 P95 ${profile.transferAmountP95} = ${amountRatio.toFixed(2)} 倍`,
  });

  // ---- 因子 2:收款人新颖度(权重最高) ----
  const novelty = readPayeeNovelty(input);
  let noveltyContribution = 0;
  if (novelty.isSelfOwned) {
    noveltyContribution = 0;
    factors.push({ name: "payee_novelty", contribution: 0, detail: "本人名下账户互转,风险最低" });
  } else if (novelty.isFirstTime) {
    noveltyContribution = RISK_WEIGHTS.payeeNovelty;
    factors.push({ name: "payee_novelty", contribution: noveltyContribution, detail: "首次向该收款人转账" });
  } else if (novelty.successCount < 3) {
    noveltyContribution = RISK_WEIGHTS.payeeNovelty * 0.5;
    factors.push({
      name: "payee_novelty",
      contribution: noveltyContribution,
      detail: `历史成功转账仅 ${novelty.successCount} 笔,信任度不足`,
    });
  } else {
    noveltyContribution = RISK_WEIGHTS.payeeNovelty * 0.1;
    factors.push({
      name: "payee_novelty",
      contribution: noveltyContribution,
      detail: `历史成功转账 ${novelty.successCount} 笔,已建立信任`,
    });
  }

  // ---- 因子 3:画像偏离度(行为异常:非常用时段) ----
  const activeHours = profile.activeHours.length > 0 ? profile.activeHours : [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
  const hourAnomaly = activeHours.includes(hour) ? 0 : 1;
  const deviationContribution = hourAnomaly * RISK_WEIGHTS.profileDeviation;
  factors.push({
    name: "profile_deviation",
    contribution: deviationContribution,
    detail: hourAnomaly
      ? `当前 ${hour} 时不在客户常用时段 [${activeHours.join(",")}]`
      : `当前 ${hour} 时在客户常用时段内`,
  });

  // ---- 因子 4:渠道风险 ----
  const channelContribution = CHANNEL_RISK_SCORE[ctx.channelCapabilities.risk] * RISK_WEIGHTS.channelRisk;
  factors.push({
    name: "channel_risk",
    contribution: channelContribution,
    detail: `渠道 ${ctx.channel} 风险等级 ${ctx.channelCapabilities.risk}`,
  });

  // ---- 因子 5:设备可信度 ----
  const deviceContribution = ctx.profile.trustedDeviceBound ? 0 : RISK_WEIGHTS.deviceTrust;
  factors.push({
    name: "device_trust",
    contribution: deviceContribution,
    detail: ctx.profile.trustedDeviceBound ? "已绑定可信设备" : "未绑定可信设备",
  });

  // ---- 因子 6:时段异常(独立贡献,便于解释) ----
  const timeContribution = hourAnomaly * RISK_WEIGHTS.timeAnomaly;
  factors.push({
    name: "time_anomaly",
    contribution: timeContribution,
    detail: hourAnomaly ? "非常用时段操作" : "正常时段",
  });

  // ---- 因子 7:名单命中(单因子顶格) ----
  const watchlistHit = readWatchlistHit(input);
  if (watchlistHit) {
    factors.push({
      name: "watchlist",
      contribution: RISK_WEIGHTS.watchlist,
      detail: `命中名单:${watchlistHit.hits.map((h) => h.listType).join(", ")}`,
    });
  }

  // ---- 因子 8:拆分交易特征 ----
  const structuring = readStructuringSignal(input);
  if (structuring.detected) {
    factors.push({
      name: "structuring",
      contribution: RISK_WEIGHTS.structuring,
      detail: structuring.detail,
    });
  }

  /**
   * ---- 因子 9:会话可疑度(连续注入命中) ----
   *
   * ★ 这条因子让"注入检测"第一次真正影响裁决:
   *   此前注入命中只写审计事件(证据),评分对它一无所知 ——
   *   于是"同一个会话连续被注入 3 次"与"第一次被注入"在分数上完全一样。
   *   现在它按命中次数线性加权(封顶在阈值处),把"这个会话正在被反复试探"
   *   这件事变成可解释的分数。
   * ★ 用连续命中次数而不是"是否命中过":偶发一次(客户转述骗局)只带来很低的分,
   *   而连续试探会迅速逼近满权重 —— 与硬规则的阈值语义保持一致。
   */
  const injectionHits = request.frequency?.injectionHits ?? 0;
  /**
   * ★ 已经进入注入冷却的会话,即便"当前这一句"没命中,也按满权重计入。
   *
   *   为什么必须这样(实测踩到):冷却期内客户说任何一句正常话,都会把
   *   **连续命中计数**清零(那是"连续"语义要求的),于是可疑度分数立刻掉回 0 ——
   *   攻击者只要在试探之间插一句"你好"就能把分数抹干净,而冷却本身还在。
   *   所以分数取"连续命中次数"与"是否仍在冷却"两者中的更严者。
   */
  const suspicionHits = request.frequency?.injectionCooldown
    ? Math.max(injectionHits, INJECTION_COOLDOWN_HITS)
    : injectionHits;
  if (suspicionHits > 0) {
    const ratio = clamp01(suspicionHits / INJECTION_COOLDOWN_HITS);
    factors.push({
      name: "session_suspicion",
      contribution: ratio * RISK_WEIGHTS.sessionSuspicion,
      detail: request.frequency?.injectionCooldown
        ? `本会话已因连续命中注入检测进入冷却(阈值 ${INJECTION_COOLDOWN_HITS} 次)`
        : `本会话连续 ${injectionHits} 次命中提示注入检测(阈值 ${INJECTION_COOLDOWN_HITS} 次)`,
    });
  }

  // 总分:普通因子求和,名单/拆分命中则直接顶格
  const hardHit = Boolean(watchlistHit) || structuring.detected;
  const linearSum = factors.reduce((s, f) => s + f.contribution, 0);

  // ---- 信任降级:已建立信任的收款人显著降低风险分 ----
  // 这是"风险评分"区别于"风险计数"的关键:信任应当是可累积的,
  // 否则系统会把长期客户当成陌生人对待,体验与安全双输。
  let credit = 0;
  const trustReasons: string[] = [];
  if (novelty.isSelfOwned) {
    credit += RISK_WEIGHTS.trustedPayeeCredit;
    trustReasons.push("本人名下账户");
  } else if (novelty.isWhitelisted && novelty.successCount >= 3) {
    credit += RISK_WEIGHTS.trustedPayeeCredit;
    trustReasons.push(`白名单收款人,历史成功转账 ${novelty.successCount} 笔`);
  }
  if (novelty.isKnownFrequent) {
    credit += RISK_WEIGHTS.trustedPayeeCredit * 0.3;
    trustReasons.push("在客户常用收款人画像中");
  }
  if (ctx.profile.trustedDeviceBound && ctx.channelCapabilities.risk === "low") {
    credit += 6;
    trustReasons.push("可信设备 + 低风险渠道");
  }
  // 降级不适用于硬命中(名单/拆分),也不允许把分数压到 0 以下
  const score = hardHit
    ? Math.min(100, Math.max(80, linearSum))
    : Math.max(0, Math.min(100, linearSum - credit));

  if (credit > 0) {
    factors.push({
      name: "trust_credit",
      contribution: -credit,
      detail: `信任降级 -${credit.toFixed(1)}(${trustReasons.join(";")})`,
    });
  }

  const legacyScore = score;
  const legacyTier = mapScoreToTier(legacyScore);
  /**
   * ★ 特征快照与 legacy 评分**共用同一批信号读取函数**,因此两者不可能漂移;
   *   一致性另有回归断言锁住(features 重算出的线性分与这里的分必须一致)。
   *   注意:hardHit 沿用上面本地算出的值 —— 它与 extractRiskFeatures 的判据同源,
   *   但这里不依赖后者,以免"抽特征的函数"变成评分的必经路径。
   */
  const features = extractRiskFeatures(request).features;
  const legacyAssessment: RiskAssessment = {
    score: legacyScore,
    factors,
    tierFromScore: legacyTier,
    features,
    scorer: { id: LEGACY_SCORER_ID, mode: "legacy", note: "手调线性权重(README/docs/21 权重表)" },
  };

  const scorerConfig = getPolicyConfig().scorer;
  if (scorerConfig.mode === "legacy") return legacyAssessment;

  /**
   * ★ 从这里往下是第 4 项的"换评分器"分支。
   *
   * 三条不可动摇的约束(换的只是评分器,裁决体系不变):
   *   ① 输出仍是 0–100 分,`mapScoreToTier` 阈值不动,硬规则继续做确定性覆盖;
   *   ② 名单/拆分这类**硬命中**依然不交给模型:scoreWithModel 内部保持
   *      min(100, max(80, legacyScore)) 的顶格;
   *   ③ `factors` 仍然是"每一项扣了多少分"的可解释契约
   *      (贡献度用分数空间表达:base + Σ contributions ≈ score)。
   */
  const model = scorerConfig.model;
  if (!model) {
    // 配置要了新评分器却没给模型:如实回落到 legacy,而不是拿旧分冒充新分
    return {
      ...legacyAssessment,
      scorer: {
        id: LEGACY_SCORER_ID,
        mode: "legacy",
        note: "配置要求使用新评分器但未加载到模型,已回落到 legacy(不冒充已升级)",
      },
    };
  }

  /**
   * ★ 用之前先校验"模型的特征顺序 == 引擎当前契约"(运行时校验,不靠类型)。
   *   模型文件是生成物:哪天引擎新增一个特征而没重新训练,权重就会整体错位 ——
   *   "看起来能跑、分数全错"是最危险的一类缺陷,宁可当场抛错。
   */
  assertModelMatchesFeatureNames(model, RISK_FEATURE_NAMES);

  const challenger = scoreWithModel(model, features, { hardHit, legacyScore });
  const challengerTier = mapScoreToTier(challenger.score);

  if (scorerConfig.mode === "shadow") {
    return {
      ...legacyAssessment,
      shadow: {
        scorerId: model.id,
        score: challenger.score,
        tier: challengerTier,
        legacyScore,
        divergent: challengerTier !== legacyTier,
        note: "影子模式:本笔仍由 legacy 裁决,challenger 仅记录不下场",
      },
    };
  }

  return {
    score: challenger.score,
    factors: challenger.factors,
    tierFromScore: challengerTier,
    features,
    scorer: {
      id: model.id,
      mode: "logistic",
      note: model.note,
    },
    legacyScore,
  };
}

/** 风险分 → 分级 */
export function mapScoreToTier(score: number): Tier {
  if (score >= RISK_THRESHOLDS.confirm) return "strong_auth";
  if (score >= RISK_THRESHOLDS.auto) return "confirm";
  return "auto";
}

/**
 * 面向界面的风险视图(三段刻度盘的数据源)。
 *
 * ★ 为什么在服务端组装,而不是让前端去 policySummary 里翻:
 *   「R-RISK-SCORE 这条代表评分」「28/62 是分档线」都属于**业务规则**。
 *   前端若自己认识 ruleId、自己写死阈值,就等于把风控规则复制了一份到界面层 ——
 *   改一次阈值要改两处,而且界面与裁决迟早各说各话。
 *   所以这里一次性把「分数 + 各因子贡献 + 阈值 + 最终档位」打包成纯展示数据。
 *
 * 数据源就是已落审计的那条 R-RISK-SCORE 理由:界面上看到的分数,
 * 与审计链里这条裁决的分数必然是同一个数(同一份数据的两种渲染)。
 *
 * 没有评分理由时返回 null(例如只读能力根本没走到评分这一步),界面据此不画。
 */
export interface RiskView {
  /** 0–100 总分 */
  score: number;
  /** 最终生效档位(可能被强制升级,故以裁决结果为准而非 tierFromScore) */
  tier: Tier;
  /** 各因子贡献,用于展开解释"这一分是怎么来的" */
  factors: RiskFactor[];
  /** 分档阈值,界面画刻度线用 */
  thresholds: { auto: number; confirm: number };
}

export function buildRiskView(
  reasons: PolicyReason[] | undefined,
  tier: Tier,
): RiskView | null {
  const scored = reasons?.find((r) => r.ruleId === "R-RISK-SCORE");
  const score = scored?.evidence?.["score"];
  if (typeof score !== "number") return null;
  const rawFactors = scored?.evidence?.["factors"];
  return {
    score,
    tier,
    factors: Array.isArray(rawFactors) ? (rawFactors as RiskFactor[]) : [],
    thresholds: { auto: RISK_THRESHOLDS.auto, confirm: RISK_THRESHOLDS.confirm },
  };
}

// ============================================================================
// 第 4 项:评分器升级 —— 特征抽取(标签管道与影子模式的地基)
// ============================================================================

/**
 * 评分模型的**输入**(不是输出)。
 *
 * ★ 为什么必须把特征单独抽出来落审计:
 *   历史评分记录里原来只有 `score` 与 `factors` —— 那是**模型输出**。
 *   换评分器时要回答"同一批请求在新旧模型下档位分布如何",
 *   就必须能用**当时的输入**重算,否则只能拿旧分数当输入,那是自欺。
 *   同理,标签管道要把事后结局(欺诈确认/投诉/退款)回填到"当时那一笔请求"上,
 *   也必须有这份可检索、可重算的输入快照。
 *
 * 取值域全部是 0–1(或 0/1 布尔),这是刻意的:
 *   · 逻辑回归/GBDT 都能直接吃,不需要再缩放;
 *   · 每个特征的**语义**都能用一句话解释(可解释性契约的另一半):
 *     `features.amount_exposure = 0.5` 明确表示"金额是客户 P95 的一半",
 *     而不是某个只对旧模型有意义的中间量。
 */
export interface RiskFeatures {
  /** 金额敞口:clamp01((amount / max(P95,1)) / 2),0–1 */
  amountExposure: number;
  /** 首次向该收款人转账(无对手方的资金操作恒为 0) */
  payeeFirstTime: number;
  /** 历史成功转账 < 3 笔但并非首次(信任不足) */
  payeeThinHistory: number;
  /** 已建立信任的收款人(白名单 + ≥3 笔) */
  payeeTrusted: number;
  /** 本人名下账户互转 */
  payeeSelfOwned: number;
  /** 当前小时不在客户常用时段 */
  hourAnomaly: number;
  /** 渠道风险:0 / 0.5 / 1 */
  channelRisk: number;
  /** 未绑定可信设备 */
  deviceUntrusted: number;
  /** 命中阻断级名单(单因子顶格,不参与线性叠加) */
  watchlistHit: number;
  /** 拆分交易特征 */
  structuring: number;
  /** 会话可疑度:clamp01(连续注入命中 / 冷却阈值),0–1 */
  sessionSuspicion: number;
  /**
   * 信任降级强度:clamp01(credit / (2 × trustedPayeeCredit)),0–1。
   *
   * ★ 注意 credit 里含一项**权重表之外的硬编码 +6**(可信设备 + 低风险渠道),
   *   所以这个比例不能反推出 credit —— 它是特征,不是还原量。
   *   重算分数时用 `feature × 2 × trustedPayeeCredit × (credit/creditActual)`
   *   是不可能的,因此重算路径必须**重新算 credit**,而不是从特征反推。
   *   (这也是"特征只用于模型、legacy 用原函数"这条分工的原因。)
   */
  trustCredit: number;
}

/** 特征名清单(训练器按这个顺序构造向量,顺序即契约) */
export const RISK_FEATURE_NAMES = [
  "amountExposure",
  "payeeFirstTime",
  "payeeThinHistory",
  "payeeTrusted",
  "payeeSelfOwned",
  "hourAnomaly",
  "channelRisk",
  "deviceUntrusted",
  "watchlistHit",
  "structuring",
  "sessionSuspicion",
  "trustCredit",
] as const;

/** 特征向量(与 RISK_FEATURE_NAMES 同序) */
export type RiskFeatureVector = number[];

/**
 * 抽取评分特征。**与 legacy 线性评分共用同一批原始信号读取函数**
 * (readPayeeNovelty / readWatchlistHit / readStructuringSignal),
 * 因此不存在"两套信号口径"的漂移。
 *
 * ★ 它**不改变** assessRisk 的任何行为:legacy 路径仍然由 assessRisk 自己算,
 *   本函数只是把同样的输入再表达一遍,供新评分器与审计使用。
 *   两者的一致性由回归断言锁住(见 tests「评分器升级」组:
 *   features 重算出的 legacy 分与 assessRisk 的分必须一致)。
 */
export function extractRiskFeatures(request: PolicyRequest): {
  features: RiskFeatures;
  /** 与 features 同序的向量 */
  vector: RiskFeatureVector;
  /** 硬命中(名单/拆分):这部分不交给模型,保持确定性顶格 */
  hardHit: boolean;
} {
  const { input, ctx } = request;
  const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;
  const profile = ctx.profile.riskProfile;
  const hour = new Date(ctx.now).getHours();

  const baseline = Math.max(profile.transferAmountP95, 1);
  const amountExposure = clamp01(amount / baseline / 2);

  const novelty = readPayeeNovelty(input);
  const payeeFirstTime = !novelty.isSelfOwned && novelty.isFirstTime ? 1 : 0;
  const payeeThinHistory = !novelty.isSelfOwned && !novelty.isFirstTime && novelty.successCount < 3 ? 1 : 0;
  const payeeTrusted = !novelty.isSelfOwned && !novelty.isFirstTime && novelty.successCount >= 3 ? 1 : 0;
  const payeeSelfOwned = novelty.isSelfOwned ? 1 : 0;

  const activeHours =
    profile.activeHours.length > 0
      ? profile.activeHours
      : [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23];
  const hourAnomaly = activeHours.includes(hour) ? 0 : 1;

  const channelRisk = CHANNEL_RISK_SCORE[ctx.channelCapabilities.risk];
  const deviceUntrusted = ctx.profile.trustedDeviceBound ? 0 : 1;

  const watchlistHit = readWatchlistHit(input) ? 1 : 0;
  const structuring = readStructuringSignal(input).detected ? 1 : 0;

  const injectionHits = request.frequency?.injectionHits ?? 0;
  const suspicionHits = request.frequency?.injectionCooldown
    ? Math.max(injectionHits, INJECTION_COOLDOWN_HITS)
    : injectionHits;
  const sessionSuspicion = suspicionHits > 0 ? clamp01(suspicionHits / INJECTION_COOLDOWN_HITS) : 0;

  // 信任降级强度(与 assessRisk 的第 321–339 行同一套判据)
  let credit = 0;
  if (novelty.isSelfOwned) credit += RISK_WEIGHTS.trustedPayeeCredit;
  else if (novelty.isWhitelisted && novelty.successCount >= 3) credit += RISK_WEIGHTS.trustedPayeeCredit;
  if (novelty.isKnownFrequent) credit += RISK_WEIGHTS.trustedPayeeCredit * 0.3;
  if (ctx.profile.trustedDeviceBound && ctx.channelCapabilities.risk === "low") credit += 6;
  const trustCredit = clamp01(credit / (2 * RISK_WEIGHTS.trustedPayeeCredit));

  const features: RiskFeatures = {
    amountExposure,
    payeeFirstTime,
    payeeThinHistory,
    payeeTrusted,
    payeeSelfOwned,
    hourAnomaly,
    channelRisk,
    deviceUntrusted,
    watchlistHit,
    structuring,
    sessionSuspicion,
    trustCredit,
  };
  return {
    features,
    vector: RISK_FEATURE_NAMES.map((n) => features[n]),
    hardHit: watchlistHit === 1 || structuring === 1,
  };
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

// ============================================================================
// 从入参中提取风险信号
// ============================================================================

interface PayeeNoveltySignal {
  isFirstTime: boolean;
  successCount: number;
  isSelfOwned: boolean;
  isWhitelisted: boolean;
  isKnownFrequent: boolean;
}

/**
 * 读取收款人风险信号。
 *
 * ★ 缺失时的默认值取向(这是一个安全设计决策,不是随手写的兜底):
 *
 *   - `isFirstTime` 缺失时默认为 **false(未知,不当作首次)**。
 *     理由:这个字段同时驱动两件事 ——
 *       ① 升级规则 R-FIRST-PAYEE-ESCALATE(需要"确认是首次"才升级)
 *       ② 确认卡上的"首次转账"警告文案
 *     若缺失时默认 true,会对**所有没有风险信号的能力调用**都加上"这是你首次
 *     向该收款人转账"的警告。而假警告是安全设计里最有害的东西:
 *     用户被无关紧要的警告刷过几次之后,就再也不会认真看真正的警告了。
 *     缺失意味着"未知",未知不应该伪装成危险。
 *
 *   - `successCount` 缺失时默认 0(保守:不凭空给予信任)。
 *     这个方向的偏差是安全的 —— 少给信任只会让系统更严格。
 */
function readPayeeNovelty(input: Record<string, unknown>): PayeeNoveltySignal {
  const raw = input["__payeeRisk"] as Partial<PayeeNoveltySignal> | undefined;
  return {
    isFirstTime: raw?.isFirstTime ?? false,
    successCount: raw?.successCount ?? 0,
    isSelfOwned: raw?.isSelfOwned ?? false,
    isWhitelisted: raw?.isWhitelisted ?? false,
    isKnownFrequent: raw?.isKnownFrequent ?? false,
  };
}

/**
 * 这次调用是否属于"有对手方的转账"。
 *
 * ★ 为什么需要这个判断(场景三暴露出来的一个真实缺陷):
 *   理财申购也是 moneyMovement,于是它同样命中了为**转账**写的两条规则:
 *     · R-FIRST-PAYEE-ESCALATE → "首次向该收款人转账,无条件升级为强验证"
 *     · R-STATIC-THRESHOLD      → "金额 10000 超过兜底阈值 1000(新收款人档位)"
 *   用户买一笔 1 万元的理财,看到的理由是"新收款人档位"和
 *   "你之前有没有和「」有过资金往来?这次是第一次,对吗?" —— 收款人是空的。
 *   这不是"更严格",而是**理由错位**:用户被要求为一笔理财做转账语义的验证,
 *   而验证之后他仍然不知道自己被验证的是什么。
 *
 *   判据用 `__payeeRisk` 是否存在,而不是按能力名硬编码:
 *   注入器只在真正解析出收款人时写入这个信号,所以它精确对应
 *   "本次操作有对手方"。将来新增任何无对手方的资金操作(如理财),
 *   都会自动避开这两条转账规则 —— 不需要再改一次规则表。
 */
function isCounterpartyTransfer(input: Record<string, unknown>): boolean {
  return input["__payeeRisk"] != null;
}

function readWatchlistHit(
  input: Record<string, unknown>,
): { hits: Array<{ listType: string; severity: string }> } | null {
  const raw = input["__screening"] as { hit?: boolean; hits?: Array<{ listType: string; severity: string }> } | undefined;
  if (!raw?.hit || !raw.hits?.length) return null;
  // 仅 block 级命中触发顶格;warn 级交由评分处理
  const blocking = raw.hits.filter((h) => h.severity === "block");
  return blocking.length > 0 ? { hits: blocking } : null;
}

function readStructuringSignal(
  input: Record<string, unknown>,
): { detected: boolean; detail: string } {
  const raw = input["__velocity"] as
    | { samePayeeCount24h?: number; sameAmountRepeatCount?: number; dailyCumulative?: number; dailyLimit?: number }
    | undefined;
  if (!raw) return { detected: false, detail: "" };

  // 24 小时内对同一收款人 4 笔及以上
  if ((raw.samePayeeCount24h ?? 0) >= 4) {
    return {
      detected: true,
      detail: `24 小时内已向该收款人转账 ${raw.samePayeeCount24h} 笔,存在拆分交易特征`,
    };
  }
  // 相同金额重复 3 次及以上
  if ((raw.sameAmountRepeatCount ?? 0) >= 3) {
    return {
      detected: true,
      detail: `相同金额重复 ${raw.sameAmountRepeatCount} 次,存在拆分交易特征`,
    };
  }
  // 日累计接近上限(90% 以上)
  if (raw.dailyCumulative != null && raw.dailyLimit != null && raw.dailyLimit > 0) {
    if (raw.dailyCumulative / raw.dailyLimit >= 0.9) {
      return {
        detected: true,
        detail: `日累计 ${raw.dailyCumulative} 已达限额的 ${Math.round((raw.dailyCumulative / raw.dailyLimit) * 100)}%`,
      };
    }
  }
  return { detected: false, detail: "" };
}

// ============================================================================
// 频次类硬规则(滑动窗口计数)
//
// ★ 为什么限流必须长在**策略引擎**里,而不是 HTTP 层的一行 `if (count > N) return 429`:
//   1. 审计链里只认"裁决"。HTTP 层返回 429 不产生 PolicyReason,于是事后复盘
//      只能看到"这个请求被拒了",答不出**哪条规则、哪个窗口、计数多少** ——
//      而"每个拒绝都必须可解释"是这套系统的底线(与名单命中、拆分检测同一条要求)。
//   2. 频次与其它硬规则是**同一类东西**:它们都是"无论评分多少都生效"的绝对约束。
//      同一类约束分居两处,就会出现"限流拦下的操作绕过了组合阻断"这类缝隙。
//   3. 计数要按**身份**归属。身份在网关由令牌确定(见 server/index.ts),
//      但"这个客户最近转了几笔"这件事只有引擎知道 —— 计数在引擎里,
//      网关只负责把客户号交给它。
//
// ★ 计数的状态放在**调用方持有的 FrequencyLedger 实例**里(见 agent/orchestrator.ts),
//   而不是模块级全局变量:
//   同一进程里可以同时存在多个 app 实例(测试夹具就是这么干的),
//   全局计数会让"上一个测试的转账"算进"这一个测试的额度",测试之间互相污染。
// ============================================================================

/** 能力按**资金语义**归类 —— 限流档位的粒度 */
export type FrequencyCategory = "read_only" | "fund_transfer" | "fund_other" | "credential" | "write_other";

/**
 * 一条频次规则:某类别在某个滑动窗口内的调用上限。
 *
 * ★ 为什么 windowMs 与 max 成对出现,而不是"每类一个上限":
 *   只读查询"1 分钟 60 次"与转账"5 分钟 3 次"是**不同的时间尺度**,
 *   用一个数字表达不了。写成 (窗口, 上限) 才能逐条解释
 *   "你在 5 分钟内发起了 4 笔转账,上限 3 笔"。
 */
export interface FrequencyRule {
  /** 稳定规则 ID(进审计与界面裁决依据,便于回归测试断言) */
  id: string;
  category: FrequencyCategory;
  /** 面向客户的类别名(人话) */
  label: string;
  windowMs: number;
  /** 窗口的人话说法(「5 分钟」「1 小时」)—— 理由文案直接用 */
  windowLabel: string;
  /** 窗口内允许的**最大次数**(第 max+1 次触发) */
  max: number;
  /**
   * 处置方式:
   *   · block    —— 直接拦下本次(资金类:不可商量);
   *   · cooldown —— 拦下本次并进入冷静期(只读/低危写入:拦一次就够,不必长期封)
   * 两者最终都体现为 `force_tier → blocked`,区别在理由文案与 evidence.cooldownUntil ——
   * ★ 不新造一套"限流状态",复用既有的分级反馈。
   */
  action: "block" | "cooldown";
  /** 冷静期时长(仅 action = cooldown 时有意义,默认取窗口长度) */
  cooldownMs?: number;
}

/**
 * 默认频次规则表。
 *
 * ★ 档位取向:只读宽松、资金严格 —— 与"安全与体验的平衡点不在提示词里"同源。
 *   读 60 次/分钟不会出事,而转账 5 分钟内 3 笔已经足够像自动化脚本。
 * ★ 数字是**起点**,不是"最优值":真实银行会按客户画像分档(新客更严、VIP 不同),
 *   这里给的是统一下限,且可被 `configurePolicy({ frequency })` 覆盖(见 PolicyConfig)。
 */
export const DEFAULT_FREQUENCY_RULES: FrequencyRule[] = [
  {
    id: "F-READ-60M",
    category: "read_only",
    label: "查询",
    windowMs: 60 * 1000,
    windowLabel: "1 分钟",
    max: 60,
    action: "cooldown",
    cooldownMs: 30 * 1000,
  },
  {
    id: "F-TRANSFER-3P5M",
    category: "fund_transfer",
    label: "转账",
    windowMs: 5 * 60 * 1000,
    windowLabel: "5 分钟",
    max: 3,
    action: "block",
  },
  {
    id: "F-FUND-OTHER-5P5M",
    category: "fund_other",
    label: "资金操作",
    windowMs: 5 * 60 * 1000,
    windowLabel: "5 分钟",
    max: 5,
    action: "block",
  },
  {
    id: "F-CREDENTIAL-3P30M",
    category: "credential",
    label: "凭证变更",
    windowMs: 30 * 60 * 1000,
    windowLabel: "30 分钟",
    max: 3,
    action: "block",
  },
  {
    id: "F-WRITE-10P5M",
    category: "write_other",
    label: "其它变更",
    windowMs: 5 * 60 * 1000,
    windowLabel: "5 分钟",
    max: 10,
    action: "cooldown",
    cooldownMs: 60 * 1000,
  },
];

/**
 * 演示/脚本用的**叙事档**:只放宽次数上限,别的什么都不改。
 *
 * ★ 为什么需要它,以及为什么它不能是"默认值":
 *   演示脚本与验证脚本会在几十秒内连做十几笔资金操作 —— 那是**脚本的节奏**,
 *   不是客户的节奏。拿出厂档跑,第 4 个转账场景就会被 `F-TRANSFER-3P5M` 拦下,
 *   于是演示看起来"坏了",而规则其实完全正确。
 *   两条路:① 认为脚本节奏正常,**放宽出厂规则** —— 拿安全换演示,不接受;
 *          ② 保留出厂规则,另外给脚本一份**显式声明、启动时打印**的叙事档 —— 选这条。
 *
 * ★ 放宽的只有 `max`:类别不动、窗口不动、动作不动、规则 ID 不动 ——
 *   因此审计里的 `frequencyRuleId` 仍然指向同一条规则,回归断言也不会失效。
 *   出厂严格档由演示的最后一个场景(《频次硬规则》)专门演示。
 */
export const NARRATIVE_FREQUENCY_RULES: FrequencyRule[] = DEFAULT_FREQUENCY_RULES.map((rule) => {
  if (rule.category === "fund_transfer") return { ...rule, max: 30 };
  if (rule.category === "fund_other") return { ...rule, max: 40 };
  if (rule.category === "read_only") return { ...rule, max: 120 };
  return rule;
});

/**
 * 能力 → 频次类别。
 *
 * ★ 判据的顺序就是它的语义:**先说清"动没动钱",再说"是什么钱"**。
 *   转账单独一档(最严)是因为它的两端都是"钱出银行体系"之外的对手方;
 *   理财申购、还款、预留资金同为资金操作,但通常有产品/合约兜底,档位可略松。
 * ★ 用能力自身的声明(moneyMovement / readOnly)而不是硬编码能力名清单:
 *   将来新增任何资金能力都会自动落到资金档 —— 不需要再改一次限流表。
 */
export function frequencyCategoryOfCapability(capability: {
  name: string;
  moneyMovement: boolean;
  readOnly: boolean;
}): FrequencyCategory {
  if (capability.moneyMovement) {
    // 「转账」的判据是能力族名上的语义:transfer.* 与跨行/AA 收款等对手方付钱
    if (/^transfer\.|^aa\.|^remittance\./.test(capability.name)) return "fund_transfer";
    return "fund_other";
  }
  if (
    /^security\.|password|phone|email/.test(capability.name) &&
    (capability.name.includes("change") || capability.name.includes("reset"))
  ) {
    return "credential";
  }
  if (capability.readOnly) return "read_only";
  return "write_other";
}

/** 一次频次判定的完整结果(进 PolicyRequest,由硬规则与评分共同读取) */
export interface FrequencySnapshot {
  category: FrequencyCategory;
  /** 命中的规则 ID(未超限时也给 —— 理由里要说清"按哪条规则算的") */
  ruleId: string;
  label: string;
  windowMs: number;
  windowLabel: string;
  /** 本窗口内已计入的次数(**含本次**) */
  count: number;
  max: number;
  overLimit: boolean;
  action: "block" | "cooldown";
  /** 冷静期截止时刻(仅 action = cooldown 且已触发时有值) */
  cooldownUntil: number | null;
  /** 注入检测的连续命中次数(见 FrequencyLedger.noteInjection) */
  injectionHits: number;
  /** 是否已因连续注入命中进入冷却 */
  injectionCooldown: boolean;
}

/** 连续命中多少次注入检测 → 进入冷却(★ 注入检测从"证据"升级为"主动防御"的阈值) */
export const INJECTION_COOLDOWN_HITS = 3;
/** 注入冷却时长 */
export const INJECTION_COOLDOWN_MS = 5 * 60 * 1000;

interface InjectionState {
  /** **连续**命中次数(一次未命中即清零) */
  hits: number;
  lastAt: number;
  cooldownUntil: number;
}

/**
 * 滑动窗口频次台账。
 *
 * ★ 两个必须做对、否则会变成永久封禁的细节:
 *   ① 窗口是**滑动**的:只保留"最宽窗口"以内的记录,更早的尝试被丢弃 ——
 *      否则客户上午转了 3 笔,下午一笔都办不了(这是"固定窗口"最常见的坑);
 *   ② 内存有界:每客户每类别最多保留 N 条时间戳,客户数也有上限 ——
 *      限流器本身不能成为内存放大的入口(否则一次压测就能把进程撑爆)。
 */
export class FrequencyLedger {
  /** 规则来源:每次判定时**现取** —— 于是 configurePolicy({frequency}) 立即生效,不必重建台账 */
  private readonly ruleSource: () => FrequencyRule[];
  /** key = customerId + 类别;value = 该类别最近的尝试时刻(升序) */
  private readonly attempts = new Map<string, number[]>();
  /** key = customerId + 类别;value = 冷静期截止时刻 */
  private readonly cooldowns = new Map<string, number>();
  private readonly injections = new Map<string, InjectionState>();
  /** 每客户每类别保留的最大时间戳条数(▶ 上限的 4 倍,足够判定最大窗口) */
  private readonly maxEntriesPerKey = 64;
  /** 最多跟踪多少个客户(超出后按最早记录淘汰) */
  private readonly maxCustomers = 500;
  private readonly trackedAt = new Map<string, number>();

  constructor(rules?: FrequencyRule[] | (() => FrequencyRule[])) {
    this.ruleSource =
      typeof rules === "function" ? rules : () => rules ?? getPolicyConfig().frequency ?? DEFAULT_FREQUENCY_RULES;
  }

  private rules(): FrequencyRule[] {
    return this.ruleSource();
  }

  /** 当前规则表(演示/测试可读) */
  getRules(): FrequencyRule[] {
    return [...this.rules()];
  }

  private ruleFor(category: FrequencyCategory): FrequencyRule {
    const found = this.rules().find((r) => r.category === category);
    return (
      found ?? {
        id: `F-${category}-DEFAULT`,
        category,
        label: category,
        windowMs: 5 * 60 * 1000,
        windowLabel: "5 分钟",
        max: Number.MAX_SAFE_INTEGER,
        action: "block",
      }
    );
  }

  /** 最宽的窗口 —— 比它更早的记录可以安全丢弃 */
  private widestWindowMs(): number {
    return this.rules().reduce((max, r) => Math.max(max, r.windowMs), 60 * 1000);
  }

  /**
   * 记一次**请求阶段**的能力调用,并给出判定。
   *
   * ★ 记录与判定**不可分离**(同一个入口):分开写迟早会出现"判了没记"
   *   (额度永远用不完)或"记了没判"(计数只涨不拦)。
   */
  observe(input: { customerId: string; capability: { name: string; moneyMovement: boolean; readOnly: boolean }; now: number }): FrequencySnapshot {
    return this.judge(input, true);
  }

  /**
   * 只判定、**不计数** —— 给"不是客户新发起的一次请求"的那些裁决点用。
   *
   * ★ 为什么必须有这一档(实测踩到的具体问题):
   *   一笔转账会经过好几个裁决点:发起请求 → 澄清后继续 → 改金额 → 确认执行。
   *   如果只让"发起请求"那一个点带快照,其它点就**完全看不到频次状态** ——
   *   于是"同一个会话连续被注入、已经进入冷却"这件事,
   *   在被澄清恢复出的那一笔上就完全不起作用(实测:注入冷却拦不住澄清恢复的转账)。
   *   反过来,如果每个点都 `observe`,额度会被一笔业务重复消耗多次。
   *
   *   所以拆成两档:**请求阶段计数并判定**,后续阶段只看判定结果(冷却/注入命中照旧生效)。
   */
  peek(input: { customerId: string; capability: { name: string; moneyMovement: boolean; readOnly: boolean }; now: number }): FrequencySnapshot {
    return this.judge(input, false);
  }

  private judge(
    input: { customerId: string; capability: { name: string; moneyMovement: boolean; readOnly: boolean }; now: number },
    record: boolean,
  ): FrequencySnapshot {
    const category = frequencyCategoryOfCapability(input.capability);
    const rule = this.ruleFor(category);
    const key = `${input.customerId}\u0000${category}`;

    // ---- ① 计数(仅在请求阶段;先记后判:本次调用确实发生了) ----
    let kept = (this.attempts.get(key) ?? []).filter((t) => input.now - t < this.widestWindowMs());
    if (record) {
      kept = [...kept, input.now].slice(-this.maxEntriesPerKey);
      this.attempts.set(key, kept);
      this.trackedAt.set(input.customerId, input.now);
      this.trim();
    }

    // ---- ② 滑动窗口内计数 ----
    const windowStart = input.now - rule.windowMs;
    const count = kept.filter((t) => t > windowStart).length;

    // ---- ③ 冷静期(未超限也可能"上一轮已经触发过冷却") ----
    const existingCooldown = this.cooldowns.get(key) ?? 0;
    let cooldownUntil = existingCooldown > input.now ? existingCooldown : null;

    let overLimit = count > rule.max;
    if (overLimit && rule.action === "cooldown" && cooldownUntil == null) {
      cooldownUntil = input.now + (rule.cooldownMs ?? rule.windowMs);
      this.cooldowns.set(key, cooldownUntil);
    }
    if (cooldownUntil != null) {
      // 冷静期内:即便窗口滑过去、计数掉下来,本次仍然按超限处置
      overLimit = true;
    }

    const injection = this.injectionState(input.customerId, input.now);
    return {
      category,
      ruleId: rule.id,
      label: rule.label,
      windowMs: rule.windowMs,
      windowLabel: rule.windowLabel,
      count,
      max: rule.max,
      overLimit,
      action: rule.action,
      cooldownUntil,
      injectionHits: injection.hits,
      injectionCooldown: injection.inCooldown,
    };
  }

  /**
   * 记一次注入检测结果。返回记录后的状态(供审计与测试断言)。
   *
   * ★ 这是"注入检测从证据升级为主动防御"的那一步:
   *   过去 detectInjection 命中只写一条审计事件(事后可查),对**正在发生的**
   *   攻击没有任何作用 —— 攻击者可以一轮一轮地试,系统每轮都"如实记录"。
   *   现在连续命中达到阈值就进入冷却,后续操作按 `R-INJECTION-COOLDOWN` 拦下。
   * ★ 用**连续**而不是累计:客户正常对话里偶尔出现一次"忽略以上指令"式的表述
   *   (比如他自己在描述一个骗局)不该被累计成"这个人可疑"。
   */
  noteInjection(input: { customerId: string; hit: boolean; at: number }): InjectionState {
    const state = this.injections.get(input.customerId);
    if (!input.hit) {
      // 未命中即清零 —— 连续计数才有意义(见上)
      const next: InjectionState = { hits: 0, lastAt: input.at, cooldownUntil: state?.cooldownUntil ?? 0 };
      this.injections.set(input.customerId, next);
      return next;
    }
    const next: InjectionState = {
      hits: (state?.hits ?? 0) + 1,
      lastAt: input.at,
      cooldownUntil: state?.cooldownUntil ?? 0,
    };
    if (next.hits >= INJECTION_COOLDOWN_HITS) next.cooldownUntil = input.at + INJECTION_COOLDOWN_MS;
    this.injections.set(input.customerId, next);
    return next;
  }

  private injectionState(customerId: string, now: number): { hits: number; inCooldown: boolean } {
    const state = this.injections.get(customerId);
    if (!state) return { hits: 0, inCooldown: false };
    // 冷却已过期 → 计数归零,给客户一条回到正常的路(不是永久封禁)
    if (state.cooldownUntil > 0 && state.cooldownUntil <= now) {
      this.injections.set(customerId, { hits: 0, lastAt: now, cooldownUntil: 0 });
      return { hits: 0, inCooldown: false };
    }
    return { hits: state.hits, inCooldown: state.cooldownUntil > now };
  }

  /**
   * 清空某个客户的频次与注入状态。
   *
   * ★ 存在的理由很具体:演示脚本与测试会**连续**做十几笔资金操作(几秒之内),
   *   那是脚本的节奏,不是客户的节奏。每个场景开始前清一次,场景之间互不影响;
   *   否则第 4 个场景会被第 3 个场景"用掉的额度"拦下,而它自己一笔都没办。
   */
  clear(customerId: string): void {
    for (const key of [...this.attempts.keys()]) {
      if (key.startsWith(`${customerId}\u0000`)) this.attempts.delete(key);
    }
    for (const key of [...this.cooldowns.keys()]) {
      if (key.startsWith(`${customerId}\u0000`)) this.cooldowns.delete(key);
    }
    this.injections.delete(customerId);
    this.trackedAt.delete(customerId);
  }

  /** 只清注入状态(演示里"恢复清白"用) */
  clearInjection(customerId: string): void {
    this.injections.delete(customerId);
  }

  /** 内存有界(见类注释的②) */
  private trim(): void {
    if (this.trackedAt.size > this.maxCustomers) {
      const sorted = [...this.trackedAt.entries()].sort((a, b) => a[1] - b[1]);
      for (const [customerId] of sorted.slice(0, sorted.length - this.maxCustomers)) {
        this.clear(customerId);
      }
    }
  }
}

// ============================================================================
// 硬规则(与评分并行执行的绝对约束)
// ============================================================================

export interface PolicyRule {
  id: string;
  description: string;
  /** 返回 null 表示未命中 */
  apply: (request: PolicyRequest) => PolicyRuleOutcome | null;
}

export type PolicyRuleOutcome =
  | { kind: "deny"; reason: PolicyReason; userMessage: string; guidance?: Guidance }
  | { kind: "handoff"; reason: PolicyReason; contextSummary: string; urgency: "normal" | "high" }
  | { kind: "force_tier"; tier: Tier; reason: PolicyReason; userMessage?: string }
  | { kind: "note"; reason: PolicyReason };

/**
 * 硬规则集。这些规则**不参与评分**,而是绝对约束 —— 命中即生效。
 *
 * 顺序有意义:deny 类规则优先于分级类规则。
 */
export const DEFAULT_RULES: PolicyRule[] = [
  // --- 组合阻断:同一会话内"改凭证 + 资金操作" ---
  {
    id: "R-CREDENTIAL-MONEY-COMBO",
    description: "同一会话内禁止组合执行凭证变更与资金操作,这是账户接管的典型路径",
    apply: ({ capability, sessionIntents }) => {
      if (!capability.moneyMovement) return null;
      const credentialActions = [
        "security.change_phone",
        "security.change_password",
        "security.change_email",
        "security.reset_transaction_password",
      ];
      const hit = (sessionIntents ?? []).filter((i) => credentialActions.includes(i));
      if (hit.length === 0) return null;
      return {
        kind: "deny",
        reason: {
          ruleId: "R-CREDENTIAL-MONEY-COMBO",
          message: `本会话已意图执行凭证变更操作 [${hit.join(", ")}],同一会话内不得再执行资金操作`,
          effect: "deny",
          evidence: { sessionIntents: hit },
        },
        userMessage:
          "为了您的账户安全,修改安全信息与转账不能在同一会话中连续进行。请先完成安全信息修改,稍后重新发起转账,或换个渠道操作。",
      };
    },
  },

  // --- 名单命中:硬阻断 ---
  {
    id: "R-WATCHLIST-BLOCK",
    description: "收款方命中涉诈/司法/制裁名单时硬阻断",
    apply: ({ input }) => {
      const raw = input["__screening"] as
        | { hit?: boolean; hits?: Array<{ listType: string; severity: string; detail: string }> }
        | undefined;
      if (!raw?.hit || !raw.hits?.length) return null;
      const blocking = raw.hits.filter((h) => h.severity === "block");
      if (blocking.length === 0) return null;
      return {
        kind: "deny",
        reason: {
          ruleId: "R-WATCHLIST-BLOCK",
          message: `收款方命中阻断级名单:${blocking.map((h) => `${h.listType}(${h.detail})`).join("; ")}`,
          effect: "deny",
          evidence: { hits: blocking },
        },
        userMessage:
          "该收款账户存在风险,我们无法为您完成这笔转账。为保护您的资金安全,建议您先通过官方客服核实对方身份。",
      };
    },
  },

  // --- 高风险渠道不得直接执行强验证级资金操作 ---
  {
    id: "R-IM-NO-STRONG-TX",
    description: "IM 渠道会话可截图、可转发、易被接管,不得在其内完成强验证级资金操作",
    apply: ({ capability, ctx, hasValidActionToken }) => {
      if (!capability.moneyMovement) return null;
      if (ctx.channelCapabilities.risk !== "high") return null;
      // 已通过原生安全流程回执的强验证可放行(如跳转 APP 完成人脸后回跳)
      if (hasValidActionToken) return null;
      if (!ctx.channelCapabilities.deepLink) {
        return {
          kind: "handoff",
          reason: {
            ruleId: "R-IM-NO-STRONG-TX",
            message: "高风险渠道且不支持安全深链,无法完成强验证,转人工处理",
            effect: "deny",
            evidence: { channel: ctx.channel },
          },
          contextSummary: `客户在 ${ctx.channel} 渠道发起资金操作,该渠道风险等级为 high 且不支持深链跳转,无法完成强验证。`,
          urgency: "high",
        };
      }
      return null;
    },
  },

  // --- 账户风控限制状态 ---
  {
    id: "R-ACCOUNT-RESTRICTED",
    description: "账户处于风控限制状态时不得执行资金操作",
    apply: ({ capability, ctx }) => {
      if (!capability.moneyMovement) return null;
      if (!ctx.profile.security.restricted) return null;
      return {
        kind: "deny",
        reason: {
          ruleId: "R-ACCOUNT-RESTRICTED",
          message: `账户处于限制状态:${ctx.profile.security.restrictionReason ?? "未说明"}`,
          effect: "deny",
          evidence: { reason: ctx.profile.security.restrictionReason },
        },
        userMessage: `您的账户当前处于安全限制状态(${ctx.profile.security.restrictionReason ?? "风控保护中"}),暂时无法发起转账。请通过官方渠道联系我们核实身份后解除。`,
      };
    },
  },

  // --- 首次收款人:无条件升级(新颖度优先于金额) ---
  {
    id: "R-FIRST-PAYEE-ESCALATE",
    description: "首次向新收款人转账,无论金额多小一律要求强验证",
    apply: ({ capability, input }) => {
      if (!capability.moneyMovement) return null;
      // 无对手方的资金操作(如理财申购)不适用"收款人新颖度"这条规则
      if (!isCounterpartyTransfer(input)) return null;
      const novelty = readPayeeNovelty(input);
      if (!novelty.isFirstTime || novelty.isSelfOwned) return null;
      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-FIRST-PAYEE-ESCALATE",
          message: "首次向该收款人转账,按新颖度优先原则无条件升级为强验证",
          effect: "escalate",
          evidence: { successCount: novelty.successCount, isSelfOwned: novelty.isSelfOwned },
        },
      };
    },
  },

  // --- 客户自设阈值(只会更严格) ---
  {
    id: "R-CUSTOMER-THRESHOLD",
    description: "客户自定义的强验证阈值,只允许比系统更严格",
    apply: ({ capability, input, ctx }) => {
      if (!capability.moneyMovement) return null;
      const threshold = ctx.profile.preferences.alwaysStrongAuthAbove;
      if (threshold == null) return null;
      const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;
      if (amount <= threshold) return null;
      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-CUSTOMER-THRESHOLD",
          message: `金额 ${amount} 超过客户自设强验证阈值 ${threshold}`,
          effect: "escalate",
          evidence: { amount, threshold },
        },
      };
    },
  },

  // --- 静态兜底阈值(对应 1.docx 的 1000 元线) ---
  {
    id: "R-STATIC-THRESHOLD",
    description:
      "静态兜底下限:单笔超过配置阈值一律至少需要强验证。可配置,档位见 PolicyConfig。" +
      "已建立信任的收款人(白名单 + 多次成功 + 本人在常用画像中)适用更宽松的档位 —— " +
      "信任是可累积的,否则长期客户会被当成陌生人对待。",
    apply: ({ capability, input }) => {
      if (!capability.moneyMovement) return null;
      // ★ 同上:静态阈值是为转账设计的"新收款人/熟客/本人"分档,
      //   对没有收款人的资金操作(理财申购)没有意义,交给理财的适配性规则去管。
      if (!isCounterpartyTransfer(input)) return null;
      const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;
      const config = getPolicyConfig();
      const novelty = readPayeeNovelty(input);

      // 档位选择:本人账户 → 最宽松;已建立信任 → 宽松;其余 → 严格
      const isSelfOwned = novelty.isSelfOwned;
      const isTrusted = novelty.isWhitelisted && novelty.successCount >= 3;
      const threshold = isSelfOwned
        ? config.selfOwnedStrongAuthAbove
        : isTrusted && novelty.isKnownFrequent
          ? config.trustedPayeeStrongAuthAbove
          : isTrusted
            ? config.knownPayeeStrongAuthAbove
            : config.strongAuthAbove;

      if (amount <= threshold) return null;
      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-STATIC-THRESHOLD",
          message: `金额 ${amount} 超过兜底阈值 ${threshold}${
            isSelfOwned ? "(本人账户互转档位)" : isTrusted ? "(已建立信任收款人档位)" : "(新收款人档位)"
          }`,
          effect: "escalate",
          evidence: { amount, threshold, selfOwned: isSelfOwned, trusted: isTrusted },
        },
      };
    },
  },

  // --- 白名单/高频收款人:有条件降级 ---
  {
    id: "R-TRUSTED-PAYEE-DEESCALATE",
    description: "已建立信任的收款人(白名单 + 多次成功 + 金额在画像内)可降级为普通确认",
    apply: ({ capability, input }) => {
      if (!capability.moneyMovement) return null;
      if (!isCounterpartyTransfer(input)) return null;
      const novelty = readPayeeNovelty(input);
      const trusted = novelty.isSelfOwned || (novelty.isWhitelisted && novelty.successCount >= 3);
      if (!trusted) return null;
      return {
        kind: "note",
        reason: {
          ruleId: "R-TRUSTED-PAYEE-DEESCALATE",
          message: novelty.isSelfOwned
            ? "本人名下账户互转,风险最低"
            : "收款人在白名单且历史成功转账 ≥3 笔,信任度较高",
          effect: "deescalate",
          evidence: { isWhitelisted: novelty.isWhitelisted, successCount: novelty.successCount },
        },
      };
    },
  },

  // ==========================================================================
  // --- 理财场景(场景三)的合规硬规则 ---
  //
  // ★ 为什么这几条必须是**硬规则**而不是提示词里的叮嘱:
  //   它们全部来自监管规定,不是产品经理的偏好。
  //   "首次购买必须测评""不得卖超出风险等级的产品"这类要求,
  //   如果实现成"提示模型注意",那么模型被说服、被注入、或者只是单纯抽风时就会失守。
  //   实现成硬规则后:**命中即生效,没有例外路径** ——
  //   包括没有"管理员可以跳过"这种后门(本项目不存在角色提权这个概念)。
  // ==========================================================================

  // --- 首次购买理财:必须先完成风险测评 ---
  {
    id: "R-WEALTH-ASSESSMENT-REQUIRED",
    description: "未完成风险承受能力测评(或测评已过期)时,不得申购理财产品",
    apply: ({ capability, input }) => {
      if (capability.name !== "wealth.purchase") return null;
      const assessed = input["__riskAssessed"] as boolean | undefined;
      const expired = input["__riskAssessmentExpired"] as boolean | undefined;
      if (assessed && !expired) return null;

      const reason: PolicyReason = expired
        ? {
            ruleId: "R-WEALTH-ASSESSMENT-EXPIRED",
            message: "客户风险测评已过期(有效期 1 年),按监管要求需重新测评后方可申购",
            effect: "deny",
            evidence: { expired: true },
          }
        : {
            ruleId: "R-WEALTH-ASSESSMENT-REQUIRED",
            message: "客户尚未完成风险承受能力测评,按监管要求首次购买理财前必须完成测评",
            effect: "deny",
            evidence: { assessed: false },
          };

      return {
        kind: "deny",
        reason,
        userMessage: expired
          ? "风险测评已超过一年,须重新测评后方可申购。请回复「重新做风险测评」(共 6 题)。"
          : "按监管规定,首次购买理财产品前必须完成风险承受能力测评。请回复「做风险测评」(共 6 题)。",
        guidance: {
          message: "测评结果仅用于判断产品适配。未完成测评时,可以浏览产品,不能受理申购。",
        },
      };
    },
  },

  // --- 风险等级不匹配:必须持有《风险不匹配确认书》 ---
  {
    id: "R-WEALTH-RISK-MISMATCH",
    description: "产品风险等级高于客户风险承受等级时,必须由客户签署风险不匹配确认书,否则阻断",
    apply: ({ capability, input }) => {
      if (capability.name !== "wealth.purchase") return null;

      const productOrdinal = input["__productRiskOrdinal"] as number | undefined;
      const customerOrdinal = input["__customerRiskOrdinal"] as number | undefined;
      if (productOrdinal == null || customerOrdinal == null) return null;
      if (productOrdinal <= customerOrdinal) return null; // 匹配,放行

      const level = input["__productRiskLevel"] as string | undefined;
      const customerLevel = input["__customerRiskLevel"] as string | undefined;
      const gap = productOrdinal - customerOrdinal;

      // 确认书签署凭据由编排器在"用户明确同意"之后写入(__ 前缀,模型看不到也写不了)
      const consentRef = input["__consentRef"] as string | undefined;
      if (consentRef) {
        return {
          kind: "note",
          reason: {
            ruleId: "R-WEALTH-RISK-MISMATCH-CONSENTED",
            message: `产品风险等级 ${level} 高于客户等级 ${customerLevel},客户已签署风险不匹配确认书 ${consentRef}`,
            effect: "pass",
            evidence: { consentRef, productLevel: level, customerLevel, gap },
          },
        };
      }

      return {
        kind: "deny",
        reason: {
          ruleId: "R-WEALTH-RISK-MISMATCH",
          message: `产品风险等级 ${level} 超出客户风险承受等级 ${customerLevel} 共 ${gap} 档,且未取得风险不匹配确认书`,
          effect: "deny",
          evidence: { productLevel: level, customerLevel, gap },
        },
        userMessage:
          `这只产品的风险等级是 ${level},超出您的风险承受能力(${customerLevel})${gap} 档。\n` +
          "按监管规定,我不能直接替您申购 —— 需要您本人签署《风险不匹配确认书》后才能继续。\n" +
          "如果您确认了解并愿意承担相应风险,请回复「签确认书」;如果想换个更稳的产品,我可以帮您筛。",
        guidance: {
          message:
            "这条规则不是拒绝您,而是确保您在**知情**的前提下自己决定。签了确认书之后,申购流程照常走,仍然需要您确认金额与产品。",
        },
      };
    },
  },

  // --- 高风险渠道不得直接完成理财申购/赎回(复用资金操作原则) ---
  {
    id: "R-WEALTH-HIGH-RISK-CHANNEL",
    description: "高风险渠道(如 IM)可截图、可转发,不得在其内完成理财申购赎回的最终确认",
    apply: ({ capability, ctx }) => {
      if (capability.name !== "wealth.purchase" && capability.name !== "wealth.redeem") return null;
      if (ctx.channelCapabilities.risk !== "high") return null;
      if (ctx.channelCapabilities.deepLink && ctx.channelCapabilities.biometric) return null;
      return {
        kind: "note",
        reason: {
          ruleId: "R-WEALTH-HIGH-RISK-CHANNEL",
          message: `理财${capability.name === "wealth.purchase" ? "申购" : "赎回"}在 ${ctx.channel} 渠道发起:该渠道风险等级为 high,确认环节需回到 App 完成身份校验`,
          effect: "escalate",
          evidence: { channel: ctx.channel, channelRisk: ctx.channelCapabilities.risk },
        },
      };
    },
  },

  // --- 反诈:用户话语中出现典型受骗特征 ---
  {
    id: "R-FRAUD-SCRIPT-INDICATOR",
    description: "识别受骗典型话术特征(被催促、被要求保密、被指导操作),触发反诈干预",
    apply: ({ input }) => {
      const raw = input["__fraudSignals"] as
        | { urgency?: boolean; secrecy?: boolean; guided?: boolean; keywords?: string[] }
        | undefined;
      if (!raw) return null;
      const count = [raw.urgency, raw.secrecy, raw.guided].filter(Boolean).length;
      if (count < 2) return null;
      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-FRAUD-SCRIPT-INDICATOR",
          message: `检测到疑似受骗话术特征(${count} 项):${
            [raw.urgency && "被催促", raw.secrecy && "被要求保密", raw.guided && "被指导操作"]
              .filter(Boolean)
              .join("、")
          }`,
          effect: "escalate",
          evidence: { signals: raw },
        },
      };
    },
  },

  // ==========================================================================
  // 卡片管理(场景四)
  //
  // ★ 这一组规则与前面几组有一个结构性差异值得单独说明:
  //   场景一~三的规则几乎都在回答"这个动作风险多大、要不要升级验证",
  //   而卡片场景的第一批规则回答的是**"这件事该不该由 Agent 经手"**。
  //   改手机号、改密码、司法冻结解除 —— 这三件事的共同点是:
  //   它们不是"风险较高的操作",而是"**根本不该经过对话通道的操作**"。
  //   对它们来说,升级验证强度是错的答案:再强的验证也无法让
  //   "对话里改掉短信接收方"变得安全。
  // ==========================================================================

  // --- ★ 凭证变更:极高风险,一律不代理 ---
  {
    id: "R-CARD-CREDENTIAL-CHANGE-BLOCKED",
    description:
      "改绑手机号 / 修改或重置密码属于极高风险凭证变更(账户接管的标准路径),Agent 一律不经手,只引导原生安全流程",
    apply: ({ capability }) => {
      const forbidden = [
        "security.change_phone",
        "security.change_password",
        "card.change_phone",
        "card.change_transaction_password",
        "card.reset_password",
      ];
      if (!forbidden.includes(capability.name)) return null;
      return {
        kind: "deny",
        reason: {
          ruleId: "R-CARD-CREDENTIAL-CHANGE-BLOCKED",
          message:
            `「${capabilityLabel(capability.name)}」属于凭证变更类操作:它会改变"谁能代表客户"这件事` +
            "(短信验证码接收方 / 交易最终凭证),是账户接管的标准路径,不经过对话通道办理",
          effect: "deny",
          evidence: { capability: capability.name, category: "credential_change" },
        },
        userMessage:
          "这一步我不能替您办 —— 修改手机号或密码会改变账户的安全凭证,只能在 App 的安全中心由您本人完成" +
          "(需要原手机号验证 + 人脸识别)。\n" +
          "★ 这不是我偷懒:账户接管最常见的路径就是先改手机号拿到验证码、再改密码、最后转走钱。" +
          "把这一步交给对话通道,等于让前面所有的验证都白做。",
        guidance: {
          deepLink: "app://security/center",
          message:
            "请前往「我的 → 安全中心」完成:① 手机号管理;② 密码管理(登录密码 / 交易密码)。" +
            "需要我帮您确认入口位置或准备材料,可以继续问我。",
        },
      };
    },
  },

  // --- ★ 解除限制:必须先查清原因 ---
  {
    id: "R-CARD-UNBLOCK-REQUIRES-CAUSE",
    description:
      "提交解除限制申请前必须已查清限制原因;司法冻结一律不受理,信息不完整类引导自助完成 —— 不得「直接说帮你解」",
    apply: ({ capability, input }) => {
      if (capability.name !== "card.unblock") return null;

      const cause = input["__cardRestrictionCause"] as string | undefined;

      // ① 没有查清原因就要求解除 —— 这正是需求里点名禁止的行为
      if (!cause) {
        return {
          kind: "deny",
          reason: {
            ruleId: "R-CARD-UNBLOCK-NO-CAUSE",
            message: "未查清卡片交易限制的原因就尝试提交解除申请,已阻断",
            effect: "deny",
            evidence: { cause: null },
          },
          userMessage:
            "在提交解除申请之前,我需要先查清这张卡**为什么被限制** —— 不同原因的处理方式完全不同:" +
            "异常交易可以提交申请、信息不完整要您自己在 App 补全、司法冻结则必须凭有权机关的文书才能解。\n" +
            "直接提交上去,轻则被退回,重则耽误您解决真正的问题。我先帮您查原因。",
          guidance: {
            message: "回复「卡为什么被限制」,我会先给出限制原因、开始时间与对应的处理通道。",
          },
        };
      }

      // ② 司法冻结:银行无权自行解除,Agent 连申请都不该提交
      if (cause === "judicial_freeze") {
        return {
          kind: "deny",
          reason: {
            ruleId: "R-CARD-JUDICIAL-FREEZE",
            message: "卡片限制原因为司法冻结:只能凭有权机关出具的解除冻结通知书办理,Agent 与银行均无权自行解除",
            effect: "deny",
            evidence: { cause },
          },
          userMessage:
            "这张卡是**司法冻结**,不是银行的风控限制。\n" +
            "我没有把解除申请提交上去 —— 因为银行无权自行解除司法冻结,提交了也不会有结果,只会让您白等。\n" +
            "解除司法冻结只能凭有权机关(法院 / 公安等)出具的《解除冻结通知书》办理。" +
            "请联系出具冻结的机关了解案情与解除条件;拿到文书后到任一网点或通过客服提交,银行收到文书即办理解除。",
          guidance: {
            message: "App「卡片详情 → 限制说明」里可以看到冻结机关与文书号。",
          },
        };
      }

      // ③ 信息不完整:需要人脸 + 证件,Agent 无法代办
      if (cause === "incomplete_information") {
        return {
          kind: "deny",
          reason: {
            ruleId: "R-CARD-UNBLOCK-SELF-SERVICE",
            message: "限制原因为信息不完整:补充身份信息需人脸识别与证件上传,只能由客户在原生安全流程中自助完成",
            effect: "deny",
            evidence: { cause },
          },
          userMessage:
            "这张卡是因为**身份信息不完整**(证件过期或地址缺失)被限制的。\n" +
            "这一类不需要提交申请,也**不能在对话里代办** —— 补全信息需要通过人脸识别与证件上传," +
            "只能在 App 的安全流程里由您本人完成。材料提交后一般 1 个工作日内自动解除。\n" +
            "入口:「我的 → 身份信息」。",
          guidance: { deepLink: "app://profile/identity", message: "打开 App「我的 → 身份信息」按提示补全。" },
        };
      }

      // ④ 异常交易 / 安全风险 / 自设限额:可受理,但仍由银行审核(或用户本人确认)
      return null;
    },
  },

  // --- ★ 额度调整:不满时间条件的申请一律受理不了 ---
  {
    id: "R-CARD-LIMIT-TIME-GATE",
    description:
      "额度调整受用卡时长(约 6 个月)与调额冷却期(约 3 个月)约束:不满足时间条件的申请银行不予受理,提前阻断并说明还差多久",
    apply: ({ capability, input }) => {
      if (capability.name !== "card.limit_adjust") return null;
      const status = input["__cardLimitEligibility"] as string | undefined;
      if (status == null || status === "eligible") return null;

      const reason = input["__cardLimitReason"] as string | undefined;
      const waitMonths = typeof input["__cardLimitWaitMonths"] === "number" ? (input["__cardLimitWaitMonths"] as number) : 0;

      const userMessage =
        status === "no_credit_line"
          ? "这张是**借记卡**,没有授信额度这回事 —— 借记卡能花多少取决于卡里余额,不存在提额流程。" +
            "如果您想要的是「先消费后还款」,可以申请一张信用卡;如果是嫌单笔限额低,我可以帮您查消费限额设置。"
          : status === "card_not_usable"
            ? "这张卡当前不可用(挂失 / 冻结 / 未激活),在卡片恢复可用之前提额申请不会被受理 —— 银行无法给一张已冻结的卡审批新额度。我们先解决卡片状态问题。"
            : `${reason ?? "您不满足提额的时间条件。"}\n` +
              `★ 提额不是即时生效的,而且有时间门槛:新开户或刚调额不久的客户通常要用卡满 6 个月左右再申请。` +
              (waitMonths > 0 ? `您大约还需要等 ${waitMonths} 个月。` : "") +
              "我可以先帮您记下提额意向,到时间提醒您。";

      return {
        kind: "deny",
        reason: {
          ruleId: "R-CARD-LIMIT-TIME-GATE",
          message: `提额资格判定为「${status}」:不满足受理条件,已阻断提交${waitMonths > 0 ? `(需再等约 ${waitMonths} 个月)` : ""}`,
          effect: "deny",
          evidence: { eligibility: status, waitMonths },
        },
        userMessage,
        guidance: {
          message:
            "这条门槛是银行的风控规则,不是系统在为难您 —— 提交上去也会被退回,提前告诉您反而省时间。" +
            "如果您的诉求是额度不够用,我可以帮您看临时额度、分期或另一张卡的额度。",
        },
      };
    },
  },

  // --- ★ 额度调整:必须是"申请",不是"已生效" ---
  {
    id: "R-CARD-LIMIT-APPLICATION-ONLY",
    description:
      "提额只能是提交申请:申请提交后额度不会立即变化,任何「已帮你提到 X 万」的表述都是错的 —— 本规则确保载荷里带着目标额度与当前额度两个不同的数",
    apply: ({ capability, input }) => {
      if (capability.name !== "card.limit_adjust") return null;
      const current = input["__cardCurrentLimit"] as number | undefined;
      const requested = input["requestedLimit"] as number | undefined;

      // 目标额度必须高于当前额度,否则这不是提额
      if (current != null && requested != null && requested <= current) {
        return {
          kind: "deny",
          reason: {
            ruleId: "R-CARD-LIMIT-NOT-HIGHER",
            message: `申请额度 ${requested} 未高于当前额度 ${current},不构成提额申请`,
            effect: "deny",
            evidence: { requested, current },
          },
          userMessage: `您要申请的额度(${requested} 元)没有高于当前额度(${current} 元)。提额申请需要填一个比现在更高的目标额度;` +
            "如果您是想**降额**(降低风险敞口),那属于安全方向的操作,我可以直接帮您办。",
        };
      }

      // ★ 只是"记一笔":让审计与展示都能看到"申请 ≠ 生效"
      return {
        kind: "note",
        reason: {
          ruleId: "R-CARD-LIMIT-APPLICATION-ONLY",
          message:
            `提交的是提额**申请**而非额度调整本身:当前额度 ${current ?? "?"} 元,目标额度 ${requested ?? "?"} 元,` +
            "生效与否由银行审核决定",
          effect: "pass",
          evidence: { currentLimit: current, requestedLimit: requested, effectiveImmediately: false },
        },
      };
    },
  },

  // --- ★ 高风险渠道不得完成卡片挂失/补卡这类敏感操作 ---
  {
    id: "R-CARD-HIGH-RISK-CHANNEL",
    description:
      "高风险渠道(如 IM)不得完成涉及卡片凭证的敏感操作:挂失后的补卡选择与激活需回到 App 完成 —— 但挂失冻结本身不拦",
    apply: ({ capability, ctx }) => {
      // ★ 挂失(card.report_loss)刻意不在拦截范围内:
      //   它是止损动作,晚一分钟客户可能就多损失一笔钱。
      //   在 IM 里说一句"卡丢了"就能立刻冻结,恰恰是这个渠道最有价值的用法。
      if (capability.name !== "card.replace" && capability.name !== "card.activate") return null;
      if (ctx.channelCapabilities.risk !== "high") return null;
      if (ctx.channelCapabilities.deepLink && ctx.channelCapabilities.biometric) return null;
      return {
        kind: "note",
        reason: {
          ruleId: "R-CARD-HIGH-RISK-CHANNEL",
          message:
            `卡片${capability.name === "card.replace" ? "补卡" : "激活"}在 ${ctx.channel} 渠道发起:` +
            "该渠道风险等级为 high,补卡与激活涉及卡片凭证,最终确认需回到 App 完成身份校验",
          effect: "escalate",
          evidence: { channel: ctx.channel, channelRisk: ctx.channelCapabilities.risk },
        },
      };
    },
  },

  // ==========================================================================
  // --- 订阅代扣场景的硬规则 ---
  //
  // ★ 这一组规则回答的是本场景最容易被"对话技巧"绕过去的三件事:
  //
  //   ① **取消前必须把账算清。** 客户说"关了它"时,他脑子里有一个金额和一个日期;
  //      如果系统不把这两个数说出来就执行,他确认的其实不是"这一笔"。
  //      所以载荷里缺金额/缺下次扣款日/缺取消后果时,直接拒绝执行 ——
  //      不是"提示一下",是**结构上执行不了**。
  //
  //   ② **取消 ≠ 退款。** 代扣协议只承诺"下一期不再扣",本期已扣费用按协议处理。
  //      这条口径必须出现在载荷与卡片里(refundPolicy),不能靠文案自觉。
  //
  //   ③ **办不到的事不许说办到了。** 商户侧自动续费(应用商店订阅)本行没有协议可解,
  //      系统只能在页面/文案上如实说明并给出商户侧路径。
  //      一旦允许「反正客户也听不出来」地回一句「已帮你取消」,
  //      下个月扣款发生时,前面所有建立的信任都会一次性清零。
  // ==========================================================================

  // --- ★ 取消代扣:必须展示扣费金额、下次扣款日与取消后果 ---
  //
  // ★ 顺序说明:这条排在"不存在 / 商户侧 / 已取消"三条**之后**。
  //   因为这三类情形下,载荷里本来就取不到完整的扣款信息(已取消的没有下次扣款日),
  //   若这条抢在前面,客户得到的会是一句莫名其妙的
  //   「要取消的这一笔我还没交代清楚」—— 而他真正需要听到的是
  //   「这笔已经取消过了」或「这笔只能在商户侧关」。
  //   **先回答"能不能办",再回答"要不要给你看详情"**,顺序反了就会答非所问。
  {
    id: "R-SUB-CANCEL-REQUIRES-DETAIL",
    description:
      "取消订阅代扣前必须已掌握并展示:扣费金额、下次扣款日、签约通道、取消生效口径、本期已扣费用处理与取消后果;缺任何一项即拒绝执行",
    apply: ({ capability, input }) => {
      if (capability.name !== "subscription.cancel") return null;
      // 三类"本来就办不成"的情形由各自更具体的规则回答,不在这里重复拦截
      if (input["__subFound"] === false) return null;
      if (input["__subCancelChannel"] === "merchant") return null;
      if (input["__subStatus"] === "cancelled") return null;

      const merchant = input["__subMerchant"];
      const amount = input["__subAmount"];
      const nextDebitAt = input["__subNextDebitAt"];
      const refundPolicy = input["__subRefundPolicy"];
      const consequence = input["__subCancelConsequence"];
      const effective = input["__subCancelEffective"];

      const missing: string[] = [];
      if (typeof merchant !== "string" || merchant.length === 0) missing.push("扣费商户");
      if (typeof amount !== "number" || !(amount > 0)) missing.push("每期扣费金额");
      if (typeof nextDebitAt !== "number") missing.push("下次扣款时间");
      if (typeof refundPolicy !== "string" || refundPolicy.length === 0) missing.push("本期已扣费用处理");
      if (typeof consequence !== "string" || consequence.length === 0) missing.push("取消后果");
      if (effective !== "next_cycle" && effective !== "immediate") missing.push("取消生效口径");

      if (missing.length === 0) return null;

      return {
        kind: "deny",
        reason: {
          ruleId: "R-SUB-CANCEL-REQUIRES-DETAIL",
          message: `取消代扣的操作详情不完整,缺少:${missing.join("、")} —— 客户在看不到这些信息的情况下「确认」,等于没有确认`,
          effect: "deny",
          evidence: { capability: capability.name, missing },
        },
        userMessage:
          "我还不能执行这次取消 —— 因为**要取消的这一笔我还没向您交代清楚**。\n" +
          "取消代扣至少要说清三件事:每期扣多少钱、下一次什么时候扣、取消之后本期已扣的费用怎么办。\n" +
          "说得不清楚就让您点「确认」,那个「确认」是没有意义的。我先把它查清楚再给您看。",
        guidance: {
          message: "回复「我的订阅代扣有哪些」,我会把每笔的金额与下次扣款时间一起列出来。",
        },
      };
    },
  },

  // --- ★ 取消一个不存在的订阅:明确告知,绝不假装办成 ---
  {
    id: "R-SUB-NOT-FOUND",
    description:
      "请求取消的订阅在流水与代扣协议里都不存在时,明确告知并列出客户实际持有的订阅 —— 不得为了让对话继续而声称已处理",
    apply: ({ capability, input }) => {
      if (capability.name !== "subscription.cancel") return null;
      if (input["__subFound"] !== false) return null;

      const query = typeof input["__subQuery"] === "string" ? String(input["__subQuery"]) : "这笔订阅";
      const known = Array.isArray(input["__subKnownMerchants"]) ? (input["__subKnownMerchants"] as string[]) : [];

      return {
        kind: "deny",
        reason: {
          ruleId: "R-SUB-NOT-FOUND",
          message: `未找到客户请求取消的订阅「${query}」:流水与代扣协议中均无匹配,已拒绝执行`,
          effect: "deny",
          evidence: { query, knownCount: known.length, known },
        },
        userMessage:
          `我没有找到「${query}」这笔订阅代扣,**所以什么都没有执行**。\n` +
          (known.length > 0
            ? `您目前识别到的订阅代扣是:${known.join("、")}。\n` +
              "★ 想取消其中哪一笔,可以直接说它的名字或序号 —— 我会先把金额与下次扣款时间念给您听,再等您确认。"
            : "近半年的流水里也没有识别到任何订阅代扣。"),
        guidance: {
          message:
            "★ 取消一笔不存在的订阅是**执行不了**的:系统不会为了让对话继续而假装办成一件事 ——" +
            "那会让客户以为已经关掉了,下个月发现还在扣款时,再也不会相信这个系统。",
        },
      };
    },
  },

  // --- ★ 商户侧自动续费:本行没有协议可解,不许声称已取消 ---
  {
    id: "R-SUB-MERCHANT-SIDE-NO-MANDATE",
    description:
      "该笔订阅的签约方在商户侧(应用商店/第三方代扣),本行没有可解除的代扣协议:只能在商户侧关闭,Agent 不得声称已代为取消",
    apply: ({ capability, input }) => {
      if (capability.name !== "subscription.cancel") return null;
      const channel = input["__subCancelChannel"];
      if (channel !== "merchant") return null;

      const merchant = typeof input["__subMerchant"] === "string" ? String(input["__subMerchant"]) : "这笔订阅";
      const path =
        typeof input["__subMerchantCancelPath"] === "string"
          ? String(input["__subMerchantCancelPath"])
          : "在该商户 App 的「订阅 / 自动续费」设置里关闭";

      return {
        kind: "deny",
        reason: {
          ruleId: "R-SUB-MERCHANT-SIDE-NO-MANDATE",
          message: `${merchant}:签约方在商户侧,本行无代扣协议可解 —— 已拒绝执行,只提供商户侧关闭路径`,
          effect: "deny",
          evidence: { merchant, channel, path },
        },
        userMessage:
          `「${merchant}」这笔我**不能在这里替您取消** —— 本行没有它的代扣协议。\n` +
          "它的钱是商户侧(应用商店 / 第三方支付)发起扣的,本行只能看到扣款记录,没有可解的协议。\n\n" +
          `★ 关闭路径:${path}\n` +
          "关掉之后建议留意下一条扣款日,确认不再扣款。",
        guidance: {
          message:
            "★ 我不会为了让这句话听起来更顺而回一句「已帮您取消」 ——" +
            "那样您会在下个月发现钱还是被扣了,而那时您已经不知道该找谁。",
        },
      };
    },
  },

  // --- ★ 已经取消过的:明确告知,不重复执行 ---
  {
    id: "R-SUB-ALREADY-CANCELLED",
    description: "该代扣协议此前已取消:明确告知取消时间与不再扣款的事实,不重复执行",
    apply: ({ capability, input }) => {
      if (capability.name !== "subscription.cancel") return null;
      if (input["__subStatus"] !== "cancelled") return null;

      const merchant = typeof input["__subMerchant"] === "string" ? String(input["__subMerchant"]) : "这笔订阅";
      const cancelledAt = typeof input["__subCancelledAt"] === "number" ? (input["__subCancelledAt"] as number) : null;

      return {
        kind: "deny",
        reason: {
          ruleId: "R-SUB-ALREADY-CANCELLED",
          message: `${merchant} 的代扣协议此前已取消${cancelledAt != null ? `(${formatDateTime(cancelledAt)})` : ""},不重复执行`,
          effect: "deny",
          evidence: { merchant, cancelledAt },
        },
        userMessage:
          `「${merchant}」这笔代扣**已经取消过了**` +
          `${cancelledAt != null ? `(取消时间 ${formatDateTime(cancelledAt)})` : ""},不会再扣款,不需要再操作一次。\n` +
          "★ 如果这个月还是被扣了,那不是这份协议扣的 —— 把扣款日期和金额告诉我,我帮您查是哪一笔。",
        guidance: {
          message: "重复取消本身没有风险,但它会让客户以为「上次没关成」 —— 如实告知比再执行一遍更有价值。",
        },
      };
    },
  },

  // --- 取消代扣的代价必须可追溯(生效口径 + 退款政策 + 后果) ---
  {
    id: "R-SUB-CANCEL-CONSEQUENCE",
    description:
      "取消代扣的生效口径、本期费用处理与后果必须登记在策略理由里 —— 事后争议时,'当时告知了什么'必须有据可查",
    apply: ({ capability, input }) => {
      if (capability.name !== "subscription.cancel") return null;
      if (input["__subFound"] === false || input["__subCancelChannel"] === "merchant") return null;
      if (input["__subStatus"] === "cancelled") return null;

      const merchant = typeof input["__subMerchant"] === "string" ? String(input["__subMerchant"]) : "订阅代扣";
      const amount = typeof input["__subAmount"] === "number" ? (input["__subAmount"] as number) : null;
      const effective = input["__subCancelEffective"] === "immediate" ? "立即生效" : "下一期起不再扣款";

      return {
        kind: "note",
        reason: {
          ruleId: "R-SUB-CANCEL-CONSEQUENCE",
          message:
            `${merchant}:取消生效口径「${effective}」,本期已扣 ${amount != null ? formatAmount(amount) : "—"} 元按协议处理 —— ` +
            `费用处理:${String(input["__subRefundPolicy"] ?? "—")};后果:${String(input["__subCancelConsequence"] ?? "—")}`,
          effect: "pass",
          evidence: {
            merchant,
            effective: input["__subCancelEffective"],
            refundPolicy: input["__subRefundPolicy"],
            consequence: input["__subCancelConsequence"],
          },
        },
      };
    },
  },

  // ==========================================================================
  // 跨场景事件联动(新场景)
  //
  // ★ 规则顺序为什么是这样(与订阅场景同一条教训,但这里更硬):
  //   ① 先回答"这次请求**有没有方案**" —— 没有方案就直接拒绝,
  //      而不是继续去检查金额够不够、商户在不在。一个即兴的
  //      「帮我锁定 1200 块」根本不属于联动方案的步骤,它应当走转账/理财那些场景;
  //   ② 再回答"这一步**说清钱去哪了吗**" —— 这是合规要求的核心,
  //      缺项必须拒绝执行,而不是提示一句"建议补充";
  //   ③ 最后才谈商户是否存在、金额是否达到起订线这类**业务可行性**。
  //   顺序颠倒的后果很具体:一份没交代去向的步骤会先被回一句
  //   「这个商户不接单」—— 客户以为问题出在商户身上。
  // ==========================================================================

  // --- ★ 没有方案就没有步骤:方案是逐步确认的前提 ---
  {
    id: "R-EVENT-PLAN-REQUIRED",
    description:
      "执行事件联动的某一步之前,必须存在一份客户看到过的方案:缺少方案号或步骤号时拒绝执行 —— 逐步确认的前提是'有步骤可确认'",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.fund_step" && capability.name !== "event.external_step") return null;
      // 只有"系统明确判定缺方案"时才拦;注入器没跑到的路径不在这里误伤
      if (input["__evPlanMissing"] !== true) return null;

      return {
        kind: "deny",
        reason: {
          ruleId: "R-EVENT-PLAN-REQUIRED",
          message: "本次请求没有对应的联动方案步骤(缺 planId/stepId),已拒绝执行",
          effect: "deny",
          evidence: { planId: input["__evPlanId"] ?? null, stepId: input["__evStepId"] ?? null },
        },
        userMessage:
          "这次我**没有可执行的方案步骤** —— 所以什么都没有办。\n" +
          "★ 事件联动的每一步都必须先从方案里出来:您先说一句「帮我规划一下」(并说清是哪件事)," +
          "我把方案摆给您看,然后您再逐步确认。\n" +
          "★ 如果您要办的是**另一件事**(比如单纯转一笔钱、买一笔理财)," +
          "直接说那件事就行 —— 那些场景有自己的确认流程,不必绕到方案里来。",
        guidance: {
          message:
            "★ 这条规则的含义:方案是逐步确认的前提。" +
            "没有方案就没有'这一步',也就没有'这一步该确认什么' —— 此时任何执行都等于替客户做了一个他没看过的决定。",
        },
      };
    },
  },

  // --- ★ 说不清钱的去向,就不许执行 ---
  {
    id: "R-EVENT-FUNDS-NOT-DISCLOSED",
    description:
      "资金/外部步骤必须在执行前把每一笔资金的去向与金额交代完整(从哪出、给谁、多少、什么时候):缺任何一项一律拒绝执行",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.fund_step" && capability.name !== "event.external_step") return null;
      if (input["__evFundsDisclosed"] !== false) return null;

      return {
        kind: "deny",
        reason: {
          ruleId: "R-EVENT-FUNDS-NOT-DISCLOSED",
          message: `步骤 ${String(input["__evStepId"] ?? "?")} 的资金去向披露不完整,已拒绝执行`,
          effect: "deny",
          evidence: {
            stepId: input["__evStepId"] ?? null,
            amount: input["__evStepAmount"] ?? null,
            toName: input["toName"] ?? input["merchantName"] ?? null,
            scheduledAt: input["scheduledAt"] ?? null,
            disclosure: input["__evDisclosure"] ?? null,
          },
        },
        userMessage:
          "这一步我**不能执行** —— 因为它还没有把钱的去向和金额说清楚。\n" +
          "涉及跨场景的操作,规矩是:每一笔钱从哪个账户出、给谁、多少、什么时候,四件事都得先摆在您面前。\n" +
          "★ 说得不清楚就让您点确认,那个确认是没有意义的 —— 所以我先把它补全再给您看。",
        guidance: {
          message:
            "★ 这不是一句提醒,而是一条硬规则:字段层面缺项即拒绝。" +
            "把'必须事先明确告知每一笔资金去向'写成提示词只是请求,写成规则才是保证。",
        },
      };
    },
  },

  // --- ★ 商户必须是目录里的真实项(外部订单不能打到不存在的商户) ---
  {
    id: "R-EVENT-MERCHANT-NOT-IN-CATALOG",
    description: "外部服务操作的目标商户必须在银行侧的外部商户目录中:查不到即拒绝,不得向一个不存在的商户下单",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.external_step") return null;
      if (input["__evMerchantFound"] !== false) return null;

      const name = typeof input["merchantName"] === "string" ? String(input["merchantName"]) : "这个商户";
      return {
        kind: "deny",
        reason: {
          ruleId: "R-EVENT-MERCHANT-NOT-IN-CATALOG",
          message: `外部商户「${name}」不在目录中,已拒绝下单`,
          effect: "deny",
          evidence: { merchantName: name, merchantId: input["merchantId"] ?? null },
        },
        userMessage:
          `我没有在外部商户目录里找到「${name}」,**所以没有提交任何订单**。\n` +
          "★ 这一步只做能核实的事:下单对象的商户名与目录必须对得上;" +
          "对不上时我不会为了把流程走完而「先下单再说」。",
        guidance: {
          message: "业务可行性判断放在披露检查之后:先确认'说不说得清',再确认'办不办得到'。",
        },
      };
    },
  },

  // --- 起订金额 ---
  {
    id: "R-EVENT-BELOW-MIN-AMOUNT",
    description: "外部订单金额低于商户起订线时拒绝提交,并如实告知起订金额",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.external_step") return null;
      if (input["__evBelowMinAmount"] !== true) return null;

      const name = typeof input["__evMerchantName"] === "string" ? String(input["__evMerchantName"]) : "该商户";
      const min = typeof input["__evMerchantMinAmount"] === "number" ? (input["__evMerchantMinAmount"] as number) : null;
      const amount = typeof input["__evStepAmount"] === "number" ? (input["__evStepAmount"] as number) : null;

      return {
        kind: "deny",
        reason: {
          ruleId: "R-EVENT-BELOW-MIN-AMOUNT",
          message: `${name}:订单金额 ${amount != null ? formatAmount(amount) : "—"} 低于起订 ${min != null ? formatAmount(min) : "—"},已拒绝`,
          effect: "deny",
          evidence: { merchantName: name, amount, minAmount: min },
        },
        userMessage:
          `「${name}」的起订金额是 ¥${min != null ? formatAmount(min) : "—"},` +
          `现在这一步是 ¥${amount != null ? formatAmount(amount) : "—"},达不到起订线,**没有提交订单**。\n` +
          "★ 您可以把这一项去掉、改成别的方式,或者把金额提到起订线以上 —— 改完我重新出方案。",
        guidance: {
          message: "金额来自商户目录,不由模型或编排器调整 —— 差一块钱也是差。",
        },
      };
    },
  },

  // --- ★ 外部订单必须走强验证(红色),不允许被任何上游许可降级 ---
  {
    id: "R-EVENT-EXTERNAL-REQUIRES-STRONG-AUTH",
    description:
      "外部服务操作是唯一'钱离开银行体系'的动作:必须强制在 strong_auth 档执行,不得继承前置步骤(如资金操作)的许可",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.external_step") return null;
      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-EVENT-EXTERNAL-REQUIRES-STRONG-AUTH",
          message: "外部订购/打款:钱将离开银行体系并形成商户订单,强制强验证档",
          effect: "escalate",
          evidence: { capability: capability.name, amount: input["__evStepAmount"] ?? null },
        },
      };
    },
  },

  // --- 大额资金预留:提高一档 ---
  {
    id: "R-EVENT-FUND-STEP-AMOUNT-CAP",
    description: "单步预留资金超过阈值时提高到强验证档 —— 金额越大,越不能只靠一次普通确认",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.fund_step") return null;
      /**
       * ★ 优先用银行侧事实 `__evStepAmount`,并**回落到公开的 amount**。
       *
       *   为什么要回落:两者本该一致(注入器就是从 amount 回填的),但注入器只在
       *   "能被解析成数字"时才回填 —— 如果模型把金额写成字符串("50000"),
       *   `__evStepAmount` 会是 null,而执行层 `Number(input.amount)` 照样能算出 5 万。
       *   只认私有字段的后果就是:**金额偏大时那条"提高一档"的规则悄悄失效**。
       *   回落是安全的:公开 amount 就是真正会被执行的金额,拿它定档不会错。
       */
      const raw = input["__evStepAmount"] ?? input["amount"];
      const amount =
        typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() !== "" ? Number(raw) : null;
      if (amount == null || !Number.isFinite(amount) || amount <= EVENT_FUND_STEP_WARN_AMOUNT) return null;

      return {
        kind: "force_tier",
        tier: "strong_auth",
        reason: {
          ruleId: "R-EVENT-FUND-STEP-AMOUNT-CAP",
          message: `单步预留 ¥${formatAmount(amount)} 超过 ¥${formatAmount(EVENT_FUND_STEP_WARN_AMOUNT)},提高到强验证档`,
          effect: "escalate",
          evidence: { amount, threshold: EVENT_FUND_STEP_WARN_AMOUNT },
        },
      };
    },
  },

  // --- 逐步确认的事实必须可追溯 ---
  {
    id: "R-EVENT-STEP-DISCLOSURE",
    description:
      "每一步执行时,把'这一步的金额、去向、时间、分级'登记进策略理由 —— 事后必须能回答'客户确认的到底是哪一步、看到的是什么'",
    apply: ({ capability, input }) => {
      if (capability.name !== "event.fund_step" && capability.name !== "event.external_step") return null;
      if (input["__evFundsDisclosed"] === false) return null;
      if (input["__evPlanMissing"] === true) return null;

      const domain = input["__evStepDomain"] === "external" ? "外部服务操作" : "资金操作";
      return {
        kind: "note",
        reason: {
          ruleId: "R-EVENT-STEP-DISCLOSURE",
          message:
            `联动方案 ${String(input["__evPlanId"] ?? "—")} 的 ${String(input["__evStepId"] ?? "—")}(${domain}):` +
            `${String(input["__evDisclosure"] ?? "—")}`,
          effect: "pass",
          evidence: {
            planId: input["__evPlanId"] ?? null,
            stepId: input["__evStepId"] ?? null,
            domain: input["__evStepDomain"] ?? null,
            amount: input["__evStepAmount"] ?? null,
            toName: input["toName"] ?? input["merchantName"] ?? null,
            scheduledAt: input["scheduledAt"] ?? null,
          },
        },
      };
    },
  },

  // --- 方案生成 ≠ 执行(留痕) ---
  {
    id: "R-EVENT-PLAN-NOT-EXECUTED",
    description:
      "生成方案这一步本身不得执行任何步骤:策略理由里明确登记'本次没有任何资金被锁定、没有任何订单被创建'",
    apply: ({ capability }) => {
      if (capability.name !== "cross_scene_event_planning") return null;
      return {
        kind: "note",
        reason: {
          ruleId: "R-EVENT-PLAN-NOT-EXECUTED",
          message: "已生成跨场景联动方案;本次没有任何资金被锁定、没有任何外部订单被创建 —— 资金操作与外部服务操作需分别确认",
          effect: "pass",
          evidence: { executed: false, splitConfirmation: ["fund", "external"] },
        },
      };
    },
  },

  // --- ★ 频次上限(滑动窗口,按客户 × 能力类别 × 时间窗) ---
  {
    id: "R-FREQUENCY-LIMIT",
    description:
      "频次类硬规则:同一客户在同一时间窗内对同一类能力的调用次数超过上限时拦下本次。" +
      "窗口与上限由 DEFAULT_FREQUENCY_RULES 定义(只读宽松、资金严格),可按类别配置。" +
      "与名单命中、拆分检测同源 —— 理由里必须能读出'哪条规则、哪个窗口、计数多少'。",
    apply: ({ frequency }) => {
      /**
       * ★ 快照缺失 = 未命中(而不是"默认严拦")。
       *   理由:卡片预演、只读试算这类路径也会走 evaluatePolicy,它们不该消耗额度,
       *   更不该因为"没数过"被判成超限。真正的计数由编排器在**请求阶段**完成。
       */
      if (!frequency?.overLimit) return null;
      const cooldownText =
        frequency.cooldownUntil != null
          ? `;已进入冷静期,${new Date(frequency.cooldownUntil).toISOString()} 后可再试`
          : "";
      return {
        kind: "force_tier",
        tier: "blocked",
        reason: {
          ruleId: "R-FREQUENCY-LIMIT",
          message:
            `${frequency.label}类操作在 ${frequency.windowLabel}内已发生 ${frequency.count} 次,` +
            `超过上限 ${frequency.max} 次(规则 ${frequency.ruleId},窗口 ${frequency.windowMs} ms)${cooldownText}`,
          effect: "deny",
          evidence: {
            category: frequency.category,
            windowMs: frequency.windowMs,
            windowLabel: frequency.windowLabel,
            count: frequency.count,
            limit: frequency.max,
            frequencyRuleId: frequency.ruleId,
            cooldownUntil: frequency.cooldownUntil,
          },
        },
        /**
         * ★ 拦截话术由规则给出(而不是落回引擎那条通用拦截文案):
         *   通用的「该操作需要在我们无法代理的安全流程中完成」对"你转得太快"是**答非所问**,
         *   客户会以为系统坏了。这里必须说清"多久之内只能几笔"。
         */
        userMessage:
          `短时间内${frequency.label}次数过多(${frequency.windowLabel}内 ${frequency.count} 次,上限 ${frequency.max} 次),` +
          `为保护您的账户安全,这一笔**没有执行**。` +
          (frequency.cooldownUntil != null
            ? `请稍后再试,或换个方式办理。`
            : `请稍后再试;如果确实是本人连续操作,可以到网点由柜员协助办理。`),
      };
    },
  },

  // --- ★ 连续注入命中 → 冷却(注入检测从"证据"变为"主动防御") ---
  {
    id: "R-INJECTION-COOLDOWN",
    description:
      "连续多次命中提示注入检测时进入冷却:此前注入检测只写审计(事后可查),对正在发生的攻击没有作用。" +
      "达到阈值后按硬规则拦下后续操作,直到冷却结束。",
    apply: ({ frequency }) => {
      if (!frequency?.injectionCooldown) return null;
      return {
        kind: "force_tier",
        tier: "blocked",
        reason: {
          ruleId: "R-INJECTION-COOLDOWN",
          message:
            `连续 ${frequency.injectionHits} 次命中提示注入检测(阈值 ${INJECTION_COOLDOWN_HITS} 次),` +
            `已进入冷却,当前操作被拦下`,
          effect: "deny",
          evidence: {
            injectionHits: frequency.injectionHits,
            threshold: INJECTION_COOLDOWN_HITS,
            cooldownMs: INJECTION_COOLDOWN_MS,
          },
        },
        userMessage:
          "检测到本会话的输入连续出现可疑的指令型内容(疑似诱导我忽略安全规则)," +
          "为保护您的账户,已暂时停止办理新操作。请稍后重新发起,或直接说明您要办的事。",
      };
    },
  },
];

// ============================================================================
// 策略配置(可外部注入,便于演示"阈值可配置"与合规调参)
// ============================================================================

export interface PolicyConfig {
  /** 非本人、非信任收款人的单笔强验证下限(对应 1.docx 的 1000 元线) */
  strongAuthAbove: number;
  /** 已建立信任的收款人(白名单 + ≥3 次成功)的档位 */
  knownPayeeStrongAuthAbove: number;
  /** 已建立信任且在客户常用画像中的收款人的档位 */
  trustedPayeeStrongAuthAbove: number;
  /** 本人名下账户互转的档位(风险最低,可放宽) */
  selfOwnedStrongAuthAbove: number;
  /** 单日累计限额 */
  dailyLimit: number;
  /** 未清算可撤销窗口(毫秒) */
  cancellableWindowMs: number;
  /** 确认载荷有效期(毫秒) */
  confirmTtlMs: number;
  /** 强验证令牌有效期(毫秒) */
  actionTokenTtlMs: number;
  /**
   * ★ 频次规则表(按客户 × 能力类别 × 时间窗的滑动窗口上限)。
   *
   * 为什么做成配置而不写死:演示脚本、压测、以及"某类业务临时收紧"都需要调它,
   * 而调它必须**只改一处**。默认值就是 DEFAULT_FREQUENCY_RULES(只读宽松、资金严格)。
   * 传数组即整体替换(不是逐条合并)—— 逐条合并会让"删掉一条规则"变成不可能,
   * 而临时放宽某类正是要能删。
   */
  frequency: FrequencyRule[];
  /**
   * ★ 评分器配置(第 4 项)。
   *
   * 三个模式的分工必须说清楚,否则"换模型"会变成一件无法回滚的事:
   *   · `legacy`  —— 手调线性权重。**默认值**,因此所有既有回归断言的行为不变。
   *   · `shadow`  —— 裁决仍走 legacy,同时并行算 challenger 并记录分歧。
   *                  这是上线前的必经阶段:先看分歧率与分歧原因,再决定要不要切。
   *   · `logistic`—— 训练出的逻辑回归真正接管评分。**裁决体系不变**:
   *                  阈值(`mapScoreToTier`)不动、硬规则继续确定性覆盖、
   *                  硬命中(名单/拆分)仍不交给模型。
   *
   * ★ 为什么默认是 legacy 而不是"最新模型":
   *   评分器是安全组件,升级必须是**显式动作**(有人按下开关、有人看过报告),
   *   不能因为"代码里更新了模型文件"就悄悄改变线上的安全行为。
   */
  scorer: {
    mode: "legacy" | "shadow" | "logistic";
    /** 训练产物(生成文件);为 null 时如实回落到 legacy,不冒充已升级 */
    model: LinearScorerModel | null;
  };
}

const DEFAULT_POLICY_CONFIG: PolicyConfig = {
  /** 新收款人:严格档位 */
  strongAuthAbove: 1000,
  /** 熟客:适度放宽 —— 但仍需用户确认(不会自动执行) */
  knownPayeeStrongAuthAbove: 5000,
  /** 长期高频熟客:进一步放宽 */
  trustedPayeeStrongAuthAbove: 20_000,
  /** 本人账户互转:最宽松 */
  selfOwnedStrongAuthAbove: 50_000,
  dailyLimit: 200_000,
  cancellableWindowMs: 5 * 60 * 1000,
  confirmTtlMs: 3 * 60 * 1000,
  actionTokenTtlMs: 2 * 60 * 1000,
  frequency: [...DEFAULT_FREQUENCY_RULES],
  scorer: {
    /** 默认不改变任何既有行为:安全组件的升级必须是显式动作 */
    mode: "legacy",
    model: LOGISTIC_V1_MODEL,
  },
};

let activeConfig: PolicyConfig = { ...DEFAULT_POLICY_CONFIG };

export function getPolicyConfig(): PolicyConfig {
  return activeConfig;
}

export function configurePolicy(partial: Partial<PolicyConfig>): PolicyConfig {
  activeConfig = { ...activeConfig, ...partial };
  return activeConfig;
}

export function resetPolicyConfig(): void {
  activeConfig = { ...DEFAULT_POLICY_CONFIG };
}

/**
 * ★ 切换评分器(第 4 项),**唯一的切换入口**。
 *
 * 为什么单独给一个函数,而不是让调用方自己拼 `configurePolicy({ scorer: {...} })`:
 *   `configurePolicy` 是**整体替换** `scorer` 字段的浅合并。调用方若忘了带 model,
 *   就会得到"要新评分器但没有模型"的配置 —— 那种状态虽然会如实回落到 legacy,
 *   但它本可以避免。这里把两件事绑在一次调用里,并要求显式给出模型(或 null)。
 *
 * ★ 影子模式与正式切换的差别就是这一个参数:换的只是评分器,裁决体系不变。
 */
export function configureScorer(
  mode: "legacy" | "shadow" | "logistic",
  model: LinearScorerModel | null = LOGISTIC_V1_MODEL,
): PolicyConfig {
  activeConfig = { ...activeConfig, scorer: { mode, model } };
  return activeConfig;
}

// ============================================================================
// 主裁决函数
// ============================================================================

/**
 * 对一个能力调用做出裁决。
 *
 * 执行顺序:
 *   1. 硬规则的 deny / handoff 判定(绝对约束,优先)
 *   2. 风险评分 → 基础分级
 *   3. 硬规则的 force_tier 升级(只升不降)
 *   4. 基线分级兜底(能力自身的 baseTier 作为下限)
 *   5. 输出裁决 + 完整理由链
 */
export function evaluatePolicy(request: PolicyRequest): PolicyDecision {
  const reasons: PolicyReason[] = [];
  const { capability } = request;

  // ---- 1. 绝对约束 ----
  for (const rule of DEFAULT_RULES) {
    const outcome = rule.apply(request);
    if (!outcome) continue;

    if (outcome.kind === "deny") {
      reasons.push(outcome.reason);
      return {
        effect: "deny",
        tier: "blocked",
        reasons,
        userMessage: outcome.userMessage,
        guidance: outcome.guidance,
      };
    }
    if (outcome.kind === "handoff") {
      reasons.push(outcome.reason);
      return {
        effect: "handoff",
        reasons,
        handoffSpec: {
          reason: outcome.reason.message,
          urgency: outcome.urgency,
          contextSummary: outcome.contextSummary,
        },
      };
    }
  }

  // ---- 2. 风险评分 ----
  const risk = assessRisk(request);
  let tier: Tier = risk.tierFromScore;
  reasons.push({
    ruleId: "R-RISK-SCORE",
    message: `风险评分 ${risk.score.toFixed(1)} → 基础分级 ${tier}`,
    effect: "pass",
    /**
     * ★ 证据里带上**输入特征**、**评分器标识**与**影子分歧**(第 4 项)。
     *
     * 为什么必须落审计而不是只留在内存里:
     *   ① 标签管道要把"事后结局"回填到"当时那一笔请求"上,必须有当时的输入;
     *   ② "同一批请求在新旧评分器下的档位分布"要用当时的输入重算,不能拿旧分数当输入;
     *   ③ 可解释性契约要能回答"这一分是怎么来的" —— factors 给了每项贡献多少,
     *      features 给了每项输入是多少,scorer 说明是谁算的。
     *   闭环:结局 → 标签 → 重训 → 影子对比 → 显式切换,每一步都有审计可查。
     */
    evidence: {
      score: risk.score,
      factors: risk.factors,
      ...(risk.features ? { features: risk.features } : {}),
      ...(risk.scorer ? { scorer: risk.scorer } : {}),
      ...(risk.shadow ? { shadow: risk.shadow } : {}),
      ...(risk.legacyScore != null ? { legacyScore: risk.legacyScore } : {}),
    },
  });

  // ---- 3. 强制升级(只升不降) ----
  /**
   * ★ 记下"把分级顶到 blocked 的那条规则想对客户说什么"。
   *   通用拦截文案(下面第 5 步)是给"需要去线下完成的安全流程"用的;
   *   而频次超限这类拦截必须说清"多久之内只能几笔",否则客户以为系统坏了。
   *   规则给不出话术时仍然回落到通用文案 —— 行为与之前完全一致。
   */
  let blockedUserMessage: string | undefined;
  for (const rule of DEFAULT_RULES) {
    const outcome = rule.apply(request);
    if (!outcome) continue;
    if (outcome.kind === "force_tier") {
      const before = tier;
      tier = escalate(tier, outcome.tier);
      if (tier !== before) {
        reasons.push(outcome.reason);
        if (tier === "blocked" && outcome.userMessage) blockedUserMessage = outcome.userMessage;
      }
    } else if (outcome.kind === "note") {
      reasons.push(outcome.reason);
    }
  }

  // ---- 4. 能力基线分级作为下限 ----
  const withBaseline = escalate(tier, capability.baseTier);
  if (withBaseline !== tier) {
    reasons.push({
      ruleId: "R-CAPABILITY-BASELINE",
      /**
       * ★ 消息里写的是**人话说法**,不是 `capability.name`。
       *   这条理由会随 policySummary 出现在界面「裁决依据」里、也会进流程链,
       *   而原来它渲染出来是「能力 transfer.submit 的基线分级为 confirm,作为下限生效」——
       *   客户看不懂,而且把内部标识摊在了他面前。
       *   规则 ID(R-CAPABILITY-BASELINE)保持不变:那才是排查用的稳定标识。
       */
      message: `「${capabilityLabel(capability.name)}」这类操作的基线档位是 ${capability.baseTier},因此按下限生效`,
      effect: "escalate",
      evidence: { baseline: capability.baseTier, capability: capability.name },
    });
    tier = withBaseline;
  }

  // ---- 5. 输出裁决 ----
  if (tier === "blocked") {
    return {
      effect: "deny",
      tier: "blocked",
      reasons,
      userMessage: blockedUserMessage ?? "该操作需要在我们无法代理的安全流程中完成。",
    };
  }

  if (tier === "auto") {
    // 自动执行的护栏:只读能力,或被显式标记为低风险可自动的写能力。
    // ★ 默认拒绝:任何新增能力若不显式声明 autoExecutable,都不会自动执行。
    //   这是"安全默认值"原则 —— 忘记声明时偏向更严格的一侧。
    if (!capability.readOnly && !capability.autoExecutable) {
      reasons.push({
        ruleId: "R-AUTO-REQUIRES-READONLY",
        message: "该能力未声明可自动执行,已回退为用户确认",
        effect: "escalate",
      });
      return buildConfirmDecision(request, reasons);
    }
    return { effect: "allow", tier: "auto", reasons };
  }

  if (tier === "confirm") {
    return buildConfirmDecision(request, reasons);
  }

  return buildStrongAuthDecision(request, reasons);
}

// ============================================================================
// 裁决结果构造
// ============================================================================

/**
 * 冻结载荷哈希。**I4 的实现**:
 * 用户确认的是这个哈希;执行时重新计算并比对,不一致则拒绝执行(防 TOCTOU)。
 *
 * 参与哈希的字段是**影响资金与对手方的全部字段**,任何变化都会导致哈希变化:
 * 金额、币种、收款人、账号、备注、费用、计划时间。
 */
export function computePayloadHash(capabilityName: string, input: Record<string, unknown>): string {
  const material = {
    capability: capabilityName,
    amount: input["amount"] ?? null,
    currency: input["currency"] ?? null,
    payeeId: input["payeeId"] ?? null,
    payeeName: input["payeeName"] ?? null,
    accountNo: input["accountNo"] ?? null,
    phone: input["phone"] ?? null,
    bankCode: input["bankCode"] ?? null,
    memo: input["memo"] ?? null,
    fromAccountId: input["fromAccountId"] ?? null,
    scheduledAt: input["scheduledAt"] ?? null,
    fee: input["__fee"] ?? null,
  };
  return createHash("sha256").update(JSON.stringify(material), "utf8").digest("hex");
}

/**
 * 生成"需确认"裁决。
 *
 * ★ 不再接收 tier 参数:这个函数的产出**恒为 confirm 档**(它自己填的就是
 *   `tier: "confirm"`)。原来那个参数只写不读 —— 一个可以传 "blocked" 却依然
 *   返回 confirm 的参数,留着只会让人误以为档位可调。
 */
function buildConfirmDecision(
  request: PolicyRequest,
  reasons: PolicyReason[],
): PolicyDecision {
  const { capability, input, ctx } = request;
  const payloadHash = computePayloadHash(capability.name, input);
  const config = getPolicyConfig();

  // 优先使用业务层提供的展示(信息更完整),否则回退到引擎自动生成
  const card = request.presentation?.card ?? buildConfirmCard(capability, input, ctx);
  const humanReadable = renderCardAsText(card);

  const confirmSpec: ConfirmSpec = {
    payloadHash,
    humanReadable,
    card,
    ttlMs: config.confirmTtlMs,
  };

  return { effect: "require_confirm", tier: "confirm", reasons, confirmSpec };
}

/** 生成"需强验证"裁决(tier 恒为 strong_auth,故不再接收档位参数) */
function buildStrongAuthDecision(
  request: PolicyRequest,
  reasons: PolicyReason[],
): PolicyDecision {
  const { capability, input, ctx } = request;

  // ★ 强验证路径同样必须展示完整操作详情。
  //   曾经的设计缺陷:强验证分支只展示"验证方式 + 有效期",用户在做人脸识别时
  //   根本看不到自己要转多少钱给谁。这在银行场景既不合理也不合规 ——
  //   客户有权在授权前看清授权内容。
  const presentationCard = request.presentation?.card ?? buildConfirmCard(capability, input, ctx);
  const payloadHash = computePayloadHash(capability.name, input);

  const buildConfirmSpec = (): ConfirmSpec => ({
    payloadHash,
    humanReadable: renderCardAsText(presentationCard),
    card: presentationCard,
    ttlMs: getPolicyConfig().confirmTtlMs,
  });

  // 若已持有针对本载荷的有效动作令牌,则视为已验证通过
  if (request.hasValidActionToken) {
    reasons.push({
      ruleId: "R-ACTION-TOKEN-VALID",
      message: "已持有针对本载荷的有效强验证令牌,放行执行",
      effect: "pass",
    });
    return {
      effect: "require_confirm",
      tier: "confirm",
      reasons,
      confirmSpec: buildConfirmSpec(),
    };
  }

  // 依据渠道能力决定可用的验证方式
  const caps = ctx.channelCapabilities;
  const methods: AuthSpec["methods"] = [];
  const required: AuthSpec["required"] = [];

  if (caps.biometric) {
    methods.push("biometric");
    required.push("biometric");
  }
  if (caps.interactive) methods.push("sms_otp");
  if (caps.risk === "low") methods.push("trusted_device", "password", "usb_key");
  if (methods.length === 0) methods.push("sms_otp");

  // 至少要求一种;若首选不可用则回退短信
  if (required.length === 0) required.push(methods.includes("sms_otp") ? "sms_otp" : methods[0]!);

  const authSpec: AuthSpec = {
    methods,
    required,
    ttlMs: getPolicyConfig().actionTokenTtlMs,
    // ★ 把被授权的操作详情挂到 AuthSpec 上,让渠道层能够
    //   "一边展示待授权内容、一边引导完成验证"
    subject: presentationCard,
  };

  // 高风险渠道:必须回到安全渠道完成强验证
  if (caps.risk === "high") {
    authSpec.fallbackGuidance = {
      deepLink: caps.deepLink ? "bankapp://security/confirm" : undefined,
      message:
        "这笔操作需要更强的身份验证。请点击链接回到手机银行 App 完成人脸识别后,自动回到本次对话继续。",
    };
  }

  return { effect: "require_strong_auth", tier: "strong_auth", reasons, authSpec };
}

// ============================================================================
// 人话确认卡(I3 之外的体验设计:不 dump JSON,逐项展示关键字段)
// ============================================================================

/**
 * 生成面向用户的确认卡。
 *
 * 按能力类型分支 —— 转账、定时转账、AA 收款各自需要展示不同的关键字段。
 * 原则:**凡影响用户决策的字段一律展示,不折叠、不省略**。
 */
export function buildConfirmCard(
  capability: CapabilitySpec,
  input: Record<string, unknown>,
  _ctx?: ExecutionContext,
): ConfirmCard {
  switch (capability.name) {
    case "transfer.create_schedule":
      return buildScheduleCard(input);
    case "collection.create":
      return buildCollectionCard(input);
    case "transfer.cancel":
    case "transfer.cancel_schedule":
      return buildCancelCard(capability, input);
    case "collection.remind":
      return buildCollectionRemindCard(input);
    // ---- 理财场景(场景三)----
    case "wealth.purchase":
      return buildWealthPurchaseCard(input);
    case "wealth.redeem":
      return buildWealthRedeemCard(input);
    // ---- 卡片管理(场景四)----
    case "card.limit_adjust":
      return buildCardLimitCard(input);
    case "card.report_loss":
      return buildCardLossCard(input);
    case "card.replace":
      return buildCardReplaceCard(input);
    case "card.activate":
      return buildCardActivateCard(input);
    case "card.new_application":
      return buildCardApplicationCard(input);
    case "card.unblock":
      return buildCardUnblockCard(input);
    // ---- 订阅代扣(新场景)----
    case "subscription.cancel":
      return buildSubscriptionCancelCard(input);
    // ---- 跨场景事件联动(新场景)----
    case "event.fund_step":
      return buildEventFundStepCard(input);
    case "event.external_step":
      return buildEventExternalStepCard(input);
    default:
      return buildTransferCard(capability, input);
  }
}

/**
 * 额度调整确认卡。
 *
 * ★ 这张卡的存在意义只有一条:**让"申请"这个词在界面上无法被含糊掉**。
 *   卡上必须同时出现三个数,缺一不可:
 *     当前额度 → 申请额度(目标) → 以及一句"审核通过后才会生效"。
 *   只展示目标额度,就是一张会误导人的卡 —— 客户会以为已经提好了。
 *
 *   同时必须写明审核时效("约 N 个工作日出结果"),因为"什么时候能好"
 *   是这类申请最集中的追问;不写清楚,客户会在第三天来问"你说帮我提的额度呢"。
 */
function buildCardLimitCard(input: Record<string, unknown>): ConfirmCard {
  const current = typeof input["__cardCurrentLimit"] === "number" ? (input["__cardCurrentLimit"] as number) : null;
  const requested = typeof input["requestedLimit"] === "number" ? (input["requestedLimit"] as number) : null;
  const last4 = String(input["__cardLast4"] ?? input["cardId"] ?? "—");
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "卡片", value: `${String(input["__cardProductName"] ?? "信用卡")} 尾号 ${last4}`, emphasis: true });
  if (current != null) fields.push({ label: "当前额度", value: `¥${formatAmount(current)}` });
  if (requested != null) fields.push({ label: "申请额度", value: `¥${formatAmount(requested)}`, emphasis: true });
  if (current != null && requested != null && requested > current) {
    fields.push({ label: "申请幅度", value: `+¥${formatAmount(requested - current)}` });
  }
  if (input["purpose"]) fields.push({ label: "用途说明", value: String(input["purpose"]) });
  fields.push({ label: "★ 生效方式", value: "提交后进入银行审核,审核通过才生效(不是即时到账)", emphasis: true });
  if (input["__estimatedDecisionAt"] != null) {
    fields.push({ label: "预计出结果", value: formatDateTime(Number(input["__estimatedDecisionAt"])) });
  }
  fields.push({ label: "申请后的额度", value: current != null ? `仍为 ¥${formatAmount(current)}(审核通过前不变)` : "以审核结果为准" });

  return {
    title: "请确认额度调整申请",
    fields,
    warning:
      "★ 提交的是**申请**,不是额度调整本身。审核通过后额度才会变化,也可能只批一部分、或者不批;" +
      "结果会通知您。在此期间请勿依赖尚未批准的额度消费。",
    reversibility: "审核出结果前可申请撤回",
  };
}

/**
 * 挂失(冻结)确认卡。
 *
 * ★ 这张卡只做一个决定:立刻冻结。
 *   卡上刻意**不放**补卡选项 —— 因为"先冻结、再聊补办"不是一个交互偏好,
 *   而是一条安全纪律:冻结是止损,补卡是善后,两者的时间压力相差几个数量级。
 *   把两个决定挤在一张卡上,客户会开始纠结"到底换号还是保号",
 *   而这几分钟的犹豫,卡可能已经被刷了。
 */
function buildCardLossCard(input: Record<string, unknown>): ConfirmCard {
  const last4 = String(input["__cardLast4"] ?? "—");
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "卡片", value: `${String(input["__cardProductName"] ?? "卡片")} 尾号 ${last4}`, emphasis: true });
  fields.push({ label: "要执行的动作", value: "立即挂失并冻结该卡(禁止一切交易)", emphasis: true });
  fields.push({ label: "生效时间", value: "立即生效,无需等待" });
  if (input["scenario"]) fields.push({ label: "您的说明", value: String(input["scenario"]) });
  if (input["__cardCreditLimit"] != null) {
    fields.push({ label: "冻结时的已用额度", value: `¥${formatAmount(Number(input["__cardCreditLimit"]))}` });
  }
  fields.push({ label: "对已绑定业务的影响", value: "自动扣款、快捷支付会失败;订阅类扣款需换卡后重新绑定" });

  return {
    title: "★ 请确认挂失并冻结这张卡",
    fields,
    warning:
      "挂失后该卡立即无法交易,这是防止被盗刷最有效的动作。" +
      "如果卡还在您手上、只是暂时找不到,挂失同样可以用 —— 之后找到卡也可以申请解除挂失。",
    reversibility: "冻结后可通过客服或 App 申请解除挂失(需身份验证)",
  };
}

/**
 * 补卡确认卡。
 *
 * ★ 需求里点得最明确的一处差异必须落在这张卡上:
 *   **换号还是保留原号,以及保留原号要等更久** —— 而且必须在操作**前**告知。
 *   所以卡上把两个方案的到手时间、是否变号、是否要重设密码、是否要重绑
 *   四项并列写出来,让客户在"点确认"之前就看清楚自己在选什么。
 */
function buildCardReplaceCard(input: Record<string, unknown>): ConfirmCard {
  const last4 = String(input["__cardLast4"] ?? "—");
  const mode = String(input["mode"] ?? "new_number");
  const keep = mode === "keep_number";
  const fields: ConfirmCard["fields"] = [];

  // ★ 到手天数优先用调用方给的值;缺失时退回卡片引擎的行业常量 ——
  //   绝不让"等待时间"这一栏在卡上显示成空值:它是客户选择哪种方式的**主要依据**。
  const estimatedDays =
    typeof input["__estimatedDays"] === "number"
      ? (input["__estimatedDays"] as number)
      : keep
        ? REPLACEMENT_ETA_DAYS.keepNumber
        : REPLACEMENT_ETA_DAYS.newNumber;

  fields.push({ label: "原卡", value: `${String(input["__cardProductName"] ?? "卡片")} 尾号 ${last4}`, emphasis: true });
  fields.push({ label: "补卡方式", value: keep ? "保留原号补卡" : "换号补卡(新卡号)", emphasis: true });
  fields.push({ label: "★ 预计到手", value: `约 ${estimatedDays} 个工作日`, emphasis: true });
  if (keep) {
    fields.push({ label: "卡号", value: `不变(仍是尾号 ${last4})` });
    fields.push({ label: "已绑定业务", value: "无需重新绑定" });
    fields.push({ label: "交易密码", value: "沿用原密码" });
    fields.push({
      label: "★ 代价",
      value: `等待时间比换号补卡长约 ${REPLACEMENT_ETA_DAYS.keepNumber - REPLACEMENT_ETA_DAYS.newNumber} 个工作日(需重新制卡并做卡号迁移)`,
      emphasis: true,
    });
  } else {
    fields.push({
      label: "卡号",
      value: input["__newCardLast4"] ? `会变(新卡尾号 ${String(input["__newCardLast4"])})` : "会变(新卡号由银行制卡时下发)",
    });
    fields.push({ label: "已绑定业务", value: "快捷支付 / 代扣 / 订阅需重新绑定", emphasis: true });
    fields.push({ label: "交易密码", value: "需重新设置", emphasis: true });
  }
  fields.push({ label: "到手后必做", value: "激活(所有补卡都需要激活后才能使用)", emphasis: true });
  if (input["__cardKindHint"] === "debit") {
    fields.push({ label: "说明", value: "借记卡补卡后,原卡余额会自动转移到新卡" });
  }

  return {
    title: "请确认补卡方式",
    fields,
    warning: keep
      ? `★ 保留原号需要更长时间(约 ${REPLACEMENT_ETA_DAYS.keepNumber} 个工作日)。如果您急用钱,换号补卡会快很多 —— 代价是要重新绑定已绑的支付业务。`
      : "★ 换号补卡会换新卡号,原来绑定的快捷支付、自动扣款与会员订阅都需要重新绑定,交易密码也要重新设置。",
    reversibility: "补卡下单后、制卡完成前可联系客服取消",
  };
}

/** 激活确认卡 —— 必须写清"要不要设交易密码",这是三条行业差异的落点 */
function buildCardActivateCard(input: Record<string, unknown>): ConfirmCard {
  const last4 = String(input["__cardLast4"] ?? "—");
  const needsPassword = input["setTransactionPassword"] === true;
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "卡片", value: `${String(input["__cardProductName"] ?? "新卡")} 尾号 ${last4}`, emphasis: true });
  fields.push({ label: "要执行的动作", value: "激活这张卡", emphasis: true });
  fields.push({
    label: "交易密码",
    value: needsPassword ? "本次一并设置交易密码" : "沿用原交易密码,无需重设",
    emphasis: true,
  });
  if (input["__activationScenario"]) {
    fields.push({ label: "换卡情形", value: String(input["__activationScenario"]) });
  }

  return {
    title: "请确认激活新卡",
    fields,
    warning: needsPassword
      ? "★ 激活后还需要设置交易密码,新卡才能真正用于交易。"
      : "★ 激活后即可使用,交易密码沿用原密码。",
    reversibility: "激活为一次性动作,不可撤销",
  };
}

/** 新卡申请确认卡 —— 必须提前告知"批了之后还要激活、还要设密码" */
function buildCardApplicationCard(input: Record<string, unknown>): ConfirmCard {
  const kind = String(input["kind"] ?? "credit");
  const kindLabel = kind === "credit" ? "信用卡" : kind === "debit" ? "借记卡" : "虚拟卡";
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "申请卡种", value: kindLabel, emphasis: true });
  if (input["requestedLimit"] != null) {
    fields.push({ label: "期望额度", value: `¥${formatAmount(Number(input["requestedLimit"]))}(以银行审批为准)` });
  }
  if (input["purpose"]) fields.push({ label: "用途说明", value: String(input["purpose"]) });
  fields.push({ label: "★ 生效方式", value: "提交后进入银行审批,结果另行通知", emphasis: true });
  fields.push({
    label: "★ 新卡到手后",
    value: "必须先激活;新开户/新办卡还需要设置交易密码,否则无法交易",
    emphasis: true,
  });

  return {
    title: "请确认新卡申请",
    fields,
    warning:
      "提交的是**申请**,银行会做资信审核,不保证一定通过;批卡额度也由银行决定。" +
      "新卡到手后必须激活并设置交易密码才能使用。",
    reversibility: "审批结果出来前可撤回申请",
  };
}

/** 解除限制申请确认卡 —— 必须写清"谁说了算" */
function buildCardUnblockCard(input: Record<string, unknown>): ConfirmCard {
  const last4 = String(input["__cardLast4"] ?? "—");
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "卡片", value: `${String(input["__cardProductName"] ?? "卡片")} 尾号 ${last4}`, emphasis: true });
  if (input["__cardRestrictionCauseLabel"]) {
    fields.push({ label: "限制原因", value: String(input["__cardRestrictionCauseLabel"]), emphasis: true });
  }
  fields.push({ label: "要提交的申请", value: "解除卡片交易限制(转银行审核)", emphasis: true });
  if (input["statement"]) fields.push({ label: "您的说明", value: String(input["statement"]) });
  if (input["__restrictionSince"] != null) {
    fields.push({ label: "限制开始时间", value: formatDateTime(Number(input["__restrictionSince"])) });
  }

  return {
    title: "请确认提交解除限制申请",
    fields,
    warning:
      "★ 提交的是**申请**:是否解除由银行审核决定,审核期间限制仍然生效。" +
      "我无法承诺一定能解除。",
    reversibility: "审核出结果前可撤回",
  };
}

/**
 * 取消订阅代扣确认卡。
 *
 * ★ 这张卡要解决的问题只有一个:**客户说的"关了它",和他以为的"钱会退回来"
 *   往往不是一回事。**
 *   所以卡上必须同时出现四类信息,缺一不可:
 *
 *     ① 取消的是哪一笔(商户 + 协议号)—— 客户可能在同一个平台上签过多笔;
 *     ② 每期扣多少、**下一次什么时候扣** —— 这两条是"要不要现在办"的依据;
 *     ③ 生效口径:下一期起不再扣款(**不是退款**)—— 这句是防误解的核心;
 *     ④ 本期已扣的钱怎么办 + 取消之后会失去什么 —— 取消的代价必须自己认。
 *
 * ★ 另一条纪律:**卡上不出现"确认即退款"之类的字样**。
 *   退款是另一件事(有的协议给退、有的不给),能力返回值里只有 refundPolicy
 *   这一种可讲的口径,卡片照抄它,不许自行加工成"钱会退给你"。
 */
function buildSubscriptionCancelCard(input: Record<string, unknown>): ConfirmCard {
  const merchant = String(input["__subMerchant"] ?? input["merchantName"] ?? "该订阅");
  const amount = typeof input["__subAmount"] === "number" ? (input["__subAmount"] as number) : null;
  const nextDebitAt = typeof input["__subNextDebitAt"] === "number" ? (input["__subNextDebitAt"] as number) : null;
  const effective = input["__subCancelEffective"] === "immediate" ? "立即生效" : "下一期起不再扣款";
  const fields: ConfirmCard["fields"] = [];

  fields.push({ label: "要取消的订阅", value: `${merchant}${input["__subCategory"] ? `(${String(input["__subCategory"])})` : ""}`, emphasis: true });
  if (input["__subAgreementNo"]) fields.push({ label: "代扣协议号", value: String(input["__subAgreementNo"]) });
  fields.push({
    label: "每期扣费",
    value: amount != null ? `¥${formatAmount(amount)}(${String(input["__subCadenceLabel"] ?? "每期")})` : "—",
    emphasis: true,
  });
  fields.push({
    label: "下一次扣款",
    value:
      nextDebitAt != null
        ? formatDateTime(nextDebitAt)
        : "无(该协议当前没有待扣款计划)",
    emphasis: true,
  });
  fields.push({ label: "★ 取消方式", value: "解除这份代扣协议", emphasis: true });
  fields.push({ label: "★ 生效口径", value: `${effective}(解除的是后续扣款,不是已扣费用的退还)`, emphasis: true });
  fields.push({ label: "★ 本期已扣费用", value: String(input["__subRefundPolicy"] ?? "以协议为准"), emphasis: true });
  fields.push({ label: "★ 取消的后果", value: String(input["__subCancelConsequence"] ?? "以协议为准") });
  if (input["__subSignedAt"] != null) {
    fields.push({ label: "签约时间", value: formatDateTime(Number(input["__subSignedAt"])) });
  }

  return {
    title: "请确认取消这笔订阅代扣",
    fields,
    warning:
      "★ 取消后**下一期起不再扣款**;本期已经扣掉的费用按上面的口径处理(多数订阅类协议不予退还," +
      "因为权益已经生效使用)。如果您要的是「把钱退回来」,那是另一件事 —— 请告诉我,我帮您查该笔扣款能不能申请退款。",
    reversibility: "取消后如需恢复,需要重新签约(部分商户的优惠价可能无法恢复)",
  };
}

/**
 * 事件联动 —— 资金操作步骤确认卡(黄色)。
 *
 * ★ 这张卡要同时解决三个问题,缺一个都会让"确认"变成走过场:
 *   ① **这是哪一份方案里的哪一步** —— 客户可能同时有两件事在推进
 *      (纪念日 + 发薪转存),卡上不写清是哪一件、哪一步,客户点确认时
 *      心里想的是另一件;
 *   ② **钱从哪出、给谁、多少、什么时候** —— 这四项是合规要求的那句话;
 *   ③ **它不做什么** —— 不对外支付、不下单、不动方案里其它步骤。
 *      第 ③ 项是这张卡的灵魂:客户最怕的正是"我就点了一下,你怎么把钱都办了"。
 *
 * ★ 卡上刻意**没有**"是否同时执行外部订购"这类勾选项:
 *   两类操作分开确认不是交互偏好,而是纪律 —— 一旦给了一个"一起办"的开关,
 *   它迟早会被当作默认值。
 */
function buildEventFundStepCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const amount = typeof input["__evStepAmount"] === "number" ? (input["__evStepAmount"] as number) : null;
  const scheduledAt = typeof input["scheduledAt"] === "number" ? Number(input["scheduledAt"]) : null;
  const mode = input["mode"] === "schedule" ? "schedule" : input["mode"] === "release" ? "release" : "reserve";
  const fromLabel = String(input["__evFromAccountLabel"] ?? "待指定出账账户");

  fields.push({ label: "所属事件", value: String(input["eventTitle"] ?? "跨场景事件联动"), emphasis: true });
  fields.push({ label: "这一步", value: `${String(input["stepTitle"] ?? input["toName"] ?? "资金操作")}(${String(input["stepId"] ?? "—")})`, emphasis: true });
  fields.push({
    label: "★ 资金金额",
    value: amount != null ? `¥${formatAmount(amount)}` : "—",
    emphasis: true,
  });
  fields.push({ label: "★ 资金去向", value: String(input["toName"] ?? "—"), emphasis: true });
  fields.push({ label: "★ 出账账户", value: fromLabel, emphasis: true });
  if (mode !== "release") {
    fields.push({
      label: mode === "reserve" ? "★ 锁定到期时间" : "★ 定时执行时间",
      value: scheduledAt != null ? formatDateTime(scheduledAt) : "—",
      emphasis: true,
    });
  }
  /**
   * ★ 三种方式的说法必须**分开写**,不能共用一句「预留」:
   *   客户说「取消刚才那个预留」时,如果卡上还写着"在本账户内预留这笔资金",
   *   他点确认的时候其实不知道自己点的是"解开" —— 一张说反了的确认卡,
   *   比没有卡更糟:它会让客户以为自己在锁钱,结果钱被放回了可用余额。
   */
  fields.push({
    label: "① 操作方式",
    value:
      mode === "reserve"
        ? "在本账户内**预留**这笔资金(锁定)"
        : mode === "schedule"
          ? "登记一个到点执行的**定时任务**"
          : "**解开**此前预留的这笔资金(钱回到可用余额)",
  });
  fields.push({
    label: "② 是否对外支付",
    value: mode === "release" ? "否 —— 只是解除本账户内的预留标记,没有任何对外支付" : "否 —— 钱不出本账户体系,不产生任何商户订单",
  });
  fields.push({ label: "③ 是否影响其它步骤", value: "否 —— 方案里其它步骤(含外部订购)一步都不会执行" });
  fields.push({
    label: "④ 可否解除",
    value:
      mode === "release"
        ? "解开后如需再锁回去,重新说一句即可(会再走一次同样的确认)"
        : "可以 —— 预留可随时解开,定时任务可随时取消",
  });
  if (input["planId"]) fields.push({ label: "方案号", value: String(input["planId"]) });

  return {
    title: mode === "release" ? "请确认这一步:解除预留" : "请确认这一步:资金操作",
    fields,
    warning:
      mode === "release"
        ? "★ 这一步只是**解除本账户内这笔资金的预留标记**:钱本来就一直在您名下," +
          "解开后它会重新计入可用余额 —— 不涉及任何对外支付,也不会触发方案里的任何外部订购。"
        : "★ 这一步只在您自己的账户内**预留**资金:钱仍在您名下,只是被标记为这笔用途专用。" +
          "它**不会**产生对外支付,也**不会**触发方案里的任何外部订购 —— 那一步要另行确认。",
    reversibility:
      mode === "release" ? "解除后想再锁回去,重新说一句即可(会再走一次确认)" : "随时可解开预留或取消定时任务(无需商户同意)",
  };
}

/**
 * 事件联动 —— 外部服务操作步骤确认卡(红色)。
 *
 * ★ 与资金操作那张卡的关键差别必须写在这张卡上,而且要用客户能懂的话:
 *   钱**会离开银行体系**。转账可以撤销、理财可以赎回、代扣可以解约、
 *   额度只是申请 —— 唯独外部订单,提交之后要退要改都得跟商户协商。
 *   这正是它必须在最强一档验证、并且必须逐笔说清去向的原因。
 *
 * ★ 卡上必须有**退订政策**:它来自商户目录,是客户判断"要不要现在订"的依据。
 *   不给这项,客户就是在不知道反悔成本的情况下点确认。
 */
function buildEventExternalStepCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const amount = typeof input["__evStepAmount"] === "number" ? (input["__evStepAmount"] as number) : null;
  const scheduledAt = typeof input["scheduledAt"] === "number" ? Number(input["scheduledAt"]) : null;

  fields.push({ label: "所属事件", value: String(input["eventTitle"] ?? "跨场景事件联动"), emphasis: true });
  fields.push({ label: "这一步", value: `${String(input["stepTitle"] ?? input["item"] ?? "外部订购")}(${String(input["stepId"] ?? "—")})`, emphasis: true });
  fields.push({ label: "★ 商户(钱去哪儿)", value: String(input["merchantName"] ?? "—"), emphasis: true });
  fields.push({ label: "★ 订购项目", value: String(input["item"] ?? "—") });
  fields.push({ label: "★ 支付金额", value: amount != null ? `¥${formatAmount(amount)}` : "—", emphasis: true });
  fields.push({ label: "★ 出账账户", value: String(input["__evFromAccountLabel"] ?? "待指定出账账户"), emphasis: true });
  fields.push({
    label: "★ 服务时间",
    value: scheduledAt != null ? formatDateTime(scheduledAt) : "—",
  });
  fields.push({
    label: "★ 退订/改期政策",
    value: String(input["__evMerchantCancelPolicy"] ?? "以商户政策为准"),
    emphasis: true,
  });
  fields.push({ label: "① 这一步的实质", value: "钱**离开银行体系**,由外部商户提供服务(不是转账、也不是理财)" });
  fields.push({ label: "② 提交后能否由银行单方撤回", value: "不能 —— 退订或改期需与商户协商" });
  fields.push({ label: "③ 是否影响其它步骤", value: "否 —— 方案里的资金操作是另一次确认" });
  if (input["planId"]) fields.push({ label: "方案号", value: String(input["planId"]) });

  return {
    title: "★ 请确认这一步:外部服务操作(需强验证)",
    fields,
    warning:
      "★ 这是全流程里唯一**钱会离开银行体系**的一步:订单一旦提交,银行无法单方面撤回," +
      "退订或改期都要按商户政策协商(见上方政策)。\n" +
      "★ 上面的金额、商户、出账账户就是这笔钱的全部去向 —— 不会再有别的扣款;" +
      "方案里的资金操作那一步**不会**因这次确认而被执行。",
    reversibility: "需与商户协商退订/改期,银行无法单方撤回",
  };
}

/**
 * 理财申购确认卡。
 *
 * ★ 合规上必须出现在卡上的四件事(缺任何一项,这张卡都不合格):
 *   ① 产品名与**风险等级** —— 用户要知道自己买的是什么风险的东西;
 *   ② 申购金额与费用、确认份额 —— 钱的去向;
 *   ③ **资金状态说明**(冻结而非划走)—— "承诺类"操作的实质;
 *   ④ **风险提示原文** —— 提示必须是申购动作的一部分,不能事后补。
 *   另外,风险等级不匹配时必须在卡上标红并写明确认书编号。
 */
function buildWealthPurchaseCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;
  const riskLevel = String(input["__productRiskLevel"] ?? "—");
  const customerLevel = input["__customerRiskLevel"] ? String(input["__customerRiskLevel"]) : "未测评";
  const ordinal = typeof input["__productRiskOrdinal"] === "number" ? (input["__productRiskOrdinal"] as number) : 0;
  const customerOrdinal = typeof input["__customerRiskOrdinal"] === "number" ? (input["__customerRiskOrdinal"] as number) : 0;
  const mismatch = ordinal > customerOrdinal;
  const consentRef = input["__consentRef"] ? String(input["__consentRef"]) : null;

  fields.push({ label: "产品名称", value: String(input["__productName"] ?? input["productName"] ?? "—"), emphasis: true });
  if (input["__productCode"]) fields.push({ label: "产品代码", value: String(input["__productCode"]) });
  fields.push({
    label: "风险等级",
    value: `${riskLevel} ${PRODUCT_RISK_LABELS[riskLevel as keyof typeof PRODUCT_RISK_LABELS] ?? ""}`,
    emphasis: true,
  });
  fields.push({
    label: "您的等级",
    value: customerLevel === "未测评" ? "未测评" : `${customerLevel} ${RISK_LEVEL_LABELS[customerLevel as keyof typeof RISK_LEVEL_LABELS] ?? ""}`,
  });
  if (mismatch && consentRef) {
    fields.push({ label: "★ 风险不匹配确认书", value: `已签署 ${consentRef}`, emphasis: true });
  }
  fields.push({ label: "申购金额", value: `¥${formatAmount(amount)}`, emphasis: true });
  if (input["__settlement"]) fields.push({ label: "赎回到账时效", value: String(input["__settlement"]) });
  if (input["fromAccountId"]) {
    fields.push({ label: "扣款账户", value: maskAccount(String(input["fromAccountId"])) });
  }
  fields.push({ label: "资金状态", value: "提交后立即冻结,份额 T+1 确认(冻结期间不可动用)" });

  return {
    title: "请确认理财申购信息",
    fields,
    warning: mismatch
      ? `★ 该产品风险等级 ${riskLevel} 高于您的风险承受能力(${customerLevel})。` +
        "您已签署《风险不匹配确认书》,请再次确认您了解可能的本金损失。" +
        "理财非存款,产品有风险,投资须谨慎。"
      : "理财非存款,产品有风险,投资须谨慎。本产品不保本、不保收益,历史业绩不代表未来表现,可能产生本金损失。",
    reversibility: "份额确认前可申请撤单;确认后需按产品规则赎回",
  };
}

/**
 * 理财赎回确认卡。
 *
 * ★ 卡上必须写清两件最容易引发客诉的事:
 *   ① **到账时间**(T+0/T+1/T+2)—— "我的钱什么时候能用";
 *   ② **兑现的收益可能为负** —— 赎回是把浮亏变成实亏的动作,不能只报喜。
 */
function buildWealthRedeemCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  fields.push({ label: "产品名称", value: String(input["__productName"] ?? input["productName"] ?? "—"), emphasis: true });
  if (input["shares"] != null) {
    fields.push({ label: "赎回份额", value: Number(input["shares"]).toLocaleString("zh-CN"), emphasis: true });
  }
  if (input["redeemAll"] === true) fields.push({ label: "赎回方式", value: "全部赎回", emphasis: true });
  if (input["amount"] != null) fields.push({ label: "赎回金额", value: `¥${formatAmount(Number(input["amount"]))}`, emphasis: true });
  if (input["__estimatedAmount"] != null) {
    fields.push({ label: "预计到账金额", value: `¥${formatAmount(Number(input["__estimatedAmount"]))}` });
  }
  if (input["__realizedProfit"] != null) {
    const p = Number(input["__realizedProfit"]);
    fields.push({
      label: p >= 0 ? "本次兑现收益" : "本次兑现亏损",
      value: `${p >= 0 ? "+" : ""}${fmtMoney(p)} 元`,
      emphasis: p < 0,
    });
  }
  fields.push({
    label: "★ 到账时间",
    value: String(input["__settlementText"] ?? input["__settlement"] ?? "以产品约定为准"),
    emphasis: true,
  });

  return {
    title: "请确认理财赎回信息",
    fields,
    warning:
      "赎回提交后份额会立即扣减,您不再享有这部分份额的后续收益;" +
      "资金按产品约定的 T+N 时效到账,到账前不计收益。",
    reversibility: "赎回申请在确认前可撤销;确认后不可撤回",
  };
}

/** 转账确认卡(不再接收 ctx:这张卡的内容全部来自冻结的载荷,与上下文无关) */
function buildTransferCard(
  capability: CapabilitySpec,
  input: Record<string, unknown>,
): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const currency = (input["currency"] as string | undefined) ?? "CNY";
  const symbol = currency === "CNY" ? "¥" : currency + " ";

  fields.push({ label: "收款人", value: String(input["payeeName"] ?? "—"), emphasis: true });
  if (input["bankName"]) fields.push({ label: "收款银行", value: String(input["bankName"]) });
  if (input["maskedAccountNo"]) fields.push({ label: "收款账号", value: String(input["maskedAccountNo"]) });
  if (input["phone"]) fields.push({ label: "手机号", value: maskPhone(String(input["phone"])) });

  const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : null;
  if (amount != null) {
    fields.push({ label: "转账金额", value: `${symbol}${formatAmount(amount)}`, emphasis: true });
  }
  const fee = typeof input["__fee"] === "number" ? (input["__fee"] as number) : 0;
  fields.push({ label: "手续费", value: fee === 0 ? "免手续费" : `${symbol}${formatAmount(fee)}` });
  if (input["fromAccountId"]) {
    fields.push({ label: "付款账户", value: maskAccount(String(input["fromAccountId"])) });
  }
  if (input["memo"]) fields.push({ label: "备注", value: String(input["memo"]) });
  if (input["__estimatedArrival"]) {
    fields.push({ label: "预计到账", value: String(input["__estimatedArrival"]) });
  }
  if (input["scheduledAt"]) {
    fields.push({ label: "计划执行时间", value: formatDateTime(Number(input["scheduledAt"])) });
  }

  return {
    title: "请确认转账信息",
    fields,
    ...buildWarnings(capability, input),
  };
}

/** 定时转账确认卡 —— 必须展示周期、首次执行时间、执行前提醒与余额不足策略 */
function buildScheduleCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : 0;

  fields.push({ label: "收款人", value: String(input["payeeName"] ?? "—"), emphasis: true });
  if (input["bankName"]) fields.push({ label: "收款银行", value: String(input["bankName"]) });
  if (input["maskedAccountNo"]) fields.push({ label: "收款账号", value: String(input["maskedAccountNo"]) });
  fields.push({ label: "每期金额", value: `¥${formatAmount(amount)}`, emphasis: true });
  fields.push({ label: "执行周期", value: recurrenceLabel(input) });
  if (input["firstRunAt"]) {
    fields.push({ label: "首次执行", value: formatDateTime(Number(input["firstRunAt"])), emphasis: true });
  }
  if (input["fromAccountId"]) {
    fields.push({ label: "付款账户", value: maskAccount(String(input["fromAccountId"])) });
  }
  if (input["memo"]) fields.push({ label: "备注", value: String(input["memo"]) });
  fields.push({
    label: "余额不足时",
    value: insufficientFundsLabel(String(input["onInsufficientFunds"] ?? "notify_and_skip")),
  });
  fields.push({
    label: "执行前提醒",
    value: input["preExecutionReminder"] === false ? "已关闭" : "已开启(执行前会提前通知您)",
  });

  return {
    title: "请确认定时转账设置",
    fields,
    warning:
      "这是周期扣款计划,将按上述周期自动执行。您可以随时说「取消定时转账」停止它。" +
      (input["preExecutionReminder"] === false ? "当前已关闭执行前提醒,建议开启。" : ""),
    reversibility: "随时可取消,取消前的每一期都会按计划执行",
  };
}

/** AA 收款确认卡 —— 必须展示总额、参与人、各自分摊额与分摊方式 */
function buildCollectionCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  const total = typeof input["totalAmount"] === "number" ? (input["totalAmount"] as number) : 0;

  fields.push({ label: "收款事由", value: String(input["title"] ?? "分摊收款"), emphasis: true });
  fields.push({ label: "总金额", value: `¥${formatAmount(total)}`, emphasis: true });
  fields.push({ label: "分摊方式", value: splitModeLabel(String(input["splitMode"] ?? "equal")) });

  const participants = (input["participants"] as Array<{ displayName: string; amount?: number; shares?: number }> | undefined) ?? [];
  if (participants.length > 0) {
    fields.push({ label: "参与人数", value: `${participants.length} 人` });

    // 逐人展示分摊额 —— 这是最容易出错也最需要用户核对的部分
    if (String(input["splitMode"] ?? "equal") === "equal" && total > 0 && participants.length > 0) {
      const each = Math.floor((total / participants.length) * 100) / 100;
      const detail = participants.map((p) => p.displayName).join("、");
      fields.push({ label: "人均", value: `¥${formatAmount(each)} × ${participants.length} 人` });
      fields.push({ label: "参与人", value: detail });
    } else {
      const detail = participants
        .map((p) =>
          String(input["splitMode"]) === "shares"
            ? `${p.displayName}(${p.shares ?? 1} 份)`
            : `${p.displayName} ¥${formatAmount(p.amount ?? 0)}`,
        )
        .join(";");
      fields.push({ label: "分摊明细", value: detail });
    }
  }

  fields.push({
    label: "手续费承担",
    value: input["feeBearer"] === "initiator" ? "由您承担" : "各自承担",
  });
  fields.push({ label: "部分支付", value: input["allowPartial"] === true ? "允许" : "不允许" });

  return {
    title: "请确认发起 AA 收款",
    fields,
    warning: "确认后将向每位参与人发送收款请求。他们各自只会看到自己的分摊金额。",
    reversibility: "可随时撤销收款请求",
  };
}

/** 撤销类确认卡 */
function buildCancelCard(capability: CapabilitySpec, input: Record<string, unknown>): ConfirmCard {
  const isSchedule = capability.name === "transfer.cancel_schedule";

  // ★ 确认卡的价值在于"让用户核对"，而不是复述一个内部编号。
  //   早期版本只显示 scheduleId / transferId（如 sched_ab12cd），
  //   用户根本不知道自己取消的是哪一个计划、撤的是哪一笔钱 ——
  //   这正是"确认信息不完整"的典型表现。
  //   现在按"取消计划"与"撤销已转出的钱"分别展示用户真正关心的字段。
  if (isSchedule) {
    const fields: ConfirmCard["fields"] = [];
    if (input["__schedulePayee"]) {
      fields.push({ label: "收款人", value: String(input["__schedulePayee"]), emphasis: true });
    }
    if (typeof input["__scheduleAmount"] === "number") {
      fields.push({
        label: "每期金额",
        value: `¥${formatAmount(input["__scheduleAmount"] as number)}`,
        emphasis: true,
      });
    }
    if (input["__scheduleFrequency"]) {
      fields.push({ label: "转账频率", value: String(input["__scheduleFrequency"]) });
    }
    if (typeof input["__scheduleNextRunAt"] === "number") {
      fields.push({ label: "原定下次执行", value: formatDateTime(input["__scheduleNextRunAt"] as number) });
    }
    // 编号放在最后：它是给客服对账用的，不是给用户核对用的
    fields.push({ label: "任务编号", value: String(input["scheduleId"] ?? "—") });
    if (input["reason"]) fields.push({ label: "原因", value: String(input["reason"]) });

    return {
      title: "请确认取消这个定时转账",
      fields,
      warning: "取消后该计划将不再执行，已完成的期数不受影响。之后如需继续，需要重新创建。",
      reversibility: "取消后可随时重新创建",
    };
  }

  // 撤销一笔已经转出去的钱：必须让用户看清"撤的是哪一笔"
  const fields: ConfirmCard["fields"] = [];
  if (input["__transferPayee"]) {
    fields.push({ label: "原收款人", value: String(input["__transferPayee"]), emphasis: true });
  }
  if (typeof input["__transferAmount"] === "number") {
    fields.push({
      label: "原转账金额",
      value: `¥${formatAmount(input["__transferAmount"] as number)}`,
      emphasis: true,
    });
  }
  if (typeof input["__transferTs"] === "number") {
    fields.push({ label: "转账时间", value: formatDateTime(input["__transferTs"] as number) });
  }
  if (input["__transferMemo"]) {
    fields.push({ label: "原备注", value: String(input["__transferMemo"]) });
  }
  // ★ 显示客户刚才在转账回执上看到的那个流水号(REF…),而不是内部 TXN/TRF 编号:
  //   卡片的全部意义是让客户核对"撤的是不是那一笔",内部编号他无从对照。
  fields.push({
    label: "转账流水号",
    value: String(input["__transferReference"] ?? input["transferId"] ?? "—"),
  });
  if (input["reason"]) fields.push({ label: "原因", value: String(input["reason"]) });

  return {
    title: "请确认撤销这笔转账",
    fields,
    warning: "撤销后款项将退回您的付款账户。若对方已入账，撤销可能失败。",
    reversibility: "退款实时到账",
  };
}

/** AA 催收确认卡 —— 必须说清"提醒谁、各欠多少" */
function buildCollectionRemindCard(input: Record<string, unknown>): ConfirmCard {
  const fields: ConfirmCard["fields"] = [];
  fields.push({ label: "AA 账单", value: String(input["__collectionTitle"] ?? "—"), emphasis: true });
  const names = input["__remindNames"];
  if (typeof names === "string" && names.length > 0) {
    fields.push({ label: "将提醒", value: names });
  }
  if (typeof input["__remindCount"] === "number") {
    fields.push({ label: "未付款人数", value: `${input["__remindCount"]} 人` });
  }
  if (typeof input["__remindOutstanding"] === "number") {
    fields.push({ label: "待收合计", value: `¥${formatAmount(input["__remindOutstanding"] as number)}` });
  }
  return {
    title: "请确认发送付款提醒",
    fields,
    warning: "提醒会发送给上述参与人。这不会改动任何资金,只是通知他们尽快付款。",
    reversibility: "提醒发出后无法撤回",
  };
}

function buildWarnings(
  capability: CapabilitySpec,
  input: Record<string, unknown>,
): { warning?: string; reversibility?: string } {
  const warnings: string[] = [];
  if (capability.sideEffect === "irreversible") {
    warnings.push("此操作一经执行不可撤销,请务必核对收款人信息。");
  }
  const novelty = readPayeeNovelty(input);
  if (novelty.isFirstTime && !novelty.isSelfOwned) {
    warnings.push("这是您首次向该收款人转账,请确认对方身份无误。");
  }
  const config = getPolicyConfig();
  return {
    ...(warnings.length > 0 ? { warning: warnings.join(" ") } : {}),
    ...(capability.moneyMovement
      ? { reversibility: `发起后 ${Math.round(config.cancellableWindowMs / 60000)} 分钟内、对方尚未入账前可撤销` }
      : {}),
  };
}

function recurrenceLabel(input: Record<string, unknown>): string {
  const f = String(input["frequency"] ?? "once");
  const interval = Number(input["interval"] ?? 1);
  const base = { once: "仅一次", daily: "每天", weekly: "每周", monthly: "每月" }[f] ?? f;
  return interval > 1 ? `${base}(每 ${interval} 期)` : base;
}

function insufficientFundsLabel(v: string): string {
  return (
    {
      notify_and_skip: "通知我并跳过本期",
      retry_next_day: "次日重试",
      partial: "按可用余额部分扣款",
    }[v] ?? v
  );
}

function splitModeLabel(v: string): string {
  return { equal: "均摊", custom: "自定义金额", shares: "按份数" }[v] ?? v;
}

/** 把确认卡渲染为纯文本(IM 等不支持富卡片的渠道自动降级) */
export function renderCardAsText(card: ConfirmCard): string {
  const lines: string[] = [card.title, "─────────────"];
  for (const f of card.fields) {
    lines.push(`${f.label}:${f.value}`);
  }
  lines.push("─────────────");
  if (card.reversibility) lines.push(`撤销说明:${card.reversibility}`);
  if (card.warning) lines.push(`请注意:${card.warning}`);
  return lines.join("\n");
}

// ============================================================================
// 脱敏工具(供策略引擎与 LLM 上下文构造共用)
// ============================================================================

export function maskAccount(accountNo: string): string {
  const digits = accountNo.replace(/\D/g, "");
  if (digits.length <= 4) return "****";
  return `**** **** **** ${digits.slice(-4)}`;
}

export function maskPhone(phone: string): string {
  const digits = phone.replace(/\D/g, "");
  if (digits.length < 7) return "***";
  return `${digits.slice(0, 3)}****${digits.slice(-4)}`;
}

/** 两位小数金额(口径见 util/format.ts,单一实现) */
export function formatAmount(amount: number): string {
  return fmtMoney(amount);
}

export function formatDateTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
