/**
 * 订阅代扣管理引擎(纯函数,零 LLM)
 *
 * ★ 这个文件回答三个问题,而且只用确定性代码回答:
 *   ① **哪些是订阅代扣**(识别)—— 从客户流水里认,而不是让客户自己回忆;
 *   ② **什么时候还要扣、扣多少**(续费提醒)—— 金额与时间都来自流水与协议;
 *   ③ **这笔能不能在这里取消、取消之后会怎样**(解约资格与后果)。
 *
 * ★ 三条设计纪律(与账单分析、理财、卡片三个场景一脉相承):
 *
 *   1. **认出来 ≠ 可以取消。**
 *      流水能证明"这个月被扣了 19 元",但证明不了"存在一份可以在这里解的协议"。
 *      苹果/谷歌这类应用商店订阅,钱是从商户侧走的,本行没有协议可解 ——
 *      系统必须如实说"这笔我关不了,请去订阅设置里关",而不是收下说"好的已取消"。
 *      过度承诺是本场景最严重的一类错误:客户以为关了,下个月照扣,还会回来投诉。
 *
 *   2. **取消 ≠ 退款。**
 *      绝大多数代扣协议的语义是"下一期不再扣",本期已经扣掉的费用不退(权益已使用)。
 *      把两者混起来,客户会在下个月发现钱照扣,或者以为钱会退回来。
 *      因此 refundPolicy / cancelEffective 是**必填字段**,确认卡上必须出现。
 *
 *   3. **规律性付款不都是订阅。**
 *      房租每月 1 号 5800 元,间隔最规律、金额最固定 —— 但它是客户付给人的合同款,
 *      不是商户代扣,取消它的后果(违约)与取消会员完全不同。
 *      判据必须能把它排除掉,且**说得清为什么排除**(见 excluded 的 reason)。
 *      少认一笔无关紧要,把房租认成"可取消的订阅"会直接伤害客户。
 */

import { fmtMoney as fmtSubMoneyShared, round2 } from "../util/format.ts";
import type { BankSubscription, SubscriptionCadence, Transaction } from "../types.ts";

const DAY_MS = 24 * 3600 * 1000;

// ============================================================================
// 关键词表 —— 识别路径之一("名称像不像一份订阅")
// ============================================================================

/**
 * 订阅/代扣的服务名词。
 *
 * ★ 判据是**服务形态**,不是商户白名单:
 *   写成 ["腾讯视频","爱奇艺","网易云音乐"] 这种名单,三个月就会过期,
 *   而且客户签的下一份协议一定不在名单里(§10 坑 #8:白名单是 bug 温床)。
 *   写成"视频/音乐/云盘/会员/课程"这类**品类词**,新商户天然落在覆盖范围内。
 *
 * ★ 刻意**不含**「保险」「房租」「宽带」:
 *   它们要么应当由"固定周期金额"路径认出来(见下),要么根本不该被认成订阅。
 *   关键词表一旦贪多,就会把水电燃气这类代扣也卷进来 —— 那些取消的后果
 *   (断水断电)与取消会员完全不是一回事。
 */
export const SUBSCRIPTION_KEYWORDS: readonly string[] = [
  "视频",
  "影视",
  "音乐",
  "云盘",
  "网盘",
  "云空间",
  "云存储",
  "会员",
  "订阅",
  "包月",
  "连续包月",
  "续费",
  "课程",
  "网课",
  "教育",
  "学堂",
  "健身",
  "阅读",
  "小说",
  "漫画",
  "知识",
  "工具",
  "加速",
  "空间",
];

/** 人对人付款的分类 —— 命中即按"人际付款"处理,不进入订阅清单 */
const PERSONAL_CATEGORIES: readonly string[] = ["转账", "住房物业", "人情往来", "借款", "工资收入", "报销"];

// ============================================================================
// 类型
// ============================================================================

/** 识别证据 —— 每一条都必须能讲清"系统凭什么认为这是订阅代扣" */
export interface SubscriptionEvidence {
  /** 商户名命中的关键词(空数组 = 靠固定周期金额认出来的) */
  keywords: string[];
  /** 观测到的扣款次数 */
  occurrences: number;
  /** 平均扣款间隔(天) */
  intervalDays: number | null;
  /** 间隔标准差(天)—— 越小越像订阅 */
  intervalStdDays: number | null;
  cadence: SubscriptionCadence | "irregular" | "unknown";
  /** 每期金额是否稳定 */
  amountStable: boolean;
  /** 金额波动幅度(元) */
  amountSpread: number;
  firstChargedAt: number | null;
  lastChargedAt: number | null;
}

export type SubscriptionStatus = "active" | "cancelled" | "flow_only";

export interface SubscriptionItem {
  /** 银行侧协议号;只有流水没有协议时为 null */
  subscriptionId: string | null;
  merchantName: string;
  category: string;
  /** 每期扣费金额 */
  amount: number;
  currency: string;
  cadence: SubscriptionCadence | "irregular" | "unknown";
  cadenceLabel: string;
  /** 下次扣款时间(已取消 / 无法推算时为 null) */
  nextDebitAt: number | null;
  daysUntilNext: number | null;
  status: SubscriptionStatus;
  statusLabel: string;
  /** 解约通道:bank = 本行可受理,merchant = 只能去商户侧关 */
  cancelChannel: "bank" | "merchant";
  cancelChannelLabel: string;
  /** 现在能不能在对话里取消 */
  cancelable: boolean;
  /** 不能取消时的原因(必须原样讲给客户) */
  cancelBlockReason: string | null;
  /** 已经扣掉的费用怎么处理 */
  refundPolicy: string;
  /** 取消的后果 */
  cancelConsequence: string;
  /** 只能商户侧关闭时的操作路径 */
  merchantCancelPath: string | null;
  /** 数据来源:flow = 仅流水识别;flow+mandate = 流水与协议双证据 */
  source: "flow" | "flow+mandate" | "mandate";
  evidence: SubscriptionEvidence;
}

/** 识别出来但**不是订阅代扣**的定期付款 —— 必须能解释为什么不算 */
export interface ExcludedRecurring {
  counterpartyName: string;
  amount: number;
  cadence: string;
  reason: string;
}

export interface SubscriptionScanResult {
  items: SubscriptionItem[];
  excluded: ExcludedRecurring[];
  /** 仍会扣款的订阅折算到每月的合计(元) */
  monthlyTotal: number;
  /** 已经取消的份数 */
  cancelledCount: number;
  /** 只有流水、本行无协议可解的份数 */
  merchantOnlyCount: number;
  scannedTransactions: number;
  windowDays: number;
  summary: string;
}

// ============================================================================
// 识别
// ============================================================================

const CADENCE_LABELS: Record<string, string> = {
  monthly: "每月",
  weekly: "每周",
  yearly: "每年",
  irregular: "不定期",
  unknown: "未确认",
};

export function cadenceLabel(c: string): string {
  return CADENCE_LABELS[c] ?? c;
}

/** 按间隔均值与标准差判周期 —— 与账单分析的判定口径一致(不一致会让同一笔钱有两种说法) */
function cadenceOf(meanInterval: number, std: number): SubscriptionCadence | "irregular" {
  if (std > Math.max(2, meanInterval * 0.2)) return "irregular";
  if (meanInterval >= 26 && meanInterval <= 34) return "monthly";
  if (meanInterval >= 5 && meanInterval <= 9) return "weekly";
  if (meanInterval >= 340 && meanInterval <= 380) return "yearly";
  return "irregular";
}

/** 下次扣款:按日历推进,而不是粗暴 +30 天(与 detectRecurring 同一口径) */
export function nextDebitFrom(lastTs: number, cadence: string): number | null {
  if (cadence !== "monthly" && cadence !== "weekly" && cadence !== "yearly") return null;
  const d = new Date(lastTs);
  if (cadence === "monthly") d.setMonth(d.getMonth() + 1);
  else if (cadence === "weekly") d.setDate(d.getDate() + 7);
  else d.setFullYear(d.getFullYear() + 1);
  return d.getTime();
}

function keywordHits(name: string): string[] {
  const lower = name.toLowerCase();
  return SUBSCRIPTION_KEYWORDS.filter((k) => lower.includes(k.toLowerCase()));
}

export interface SubscriptionScanInput {
  /** 客户本人、指定窗口内的流水(调用方负责限定范围) */
  transactions: Transaction[];
  /** 银行侧代扣协议 */
  mandates: BankSubscription[];
  now: number;
  windowDays?: number;
  /**
   * 收款人目录里的**个人**收款人 ID。
   *
   * ★ 为什么由调用方传进来而不是引擎自己去查:
   *   "对手方是不是我在给人转账"是银行侧事实(收款人目录),不是流水里的字段。
   *   引擎保持纯函数(可单测、可复算),取数留在能力层。
   */
  personalPayeeIds?: ReadonlySet<string>;
}

interface FlowGroup {
  name: string;
  category: string;
  counterpartyId: string | null;
  list: Transaction[];
}

function groupByCounterparty(out: Transaction[]): FlowGroup[] {
  const map = new Map<string, FlowGroup>();
  for (const t of out) {
    const hit = map.get(t.counterpartyName);
    if (hit) {
      hit.list.push(t);
      if (!hit.counterpartyId && t.counterpartyId) hit.counterpartyId = t.counterpartyId;
    } else {
      map.set(t.counterpartyName, {
        name: t.counterpartyName,
        category: t.category ?? "其他",
        counterpartyId: t.counterpartyId ?? null,
        list: [t],
      });
    }
  }
  return [...map.values()];
}

function computeEvidence(group: FlowGroup): SubscriptionEvidence {
  const sorted = [...group.list].sort((a, b) => a.ts - b.ts);
  const amounts = sorted.map((t) => t.amount);
  const max = Math.max(...amounts);
  const min = Math.min(...amounts);
  const spread = round2(max - min);
  // ★ 金额"稳定"的判据同时给绝对与相对两条线:
  //   6 元的云空间差 1 元是 17%(不该判为不稳定),5800 元的房租差 1 元是 0.02%。
  const avg = amounts.reduce((s, a) => s + a, 0) / amounts.length;
  const amountStable = spread <= Math.max(1, avg * 0.05);

  let intervalDays: number | null = null;
  let stdDays: number | null = null;
  let cadence: SubscriptionEvidence["cadence"] = "unknown";
  if (sorted.length >= 2) {
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) intervals.push((sorted[i]!.ts - sorted[i - 1]!.ts) / DAY_MS);
    const mean = intervals.reduce((s, i) => s + i, 0) / intervals.length;
    const variance = intervals.reduce((s, i) => s + (i - mean) ** 2, 0) / intervals.length;
    intervalDays = Math.round(mean * 10) / 10;
    stdDays = Math.round(Math.sqrt(variance) * 10) / 10;
    cadence = cadenceOf(mean, Math.sqrt(variance));
  }

  return {
    keywords: keywordHits(group.name),
    occurrences: sorted.length,
    intervalDays,
    intervalStdDays: stdDays,
    cadence,
    amountStable,
    amountSpread: spread,
    firstChargedAt: sorted.length > 0 ? sorted[0]!.ts : null,
    lastChargedAt: sorted.length > 0 ? sorted[sorted.length - 1]!.ts : null,
  };
}

/** 商户名归一化:大小写、空格、常见分隔符、全角括号一律抹平后再比 */
export function normalizeMerchantName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[\s\u3000]+/g, "")
    .replace(/[()（）【】\[\]·、,，.。\-—_/\\|:：'"“”‘’]/g, "");
}

/** 字面相似度(1 = 完全相同) */
function bigramDice(a: string, b: string): number {
  if (a.length < 2 || b.length < 2) return a === b ? 1 : 0;
  const grams = (s: string) => {
    const out: string[] = [];
    for (let i = 0; i < s.length - 1; i++) out.push(s.slice(i, i + 2));
    return out;
  };
  const ga = grams(a);
  const gb = grams(b);
  const pool = [...gb];
  let hits = 0;
  for (const g of ga) {
    const idx = pool.indexOf(g);
    if (idx >= 0) {
      hits += 1;
      pool.splice(idx, 1);
    }
  }
  return (2 * hits) / (ga.length + gb.length);
}

/**
 * 商户名匹配打分。
 *
 * ★ 为什么不复用收款人那套 scoreName:
 *   收款人匹配要处理"张玮/章伟"这种**同音同姓**与拼音首字母(那是人名的问题);
 *   商户名的问题完全不同 —— 客户会说「爱奇艺」指代「爱奇艺会员」、
 *   说「那个云空间」指代「iCloud 云空间」。所以判据是**包含关系 + 字面重合**,
 *   而不是拼音。同一个"定位"目标在两处用不同判据是刻意的,不是重复实现。
 */
export function scoreMerchantMatch(query: string, merchantName: string): number {
  const q = normalizeMerchantName(query);
  const m = normalizeMerchantName(merchantName);
  if (q.length === 0 || m.length === 0) return 0;
  if (q === m) return 1;
  if (m.includes(q)) return 0.92;
  if (q.includes(m)) return 0.88;
  return round2(bigramDice(q, m)) * 0.8;
}

/** 匹配阈值:低于它的候选不进候选列表(宁可说"没找到",不可猜着办) */
export const SUBSCRIPTION_MATCH_THRESHOLD = 0.8;

export interface SubscriptionMatch {
  best: SubscriptionItem | null;
  /** 全部达到阈值的候选(去重后按分数降序) */
  candidates: Array<{ item: SubscriptionItem; score: number }>;
  /** 是否不止一个候选 —— 此时必须让客户指认,不得替他选 */
  ambiguous: boolean;
  /** 打分最高但没到阈值时的分数(用于解释"为什么没找到",如"您要找的可能是 XX") */
  closestScore: number;
  closestName: string | null;
}

export function matchSubscription(query: string, items: SubscriptionItem[]): SubscriptionMatch {
  const scored = items
    .map((item) => ({ item, score: scoreMerchantMatch(query, item.merchantName) }))
    .sort((a, b) => b.score - a.score);
  const candidates = scored.filter((s) => s.score >= SUBSCRIPTION_MATCH_THRESHOLD);
  return {
    best: candidates.length > 0 ? candidates[0]!.item : null,
    candidates,
    ambiguous: candidates.length > 1,
    closestScore: scored.length > 0 ? scored[0]!.score : 0,
    closestName: scored.length > 0 ? scored[0]!.item.merchantName : null,
  };
}

// ============================================================================
// 主识别函数
// ============================================================================

/**
 * 扫描流水 + 交叉核对代扣协议 → 订阅代扣清单。
 *
 * 识别判据(**两条路径,任一成立**)：
 *   ① 关键词路径:商户名命中服务品类词(视频/音乐/云盘/会员/课程…),且扣款 ≥2 次;
 *   ② 固定周期金额路径:间隔规律(cadence 成立)+ 每期金额稳定 + 扣款 ≥3 次。
 *
 * 排除判据(任一成立即排除,并写入 excluded 与理由):
 *   · 对手方是收款人目录里的**个人** → 人对人的合同/人际付款(房租是典型);
 *   · 分类属于人际往来/居住/收入类 → 同上;
 *   · 无关键词且金额不稳定 → 更像随机消费,不是订阅。
 */
export function scanSubscriptions(input: SubscriptionScanInput): SubscriptionScanResult {
  const { transactions, mandates, now } = input;
  const windowDays = input.windowDays ?? 180;
  const out = transactions.filter((t) => t.direction === "out");
  const groups = groupByCounterparty(out);

  const mandateByName = new Map<string, BankSubscription>();
  for (const m of mandates) mandateByName.set(normalizeMerchantName(m.merchantName), m);

  const items: SubscriptionItem[] = [];
  const excluded: ExcludedRecurring[] = [];
  const usedMandateIds = new Set<string>();

  for (const group of groups) {
    const evidence = computeEvidence(group);
    const hasKeyword = evidence.keywords.length > 0;
    const periodic = evidence.cadence === "monthly" || evidence.cadence === "weekly" || evidence.cadence === "yearly";
    const byKeyword = hasKeyword && evidence.occurrences >= 2;
    const byCycle = periodic && evidence.amountStable && evidence.occurrences >= 3;

    // 连"像订阅"都算不上 → 不进清单,也不进 excluded(否则清单会被日常消费淹没)
    if (!byKeyword && !byCycle) continue;

    const mandate = mandateByName.get(normalizeMerchantName(group.name)) ?? null;

    // ---- 排除①:个人收款人(房租、给家人的生活费…)----
    if (group.counterpartyId && input.personalPayeeIds?.has(group.counterpartyId)) {
      excluded.push({
        counterpartyName: group.name,
        amount: round2(group.list[group.list.length - 1]!.amount),
        cadence: evidence.cadence,
        reason:
          `对手方「${group.name}」是您收款人目录里的**个人**,这是一笔人对人的定期付款(合同款/家用),` +
          "不是商户代扣 —— 取消它的后果是违约或断供,与关闭一份会员协议完全不同,因此不列入可取消的订阅。",
      });
      continue;
    }

    // ---- 排除②:分类属于人际往来/居住/收入,且没有订阅关键词 ----
    if (!hasKeyword && PERSONAL_CATEGORIES.some((c) => group.category.includes(c))) {
      excluded.push({
        counterpartyName: group.name,
        amount: round2(group.list[group.list.length - 1]!.amount),
        cadence: evidence.cadence,
        reason: `分类「${group.category}」属于人对人的定期付款,且商户名没有订阅特征 —— 不列为代扣。`,
      });
      continue;
    }

    // ---- 排除③:靠周期认出来的,但金额并不固定 ----
    if (!hasKeyword && !evidence.amountStable) {
      excluded.push({
        counterpartyName: group.name,
        amount: round2(group.list[group.list.length - 1]!.amount),
        cadence: evidence.cadence,
        reason: `扣款间隔较规律,但每期金额波动 ${evidence.amountSpread} 元 —— 更像周期性消费(如加油、买菜),不是固定金额的代扣。`,
      });
      continue;
    }

    const lastAmount = round2(group.list[group.list.length - 1]!.amount);
    const cadence: SubscriptionCadence | "irregular" | "unknown" = evidence.cadence;
    const nextFromFlow = evidence.lastChargedAt != null ? nextDebitFrom(evidence.lastChargedAt, cadence) : null;

    if (mandate) usedMandateIds.add(mandate.subscriptionId);

    const cancelled = mandate?.status === "cancelled";
    // ★ 协议优先:签约金额与协议里的下次扣款日是**合同事实**,流水的推算只是兜底
    const amount = mandate ? round2(mandate.amount) : lastAmount;
    const nextDebitAt = cancelled ? null : (mandate?.nextDebitAt ?? nextFromFlow);
    const channel = mandate ? (mandate.channel === "bank_mandate" ? "bank" : "merchant") : "merchant";

    items.push(
      buildItem({
        mandate,
        merchantName: mandate?.merchantName ?? group.name,
        category: mandate?.category ?? group.category,
        amount,
        currency: mandate?.currency ?? "CNY",
        cadence: mandate ? mandate.cadence : cadence,
        nextDebitAt,
        now,
        channel,
        source: mandate ? "flow+mandate" : "flow",
        evidence,
      }),
    );
  }

  // ---- 只看协议、流水里没出现的:也要列出来(客户问的是"我签了哪些代扣")----
  for (const m of mandates) {
    if (usedMandateIds.has(m.subscriptionId)) continue;
    const nextDebitAt = m.status === "cancelled" ? null : m.nextDebitAt;
    items.push(
      buildItem({
        mandate: m,
        merchantName: m.merchantName,
        category: m.category,
        amount: round2(m.amount),
        currency: m.currency,
        cadence: m.cadence,
        nextDebitAt,
        now,
        channel: m.channel === "bank_mandate" ? "bank" : "merchant",
        source: "mandate",
        evidence: {
          keywords: keywordHits(m.merchantName),
          occurrences: 0,
          intervalDays: null,
          intervalStdDays: null,
          cadence: m.cadence,
          amountStable: true,
          amountSpread: 0,
          firstChargedAt: null,
          lastChargedAt: null,
        },
      }),
    );
  }

  // 排序:能取消的在前 → 快要扣款的在前 → 金额大的在前
  items.sort((a, b) => {
    if (a.cancelable !== b.cancelable) return a.cancelable ? -1 : 1;
    const da = a.daysUntilNext ?? Number.POSITIVE_INFINITY;
    const db = b.daysUntilNext ?? Number.POSITIVE_INFINITY;
    if (da !== db) return da - db;
    return b.amount - a.amount;
  });

  const activeItems = items.filter((i) => i.status === "active");
  const monthlyTotal = round2(activeItems.reduce((s, i) => s + monthlyEquivalent(i), 0));
  const cancelledCount = items.filter((i) => i.status === "cancelled").length;
  const merchantOnlyCount = items.filter((i) => i.status === "flow_only").length;

  const summary =
    items.length === 0
      ? `近 ${windowDays} 天的流水里没有发现订阅代扣。`
      : `近 ${windowDays} 天的流水里识别出 ${items.length} 笔订阅代扣` +
        `(其中 ${activeItems.length} 笔仍在扣款,每月合计约 ${fmtSubMoney(monthlyTotal)} 元` +
        `${cancelledCount > 0 ? `;${cancelledCount} 笔已取消` : ""}` +
        `${merchantOnlyCount > 0 ? `;${merchantOnlyCount} 笔属于商户侧自动续费,本行无法直接解约` : ""})。`;

  return {
    items,
    excluded,
    monthlyTotal,
    cancelledCount,
    merchantOnlyCount,
    scannedTransactions: out.length,
    windowDays,
    summary,
  };
}

function buildItem(args: {
  mandate: BankSubscription | null;
  merchantName: string;
  category: string;
  amount: number;
  currency: string;
  cadence: SubscriptionCadence | "irregular" | "unknown";
  nextDebitAt: number | null;
  now: number;
  channel: "bank" | "merchant";
  source: SubscriptionItem["source"];
  evidence: SubscriptionEvidence;
}): SubscriptionItem {
  const { mandate, nextDebitAt, now, channel } = args;
  const cancelled = mandate?.status === "cancelled";
  const status: SubscriptionStatus = cancelled ? "cancelled" : mandate ? "active" : "flow_only";

  const daysUntilNext = nextDebitAt != null ? Math.ceil((nextDebitAt - now) / DAY_MS) : null;

  let cancelable = false;
  let cancelBlockReason: string | null = null;
  if (cancelled) {
    cancelBlockReason =
      `这份代扣协议已于 ${mandate?.cancelledAt != null ? fmtSubDay(mandate.cancelledAt) : "此前"}取消,不会再扣款,无需重复操作。`;
  } else if (!mandate) {
    cancelBlockReason =
      "本行没有查到这笔的**代扣协议** —— 它属于商户侧自动续费(常见于应用商店订阅)," +
      "钱由商户通过卡组织发起,本行没有可解的协议,只能在商户侧关闭。";
  } else if (channel === "merchant") {
    cancelBlockReason =
      "这笔的签约方在**商户侧**,本行没有可解的协议。可以帮您确认商户侧的关闭路径,但不能声称已经替您取消。";
  } else {
    cancelable = true;
  }

  const statusLabel = cancelled
    ? "已取消"
    : !mandate
      ? "仅流水识别 · 无本行协议"
      : channel === "bank"
        ? "代扣中 · 本行可解约"
        : "代扣中 · 需商户侧关闭";

  return {
    subscriptionId: mandate?.subscriptionId ?? null,
    merchantName: args.merchantName,
    category: args.category,
    amount: args.amount,
    currency: args.currency,
    cadence: args.cadence,
    cadenceLabel: cadenceLabel(args.cadence),
    nextDebitAt,
    daysUntilNext,
    status,
    statusLabel,
    cancelChannel: channel,
    cancelChannelLabel: mandate?.channelLabel ?? "商户侧自动续费(本行无协议)",
    cancelable,
    cancelBlockReason,
    refundPolicy:
      mandate?.refundPolicy ??
      "本行没有这笔的代扣协议,费用争议需要与该商户协商;本行可协助提供流水作为凭证。",
    cancelConsequence:
      mandate?.cancelConsequence ??
      "在该商户处关闭自动续费后,到期不再续订,已购权益按商户规则处理。",
    merchantCancelPath: mandate?.merchantCancelPath ?? "在该商户 App 的「订阅 / 自动续费」设置里关闭",
    source: args.source,
    evidence: args.evidence,
  };
}

export function monthlyEquivalent(item: SubscriptionItem): number {
  if (item.cadence === "monthly") return item.amount;
  if (item.cadence === "yearly") return round2(item.amount / 12);
  if (item.cadence === "weekly") return round2((item.amount * 30) / 7);
  return item.amount;
}

// ============================================================================
// 续费提醒
// ============================================================================

/**
 * 即将扣款的订阅。
 *
 * ★ 只算**仍会扣款**的那些(active)。
 *   已取消的、本行无协议但商户侧仍在续费的,必须分开表达:
 *   后者对客户同样是"还要扣钱"的事实,只是系统关不了 —— 漏掉它,
 *   客户就会在扣款后才想起来,而这恰恰是续费提醒存在的意义。
 */
export function upcomingRenewals(items: SubscriptionItem[], _now: number, withinDays = 30): SubscriptionItem[] {
  return items
    .filter((i) => i.status !== "cancelled" && i.daysUntilNext != null && i.daysUntilNext <= withinDays)
    .sort((a, b) => (a.daysUntilNext ?? 0) - (b.daysUntilNext ?? 0));
}

// ============================================================================
// 渲染
// ============================================================================

/** 两位小数金额(与全仓金额口径共用一份实现,见 util/format.ts) */
export function fmtSubMoney(n: number): string {
  return fmtSubMoneyShared(n);
}

export function fmtSubDay(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export function fmtSubDateTime(ts: number): string {
  const d = new Date(ts);
  return `${fmtSubDay(ts)} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** 扣款倒计时的说法 —— "还有 3 天"比"10月18日"更容易让客户有感觉 */
export function daysText(days: number | null): string {
  if (days == null) return "扣款时间未知";
  if (days < 0) return `已过期 ${Math.abs(days)} 天`;
  if (days === 0) return "今天";
  if (days === 1) return "明天";
  return `${days} 天后`;
}

function evidenceText(e: SubscriptionEvidence): string {
  const parts: string[] = [];
  if (e.keywords.length > 0) parts.push(`商户名命中关键词「${e.keywords.join("、")}」`);
  if (e.occurrences >= 2 && e.intervalDays != null) {
    parts.push(`近 ${e.occurrences} 次扣款间隔约 ${e.intervalDays} 天${e.intervalStdDays != null ? `(波动 ${e.intervalStdDays} 天)` : ""}`);
  }
  if (e.amountStable && e.occurrences >= 2) parts.push(`每期金额稳定(波动 ${e.amountSpread} 元)`);
  if (e.occurrences === 0) parts.push("依据银行侧代扣协议(该窗口内尚未扣款)");
  return parts.length > 0 ? parts.join(";") : "依据银行侧代扣协议";
}

/** 清单里的单行 —— 金额与时间必须同时出现,缺一个客户就得自己去猜 */
function itemLine(item: SubscriptionItem, index?: number): string {
  const prefix = index != null ? `${index}. ` : "";
  const when =
    item.status === "cancelled"
      ? "已取消,不再扣款"
      : item.nextDebitAt != null
        ? `下次扣款 ${fmtSubDay(item.nextDebitAt)}(${daysText(item.daysUntilNext)}),扣 ¥${fmtSubMoney(item.amount)}`
        : `每期 ¥${fmtSubMoney(item.amount)},扣款日待定`;
  return `${prefix}${item.merchantName} · ${item.cadenceLabel} ¥${fmtSubMoney(item.amount)} · ${when} · ${item.statusLabel}`;
}

export function renderSubscriptionList(items: SubscriptionItem[]): string[] {
  const lines: string[] = [];
  items.forEach((item, i) => lines.push(itemLine(item, i + 1)));
  return lines;
}

/**
 * 单笔详情 —— 确认卡之外的第二处"必须说全"的地方。
 *
 * ★ 六件事缺一不可:扣多少、什么时候扣、签约方是谁、能不能在这里解、
 *   本期已扣的钱怎么办、取消之后会失去什么。
 *   前三条让客户判断"要不要取消",后三条让客户判断"取消的代价我认不认"。
 */
export function renderSubscriptionDetail(item: SubscriptionItem, _now: number): string[] {
  const lines: string[] = [];
  lines.push(`【${item.merchantName}】${item.category}`);
  lines.push(`每期扣费:¥${fmtSubMoney(item.amount)}(${item.cadenceLabel})`);
  lines.push(
    item.status === "cancelled"
      ? `当前状态:已取消(不会再扣款)`
      : item.nextDebitAt != null
        ? `下次扣款:${fmtSubDateTime(item.nextDebitAt)} —— ${daysText(item.daysUntilNext)}`
        : `下次扣款:待定(该协议在本窗口内没有扣款记录)`,
  );
  lines.push(`签约通道:${item.cancelChannelLabel}`);
  if (item.subscriptionId) lines.push(`协议号:${item.subscriptionId}`);
  lines.push(`识别依据:${evidenceText(item.evidence)}`);
  lines.push("");
  if (item.cancelable) {
    lines.push(`可以在本行解约。生效方式:下一期起不再扣款,不是退还已扣费用。`);
    lines.push(`本期已扣费用:${item.refundPolicy}`);
    lines.push(`取消后果:${item.cancelConsequence}`);
  } else {
    lines.push(`不能在本行解约:${item.cancelBlockReason ?? "不在可受理范围"}`);
    if (item.merchantCancelPath) lines.push(`关闭路径:${item.merchantCancelPath}`);
  }
  return lines;
}

/** 已取消 / 商户侧 / 不存在 —— 三类"没办成"的统一出口:说清是什么、为什么、下一步在哪 */
export function renderCancelNotices(args: {
  items: SubscriptionItem[];
  merchantQuery: string;
  closestName: string | null;
  closestScore: number;
}): { text: string; kind: "not_found"; } {
  const lines: string[] = [];
  lines.push(`我没有找到「${args.merchantQuery}」这笔订阅代扣 —— 所以**什么都没有执行**。`);
  lines.push("");
  if (args.closestName && args.closestScore >= 0.45) {
    lines.push(`您是不是想找「${args.closestName}」?如果是,直接说「取消${args.closestName}」。`);
    lines.push("");
  }
  const known = args.items.filter((i) => i.status !== "cancelled");
  if (known.length === 0) {
    lines.push("近半年您的流水里也没有识别到任何订阅代扣。");
  } else {
    lines.push(`您目前识别到的订阅代扣是这些(${known.length} 笔):`);
    lines.push(...known.map((i, idx) => itemLine(i, idx + 1)));
    lines.push("");
    lines.push("如不确定是哪一笔,请回复序号或商户名称。系统将先说明金额与下次扣款时间,确认后才会办理。");
  }
  lines.push("");
  lines.push("未找到对应订阅,因此未执行任何操作。");
  return { text: lines.join("\n"), kind: "not_found" };
}

export { DAY_MS as SUBSCRIPTION_DAY_MS };
export { itemLine as renderSubscriptionItemLine, evidenceText as renderSubscriptionEvidence };