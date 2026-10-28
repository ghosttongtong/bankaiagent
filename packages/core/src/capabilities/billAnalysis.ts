/**
 * 账单分析引擎(纯函数,确定性)
 *
 * ★ 这是账单分析场景的"数字大脑":
 *    所有金额计算、异常判定、结论生成都在这里完成 —— 零 LLM 参与。
 *    模型只负责把用户的话翻译成"调用哪个能力、传什么参数";
 *    这里的每一行都能被审计员逐条读懂、被单测覆盖。
 *
 * ★ 与转账场景的七条不变量完全对齐:
 *    I1 模型不做裁决 —— 这里的判定全是确定性规则
 *    I3 数字必须来自工具 —— 输入是银行侧取数结果,输出金额字段全部可追溯
 *    I6 一切外部输入不可信 —— memo 只用于展示,不参与任何判定逻辑
 *
 * 数据输入:Transaction[](银行核心侧取数,仅限本人账户)。
 * 演示数据在 `packages/bankcore/src/mock.ts`,种子固定,演示可复现。
 */

import { fmtDateCn, round2 } from "../util/format.ts";
import type { Transaction } from "../types.ts";

// ============================================================================
// 基础工具
// ============================================================================

function median(nums: number[]): number {
  if (nums.length === 0) return 0;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/** 中文日期(本地时区):`2026年9月29日` —— 与 util/format 的口径共用一份实现 */
export function fmtDate(ts: number): string {
  return fmtDateCn(ts);
}

export function fmtMonth(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}年${d.getMonth() + 1}月`;
}

function hourOf(ts: number): number {
  return new Date(ts).getHours();
}

// ============================================================================
// 异常交易识别
// ============================================================================

export type AnomalyKind =
  | "large_single" // 单笔大额(相对本人消费中位数)
  | "off_hours" // 深夜时段交易
  | "first_time_large" // 首次出现的对手方 + 大额
  | "duplicate_burst" // 短时间内同商户同金额重复扣款
  | "category_spike"; // 某分类支出较上期突增

export type AnomalySeverity = "high" | "medium" | "low";

export interface Anomaly {
  kind: AnomalyKind;
  severity: AnomalySeverity;
  title: string;
  description: string;
  amount: number;
  ts: number;
  counterpartyName: string;
  category: string;
  transactionId: string;
  suggestedAction: string;
}

export interface AnomalyReport {
  windowLabel: string;
  checkedCount: number;
  anomalies: Anomaly[];
  summary: string;
}

const SUGGESTED_ACTION: Record<AnomalySeverity, string> = {
  high: "建议立即核实是否本人操作;如非本人,回复「转人工」联系反诈专员,必要时可先冻结卡片",
  medium: "建议打开交易详情核对;确认无误后可忽略本条",
  low: "仅作提示,一般无需处理",
};

/**
 * 识别可疑交易。
 *
 * ★ 阈值设计原则(来自转账场景的教训):假警告有害。
 *   一个"把房租每月报一遍"的异常检测,用户看三次就会关掉提醒功能。
 *   所以:
 *     · 先识别**周期性付款**(房租/订阅),把它们从"大额异常"里剔除 ——
 *       房租 5800 不是异常,它是模式;
 *     · 首次对手方的大额门槛设得比"单笔大额"更高,避免把给家人的转账当异常。
 */
export function detectAnomalies(txs: Transaction[], now: number): AnomalyReport {
  const out = txs.filter((t) => t.direction === "out");
  const anomalies: Anomaly[] = [];

  // ---- 0. 先识别周期性付款,用于排除"房租/订阅"这类规律性大额 ----
  const recurringNames = new Set(detectRecurring(out, now).items.map((r) => r.counterpartyName));

  // ---- 1. 单笔大额(相对本人消费水平) ----
  const amounts = out.map((t) => t.amount);
  const med = median(amounts);
  const largeThreshold = Math.max(3_000, med * 6);
  for (const t of out) {
    if (t.amount < largeThreshold) continue;
    if (recurringNames.has(t.counterpartyName)) continue; // 房租/订阅是模式,不是异常
    const ratio = med > 0 ? Math.round((t.amount / med) * 10) / 10 : null;
    const severity: AnomalySeverity = t.amount >= largeThreshold * 2 ? "high" : "medium";
    anomalies.push({
      kind: "large_single",
      severity,
      title: `单笔大额支出 ¥${round2(t.amount)}`,
      description:
        `向「${t.counterpartyName}」支出 ${round2(t.amount)} 元` +
        (ratio ? `,约为本人日常消费中位数(${round2(med)} 元)的 ${ratio} 倍` : ""),
      amount: t.amount,
      ts: t.ts,
      counterpartyName: t.counterpartyName,
      category: t.category ?? "其他",
      transactionId: t.transactionId,
      // ★ 建议文案必须与严重度一致:high 级却说"确认无误后可忽略"是自相矛盾的。
      suggestedAction: SUGGESTED_ACTION[severity],
    });
  }

  // ---- 2. 深夜时段交易(0–5 点) ----
  for (const t of out) {
    const h = hourOf(t.ts);
    if (h >= 0 && h <= 5 && t.amount >= 200) {
      anomalies.push({
        kind: "off_hours",
        severity: t.amount >= 1_000 ? "high" : "low",
        title: `凌晨时段交易 ¥${round2(t.amount)}`,
        description: `${fmtDate(t.ts)} ${String(h).padStart(2, "0")}:xx 向「${t.counterpartyName}」支付 ${round2(t.amount)} 元`,
        amount: t.amount,
        ts: t.ts,
        counterpartyName: t.counterpartyName,
        category: t.category ?? "其他",
        transactionId: t.transactionId,
        suggestedAction: t.amount >= 1_000 ? SUGGESTED_ACTION.high : SUGGESTED_ACTION.low,
      });
    }
  }

  // ---- 3. 首次出现的对手方 + 大额 ----
  // ★ 去重:同一笔交易若已被"单笔大额"标记,不再重复标记为"新对手方大额"。
  //   否则用户看到同一笔 12800 元出现两条,会怀疑检测器在凑数 ——
  //   假重复和假警告一样,都会稀释真实信号。
  const alreadyLargeTxs = new Set(anomalies.filter((a) => a.kind === "large_single").map((a) => a.transactionId));
  const byCounterparty = new Map<string, Transaction[]>();
  for (const t of out) {
    const list = byCounterparty.get(t.counterpartyName) ?? [];
    list.push(t);
    byCounterparty.set(t.counterpartyName, list);
  }
  for (const [name, list] of byCounterparty) {
    if (list.length !== 1) continue;
    const t = list[0]!;
    if (t.amount < 5_000) continue;
    if (alreadyLargeTxs.has(t.transactionId)) continue;
    anomalies.push({
      kind: "first_time_large",
      severity: "high",
      title: `新对手方大额支出 ¥${round2(t.amount)}`,
      description: `「${name}」是分析窗口内首次出现的对手方,单笔 ${round2(t.amount)} 元`,
      amount: t.amount,
      ts: t.ts,
      counterpartyName: name,
      category: t.category ?? "其他",
      transactionId: t.transactionId,
      suggestedAction: SUGGESTED_ACTION.high,
    });
  }

  // ---- 4. 短时重复扣款:7 天内同商户同金额 ≥3 笔 ----
  const DAY = 24 * 3600 * 1000;
  const flagged = new Set<string>();
  for (const t of out) {
    if (flagged.has(t.counterpartyName)) continue;
    const same = out.filter(
      (o) => o.counterpartyName === t.counterpartyName && Math.abs(o.amount - t.amount) < 0.01,
    );
    if (same.length < 3) continue;
    const tsSorted = same.map((o) => o.ts).sort((a, b) => a - b);
    const windowDays = (tsSorted[tsSorted.length - 1]! - tsSorted[0]!) / DAY;
    if (windowDays <= 7) {
      flagged.add(t.counterpartyName);
      anomalies.push({
        kind: "duplicate_burst",
        severity: "medium",
        title: `疑似重复扣款:「${t.counterpartyName}」`,
        description: `在 ${Math.round(windowDays)} 天内被扣款 ${same.length} 笔,每笔 ${round2(t.amount)} 元`,
        amount: round2(t.amount * same.length),
        ts: tsSorted[0]!,
        counterpartyName: t.counterpartyName,
        category: t.category ?? "其他",
        transactionId: t.transactionId,
        suggestedAction: SUGGESTED_ACTION.medium,
      });
    }
  }

  // ---- 5. 分类支出突增:近 30 天 vs 前 30 天 ----
  const now30 = now - 30 * DAY;
  const prev30 = now - 60 * DAY;
  const catSum = (from: number, to: number) => {
    const m = new Map<string, number>();
    for (const t of out) {
      if (t.ts >= from && t.ts < to) {
        m.set(t.category ?? "其他", (m.get(t.category ?? "其他") ?? 0) + t.amount);
      }
    }
    return m;
  };
  const recentCats = catSum(now30, now);
  const prevCats = catSum(prev30, now30);
  for (const [cat, recent] of recentCats) {
    const prev = prevCats.get(cat) ?? 0;
    if (recent >= 800 && prev > 0 && recent >= prev * 2.5) {
      anomalies.push({
        kind: "category_spike",
        severity: "medium",
        title: `「${cat}」支出突增`,
        description: `近 30 天 ${round2(recent)} 元,是前 30 天(${round2(prev)} 元)的 ${Math.round((recent / prev) * 10) / 10} 倍`,
        amount: round2(recent),
        ts: now,
        counterpartyName: cat,
        category: cat,
        transactionId: "",
        suggestedAction: SUGGESTED_ACTION.medium,
      });
    }
  }

  // 排序:严重度优先,再按金额
  const order = { high: 0, medium: 1, low: 2 };
  anomalies.sort((a, b) => order[a.severity] - order[b.severity] || b.amount - a.amount);

  const high = anomalies.filter((a) => a.severity === "high").length;
  const summary =
    anomalies.length === 0
      ? `检查了 ${out.length} 笔支出,未发现明显异常。`
      : `检查了 ${out.length} 笔支出,发现 ${anomalies.length} 处需要留意${high > 0 ? `,其中 ${high} 处建议立即核实` : ""}。`;

  return {
    windowLabel: `${fmtDate(now - 90 * DAY)} 至 ${fmtDate(now)}`,
    checkedCount: out.length,
    anomalies: anomalies.slice(0, 10),
    summary,
  };
}

// ============================================================================
// 月度 / 年度账单报告
// ============================================================================

export interface ReportInsight {
  type: "warning" | "info" | "suggestion";
  text: string;
  evidence?: string;
}

export interface PeriodReport {
  periodLabel: string;
  income: number;
  expense: number;
  net: number;
  txCount: number;
  savingsRate: number | null;
  topCategories: Array<{ key: string; total: number; count: number; sharePct: number }>;
  topCounterparties: Array<{ key: string; total: number; count: number }>;
  largestTransactions: Array<{ counterpartyName: string; amount: number; category: string; ts: number }>;
  comparison: {
    baselineLabel: string;
    incomeChangePct: number | null;
    expenseChangePct: number | null;
    verdict: "much_higher" | "higher" | "similar" | "lower" | "much_lower";
    verdictText: string;
  } | null;
  insights: ReportInsight[];
  summary: string;
}

export function buildPeriodReport(
  txs: Transaction[],
  opts: { from: number; to: number; compareWithPrevious: boolean },
): PeriodReport {
  const { from, to, compareWithPrevious } = opts;

  // ★ txs 是"当前周期 + 上一周期"的并集(调用方取宽窗口,这里按时间过滤)。
  //   早期实现假定 txs 只含当前周期,导致上一周期基线永远是 0,
  //   输出"支出与上期基本持平(null%)"这种坏话。
  const inTxs = txs.filter((t) => t.direction === "in" && t.ts >= from && t.ts < to);
  const outTxs = txs.filter((t) => t.direction === "out" && t.ts >= from && t.ts < to);

  const income = round2(inTxs.reduce((s, t) => s + t.amount, 0));
  const expense = round2(outTxs.reduce((s, t) => s + t.amount, 0));
  const net = round2(income - expense);
  const savingsRate = income > 0 ? Math.round((net / income) * 1000) / 10 : null;

  // 分类汇总
  const catMap = new Map<string, { total: number; count: number }>();
  for (const t of outTxs) {
    const k = t.category ?? "其他";
    const cur = catMap.get(k) ?? { total: 0, count: 0 };
    cur.total += t.amount;
    cur.count += 1;
    catMap.set(k, cur);
  }
  const topCategories = [...catMap.entries()]
    .map(([key, v]) => ({
      key,
      total: round2(v.total),
      count: v.count,
      sharePct: expense > 0 ? Math.round((v.total / expense) * 1000) / 10 : 0,
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 6);

  // 商户汇总
  const cpMap = new Map<string, { total: number; count: number }>();
  for (const t of outTxs) {
    const cur = cpMap.get(t.counterpartyName) ?? { total: 0, count: 0 };
    cur.total += t.amount;
    cur.count += 1;
    cpMap.set(t.counterpartyName, cur);
  }
  const topCounterparties = [...cpMap.entries()]
    .map(([key, v]) => ({ key, total: round2(v.total), count: v.count }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 6);

  // 最大几笔支出
  const largestTransactions = [...outTxs]
    .sort((a, b) => b.amount - a.amount)
    .slice(0, 3)
    .map((t) => ({
      counterpartyName: t.counterpartyName,
      amount: round2(t.amount),
      category: t.category ?? "其他",
      ts: t.ts,
    }));

  // ---- 对比上一周期 ----
  let comparison: PeriodReport["comparison"] = null;
  if (compareWithPrevious) {
    const span = to - from;
    const baseFrom = from - span;
    const baseTo = from;
    const baseIn = round2(txs.filter((t) => t.direction === "in" && t.ts >= baseFrom && t.ts < baseTo).reduce((s, t) => s + t.amount, 0));
    const baseOut = round2(txs.filter((t) => t.direction === "out" && t.ts >= baseFrom && t.ts < baseTo).reduce((s, t) => s + t.amount, 0));

    const expenseChangePct = baseOut > 0 ? Math.round(((expense - baseOut) / baseOut) * 1000) / 10 : null;
    const incomeChangePct = baseIn > 0 ? Math.round(((income - baseIn) / baseIn) * 1000) / 10 : null;

    const verdictV: "much_higher" | "higher" | "similar" | "lower" | "much_lower" =
      (() => {
        const pct = expenseChangePct ?? 0;
        if (pct >= 50) return "much_higher";
        if (pct >= 15) return "higher";
        if (pct > -15) return "similar";
        if (pct > -50) return "lower";
        return "much_lower";
      })();

    const verdictTextMap = {
      much_higher: `支出较上期明显上升 ${expenseChangePct}%`,
      higher: `支出较上期上升 ${expenseChangePct}%`,
      similar: `支出与上期基本持平(${expenseChangePct}%)`,
      lower: `支出较上期下降 ${Math.abs(expenseChangePct ?? 0)}%`,
      much_lower: `支出较上期明显下降 ${Math.abs(expenseChangePct ?? 0)}%`,
    };

    // ★ 上一周期没有数据时,如实说明"无法对比",绝不能打印 null%。
    //   数据缺口是正常现象(如新客户、演示数据窗口短),把它藏起来才是问题。
    const noBaseline = baseIn === 0 && baseOut === 0;
    comparison = {
      baselineLabel: noBaseline ? "上一周期(无数据)" : `上一周期(${fmtDate(baseFrom)} 至 ${fmtDate(baseTo)})`,
      incomeChangePct,
      expenseChangePct,
      verdict: verdictV,
      verdictText: noBaseline ? "上一周期无数据,暂无法对比" : verdictTextMap[verdictV],
    };
  }

  // ---- 洞察(确定性规则,每条都可解释) ----
  const insights: ReportInsight[] = [];

  // 1. 储蓄率
  if (savingsRate != null) {
    if (savingsRate < 0) {
      insights.push({
        type: "warning",
        text: `本周期支出(${expense} 元)超过收入(${income} 元),出现 ${Math.abs(net)} 元缺口`,
        evidence: "入不敷出时,固定支出与订阅类支出是首先值得检查的对象",
      });
    } else if (savingsRate < 20) {
      insights.push({
        type: "info",
        text: `本周期储蓄率 ${savingsRate}%,低于 20% 的健康线`,
        evidence: "可查看订阅类定期支出,取消闲置订阅通常能立竿见影",
      });
    } else {
      insights.push({
        type: "info",
        text: `本周期储蓄率 ${savingsRate}%,收支结构健康`,
      });
    }
  }

  // 2. 最大分类占比
  const topCat = topCategories[0];
  if (topCat && topCat.sharePct >= 40) {
    insights.push({
      type: "warning",
      text: `「${topCat.key}」占全部支出的 ${topCat.sharePct}%,占比偏高`,
      evidence: `该分类共 ${topCat.count} 笔,合计 ${topCat.total} 元`,
    });
  }

  // 3. 订阅类重叠(文化娱乐分类的定期扣款 ≥3 项)
  const recurring = detectRecurring(outTxs, to);
  const entertainmentSubs = recurring.items.filter((r) => r.category === "文化娱乐");
  if (entertainmentSubs.length >= 3) {
    insights.push({
      type: "suggestion",
      text: `检测到 ${entertainmentSubs.length} 项文化娱乐类订阅,每月合计约 ${round2(entertainmentSubs.reduce((s, r) => s + r.monthlyEquivalent, 0))} 元`,
      evidence: entertainmentSubs.map((r) => r.counterpartyName).join("、"),
    });
  }

  // 4. 最大单笔占支出比
  const biggest = largestTransactions[0];
  if (biggest && expense > 0 && biggest.amount / expense > 0.2) {
    insights.push({
      type: "info",
      text: `最大一笔支出「${biggest.counterpartyName}」${biggest.amount} 元,占周期支出的 ${Math.round((biggest.amount / expense) * 100)}%`,
    });
  }

  const summaryParts = [
    `${fmtDate(from)} 至 ${fmtDate(to)}:收入 ${income} 元,支出 ${expense} 元,净${net >= 0 ? "结余" : "缺口"} ${Math.abs(net)} 元`,
    comparison ? comparison.verdictText : "",
    topCat ? `支出最多的是「${topCat.key}」(${topCat.total} 元,占 ${topCat.sharePct}%)` : "",
    insights.length > 0 ? `另有 ${insights.length} 条账单洞察` : "",
  ].filter(Boolean);

  return {
    periodLabel: `${fmtDate(from)} 至 ${fmtDate(to)}`,
    income,
    expense,
    net,
    txCount: txs.length,
    savingsRate,
    topCategories,
    topCounterparties,
    largestTransactions,
    comparison,
    insights,
    summary: summaryParts.join(";"),
  };
}

// ============================================================================
// 定期支出 / 订阅识别
// ============================================================================

export interface RecurringItem {
  counterpartyName: string;
  category: string;
  count: number;
  avgAmount: number;
  intervalDays: number | null;
  cadence: "weekly" | "monthly" | "yearly" | "irregular";
  /** 折算到每月 */
  monthlyEquivalent: number;
  firstTs: number;
  lastTs: number;
  expectedNext: number | null;
}

export interface RecurringReport {
  items: RecurringItem[];
  monthlyTotal: number;
  summary: string;
}

const DAY_MS = 24 * 3600 * 1000;

/**
 * 识别定期支出(订阅/房租/月供)。
 *
 * ★ 形参 `_now` 刻意保留但不用:周期判定只看**同一收款人的历史间隔**,
 *   不依赖"现在几点"。保留位置是为了让调用方读起来仍是"给我这段时间的流水"
 *   (真实实现若将来需要按 now 截断窗口,占位就在这儿)。
 */
export function detectRecurring(outTxs: Transaction[], _now: number): RecurringReport {
  const byCounterparty = new Map<string, Transaction[]>();
  for (const t of outTxs) {
    const list = byCounterparty.get(t.counterpartyName) ?? [];
    list.push(t);
    byCounterparty.set(t.counterpartyName, list);
  }

  const items: RecurringItem[] = [];

  for (const [name, list] of byCounterparty) {
    if (list.length < 3) continue;
    const sorted = [...list].sort((a, b) => a.ts - b.ts);
    const intervals: number[] = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push((sorted[i]!.ts - sorted[i - 1]!.ts) / DAY_MS);
    }
    const meanInterval = intervals.reduce((s, i) => s + i, 0) / intervals.length;
    const amounts = sorted.map((t) => t.amount);
    const avgAmount = round2(amounts.reduce((s, a) => s + a, 0) / amounts.length);

    // ★ 判定"规律性":间隔必须稳定。标准差过大 = 随机消费,不是订阅。
    const variance = intervals.reduce((s, i) => s + (i - meanInterval) ** 2, 0) / intervals.length;
    const std = Math.sqrt(variance);

    let cadence: RecurringItem["cadence"] = "irregular";
    if (std <= Math.max(2, meanInterval * 0.2)) {
      if (meanInterval >= 26 && meanInterval <= 34) cadence = "monthly";
      else if (meanInterval >= 5 && meanInterval <= 9) cadence = "weekly";
      else if (meanInterval >= 340 && meanInterval <= 380) cadence = "yearly";
    }
    if (cadence === "irregular") continue;

    const monthlyEquivalent =
      cadence === "monthly" ? avgAmount : cadence === "weekly" ? round2((avgAmount * 30) / meanInterval) : round2(avgAmount / 12);

    const lastTs = sorted[sorted.length - 1]!.ts;
    // ★ 下次预计扣款:按日历推进,而不是粗暴 +30 天。
    //   房租每月 1 号扣,+30 天会算出"10月31日"(错一天);
    //   按月加一个自然月才能得到"11月1日"。
    const nextDate = new Date(lastTs);
    if (cadence === "monthly") nextDate.setMonth(nextDate.getMonth() + 1);
    else if (cadence === "weekly") nextDate.setDate(nextDate.getDate() + 7);
    else nextDate.setFullYear(nextDate.getFullYear() + 1);
    const expectedNext = nextDate.getTime();

    items.push({
      counterpartyName: name,
      category: sorted[0]!.category ?? "其他",
      count: sorted.length,
      avgAmount,
      intervalDays: Math.round(meanInterval * 10) / 10,
      cadence,
      monthlyEquivalent,
      firstTs: sorted[0]!.ts,
      lastTs,
      expectedNext,
    });
  }

  items.sort((a, b) => b.monthlyEquivalent - a.monthlyEquivalent);

  const monthlyTotal = round2(items.reduce((s, r) => s + r.monthlyEquivalent, 0));
  const summary =
    items.length === 0
      ? "未发现规律的定期支出。"
      : `发现 ${items.length} 项定期支出,每月合计约 ${monthlyTotal} 元。`;

  return { items, monthlyTotal, summary };
}

// ============================================================================
// 收支 / 现金流分析
// ============================================================================

export interface CashflowMonth {
  month: string;
  income: number;
  expense: number;
  net: number;
  savingsRate: number | null;
}

export interface CashflowReport {
  months: CashflowMonth[];
  totalIncome: number;
  totalExpense: number;
  totalNet: number;
  trend: "rising_expense" | "falling_expense" | "stable_expense" | "insufficient_data";
  summary: string;
}

export function buildCashflow(txs: Transaction[], monthCount: number, now: number): CashflowReport {
  const start = new Date(now);
  start.setDate(1);
  start.setHours(0, 0, 0, 0);
  start.setMonth(start.getMonth() - (monthCount - 1));

  const months: CashflowMonth[] = [];
  for (let i = 0; i < monthCount; i++) {
    const from = new Date(start);
    from.setMonth(start.getMonth() + i);
    const to = new Date(from);
    to.setMonth(from.getMonth() + 1);

    const inSum = txs.filter((t) => t.direction === "in" && t.ts >= from.getTime() && t.ts < to.getTime()).reduce((s, t) => s + t.amount, 0);
    const outSum = txs.filter((t) => t.direction === "out" && t.ts >= from.getTime() && t.ts < to.getTime()).reduce((s, t) => s + t.amount, 0);
    const net = inSum - outSum;

    months.push({
      month: fmtMonth(from.getTime()),
      income: round2(inSum),
      expense: round2(outSum),
      net: round2(net),
      savingsRate: inSum > 0 ? Math.round((net / inSum) * 1000) / 10 : null,
    });
  }

  const totalIncome = round2(months.reduce((s, m) => s + m.income, 0));
  const totalExpense = round2(months.reduce((s, m) => s + m.expense, 0));
  const totalNet = round2(totalIncome - totalExpense);

  // 支出趋势:首尾对比(排除当前未完整月份的影响)
  let trend: CashflowReport["trend"] = "insufficient_data";
  if (months.length >= 3) {
    const first = months[0]!.expense;
    const last = months[months.length - 1]!.expense;
    if (first <= 0) trend = "insufficient_data";
    else {
      const pct = (last - first) / first;
      trend = pct >= 0.15 ? "rising_expense" : pct <= -0.15 ? "falling_expense" : "stable_expense";
    }
  }

  const trendText: Record<CashflowReport["trend"], string> = {
    rising_expense: `支出呈上升趋势(首月 ${months[0]?.expense ?? 0} 元 → 末月 ${months[months.length - 1]?.expense ?? 0} 元)`,
    falling_expense: `支出呈下降趋势`,
    stable_expense: `支出整体平稳`,
    insufficient_data: `数据不足,暂无法判断趋势`,
  };

  const summary = `近 ${monthCount} 个月:收入合计 ${totalIncome} 元,支出合计 ${totalExpense} 元,净${totalNet >= 0 ? "结余" : "缺口"} ${Math.abs(totalNet)} 元;${trendText[trend]}。`;

  return { months, totalIncome, totalExpense, totalNet, trend, summary };
}

// ============================================================================
// 综合洞察
// ============================================================================

export interface Insight {
  type: "warning" | "info" | "suggestion";
  title: string;
  text: string;
  evidence?: string;
}

export interface InsightReport {
  insights: Insight[];
  summary: string;
}

export function buildInsights(txs: Transaction[], now: number): InsightReport {
  const insights: Insight[] = [];

  const from = now - 30 * DAY_MS;
  const recent = txs.filter((t) => t.ts >= from);

  // 1. 异常交易(复用异常识别)
  const anomalyReport = detectAnomalies(txs, now);
  const highAnomalies = anomalyReport.anomalies.filter((a) => a.severity === "high");
  if (highAnomalies.length > 0) {
    insights.push({
      type: "warning",
      title: "有交易需要您核实",
      text: `发现 ${highAnomalies.length} 笔可疑支出,建议优先处理`,
      evidence: highAnomalies.map((a) => a.title).join("、"),
    });
  }

  // 2. 定期支出盘点
  const out = txs.filter((t) => t.direction === "out");
  const recurring = detectRecurring(out, now);
  if (recurring.items.length > 0) {
    const entertainment = recurring.items.filter((r) => r.category === "文化娱乐");
    insights.push({
      type: "info",
      title: "定期支出盘点",
      text: `每月固定支出约 ${recurring.monthlyTotal} 元,共 ${recurring.items.length} 项`,
      evidence: recurring.items.slice(0, 4).map((r) => `${r.counterpartyName}(约${r.monthlyEquivalent}/月)`).join("、"),
    });
    if (entertainment.length >= 2) {
      insights.push({
        type: "suggestion",
        title: "订阅可能有重叠",
        text: `您有 ${entertainment.length} 项文化娱乐类订阅,建议检查是否有重复或闲置`,
        evidence: entertainment.map((r) => r.counterpartyName).join("、"),
      });
    }
  }

  // 3. 收支健康度
  const income = recent.filter((t) => t.direction === "in").reduce((s, t) => s + t.amount, 0);
  const expense = recent.filter((t) => t.direction === "out").reduce((s, t) => s + t.amount, 0);
  if (income > 0) {
    const rate = Math.round(((income - expense) / income) * 1000) / 10;
    if (rate < 0) {
      insights.push({
        type: "warning",
        title: "本月入不敷出",
        text: `近 30 天支出 ${round2(expense)} 元,超出收入 ${round2(income)} 元`,
        evidence: "优先检查大额支出与订阅",
      });
    } else if (rate < 20) {
      insights.push({
        type: "info",
        title: "储蓄率偏低",
        text: `近 30 天储蓄率 ${rate}%,低于 20% 健康线`,
      });
    }
  }

  // 4. 住房负担(住房物业类 vs 月收入)
  const housing = recent
    .filter((t) => t.direction === "out" && (t.category === "住房物业"))
    .reduce((s, t) => s + t.amount, 0);
  const monthlyIncome = recent.filter((t) => t.direction === "in").reduce((s, t) => s + t.amount, 0);
  if (monthlyIncome > 0 && housing / monthlyIncome > 0.3) {
    insights.push({
      type: "info",
      title: "住房支出占比偏高",
      text: `近 30 天住房类支出 ${round2(housing)} 元,占收入的 ${Math.round((housing / monthlyIncome) * 100)}%`,
      evidence: "建议检查房租以外的水电物业账单",
    });
  }

  const summary =
    insights.length === 0
      ? "暂未发现需要关注的账单问题。"
      : `共 ${insights.length} 条账单洞察:${insights.filter((i) => i.type === "warning").length} 条提醒、${insights.filter((i) => i.type === "suggestion").length} 条建议。`;

  return { insights, summary };
}
