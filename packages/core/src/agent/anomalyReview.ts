/**
 * 异常复核:重扫的成本/风险权衡 + 误报撤回
 *
 * ★ 需求原话:"遇到异常时,Agent 自己权衡'重扫成本'和'遗漏风险',
 *   决定是否重新扫描或先检查是否有遗漏,不要无脑重试。"
 *
 *   为什么这件事值得单独做一层:
 *   真实系统里"再扫一遍"几乎总是被当成最省事的回答 —— 客户问"还有没有漏",
 *   系统就重扫一遍。但重扫有两个成本:①算一遍全量流水的时延与额度;
 *   ②如果这次和上次扫的是同一批数据,结果**必然一样**,客户得到的是"看起来认真、
 *   实际没有新信息"的假动作。
 *
 *   所以这里的判据是确定性的两项评分(不是模型拍脑袋):
 *     · 重扫成本(rescanCost):与上次扫描的条数、是否被截断、新增交易量相关;
 *     · 遗漏风险(omissionRisk):与截断、时间跨度、新增交易、未覆盖账户相关。
 *   两者比较得到四种处置:先扫一次 / 全量重扫 / 只扫增量 / 先查覆盖缺口。
 *
 * ★ 误报撤回同样要求"可核对":撤回必须绑定**一条补充证据**,
 *   并且明确列出"撤回了哪条、还有哪条要复核" —— 否则撤回就变成了"客户一说不满就消失"。
 */

import type { Anomaly } from "../capabilities/billAnalysis.ts";

export type AnomalyStatus = "open" | "withdrawn";

export interface ReviewedAnomaly {
  id: string;
  title: string;
  severity: Anomaly["severity"];
  amount: number;
  ts: number;
  counterpartyName: string;
  /** 判定依据(规则口径),撤回后仍保留 —— 否则"撤回"就无法解释 */
  basis: string;
  suggestedAction: string;
  status: AnomalyStatus;
  /** 撤回时客户给的补充证据 */
  evidence?: string;
  withdrawnAt?: number;
}

export interface ScanState {
  at: number;
  /** 上次扫描的窗口天数 */
  windowDays: number;
  /** 实际检查的笔数 */
  checkedCount: number;
  /** 是否触达了条数上限(意味着更早的交易没看) */
  truncated: boolean;
  anomalies: ReviewedAnomaly[];
}

export type ReviewDecisionKind = "scan_first" | "rescan" | "rescan_incremental" | "inspect_gaps";

export interface ReviewDecision {
  decision: ReviewDecisionKind;
  decisionLabel: string;
  rescanCost: { score: number; factors: string[] };
  omissionRisk: { score: number; factors: string[] };
  /** 上次扫描的覆盖缺口(人话) */
  gaps: string[];
  newTxCount: number;
  /** 为什么这样决定 —— 必须能讲给客户听 */
  reason: string;
}

const clamp = (n: number, lo = 0, hi = 100): number => Math.max(lo, Math.min(hi, Math.round(n)));

/** 异常 → 稳定 ID(界面与审计都用它指代同一条) */
export function anomalyIdOf(a: Anomaly, index: number): string {
  const tail = a.transactionId.replace(/[^a-zA-Z0-9]/g, "").slice(-6);
  return tail ? `AN-${tail}` : `AN-${index + 1}`;
}

/** 把 detect_anomalies 的结果转成可复核的记录 */
export function toReviewedAnomalies(anomalies: Anomaly[]): ReviewedAnomaly[] {
  return anomalies.map((a, i) => ({
    id: anomalyIdOf(a, i),
    title: a.title,
    severity: a.severity,
    amount: a.amount,
    ts: a.ts,
    counterpartyName: a.counterpartyName,
    basis: a.description,
    suggestedAction: a.suggestedAction,
    status: "open" as const,
  }));
}

/**
 * 权衡"重扫成本"与"遗漏风险"。
 *
 * 两项评分都只由**已知事实**推出(上次扫了多少、是否截断、之后新增几笔、过了多久),
 * 因此同一个输入永远得到同一个结论 —— 审计时能复现。
 */
export function decideReview(input: {
  scan: ScanState | null;
  now: number;
  /** 上次扫描之后新增的支出笔数 */
  newTxCount: number;
  /** 上次之后新出现资金往来的账户数(可选) */
  newAccountsTouched?: number;
}): ReviewDecision {
  const { scan, now, newTxCount } = input;
  const newAccounts = input.newAccountsTouched ?? 0;

  if (!scan) {
    return {
      decision: "scan_first",
      decisionLabel: "先扫一次",
      rescanCost: { score: 20, factors: ["还没有扫描记录,无法增量"] },
      omissionRisk: { score: 50, factors: ["从未检查过,遗漏风险未知"] },
      gaps: ["还没有做过异常扫描"],
      newTxCount,
      reason: "没有上次扫描可比对,先完整扫一次才有判断依据。",
    };
  }

  const hoursSince = Math.max(0, (now - scan.at) / (3600 * 1000));
  const daysSince = hoursSince / 24;

  // ---- 重扫成本 ----
  const costFactors: string[] = [];
  let cost = 25;
  costFactors.push(`基础读取成本 25(需要把窗口内的流水重新过一遍)`);
  const volumeCost = Math.min(35, scan.checkedCount / 6);
  cost += volumeCost;
  costFactors.push(`上次检查 ${scan.checkedCount} 笔 → +${Math.round(volumeCost)}`);
  if (scan.truncated) {
    cost += 15;
    costFactors.push("上次已触达条数上限,重扫要放宽上限 → +15");
  }
  const newCost = Math.min(20, newTxCount * 2);
  if (newCost > 0) {
    cost += newCost;
    costFactors.push(`新增 ${newTxCount} 笔需要一并检查 → +${Math.round(newCost)}`);
  }

  // ---- 遗漏风险 ----
  const riskFactors: string[] = [];
  let risk = 0;
  if (scan.truncated) {
    risk += 30;
    riskFactors.push("上次只扫了最近的交易(已达上限),更早的可能没看 → +30");
  }
  if (newTxCount > 0) {
    const r = Math.min(30, newTxCount * 3);
    risk += r;
    riskFactors.push(`上次之后又有 ${newTxCount} 笔新交易没查过 → +${Math.round(r)}`);
  }
  if (newAccounts > 0) {
    risk += Math.min(15, newAccounts * 10);
    riskFactors.push(`有 ${newAccounts} 个账户上次没覆盖 → +${Math.min(15, newAccounts * 10)}`);
  }
  if (daysSince >= 1) {
    risk += Math.min(20, Math.floor(daysSince) * 5);
    riskFactors.push(`距上次检查已 ${Math.floor(daysSince)} 天 → +${Math.min(20, Math.floor(daysSince) * 5)}`);
  }
  if (riskFactors.length === 0) riskFactors.push("上次覆盖完整、之后无新交易 → 遗漏风险低");

  const costScore = clamp(cost);
  const riskScore = clamp(risk);

  // ---- 覆盖缺口 ----
  const gaps: string[] = [];
  if (scan.truncated) gaps.push(`上次只看了最近 ${scan.checkedCount} 笔,更早的交易未覆盖`);
  if (scan.windowDays < 90) gaps.push(`上次只看近 ${scan.windowDays} 天,更早的账单没查`);
  if (newAccounts > 0) gaps.push(`有 ${newAccounts} 个账户未纳入上次扫描`);
  if (gaps.length === 0) gaps.push("上次扫描的窗口与账户覆盖完整");

  // ---- 决策 ----
  let decision: ReviewDecisionKind;
  let reason: string;
  if (riskScore >= 60) {
    decision = "rescan";
    reason = `遗漏风险 ${riskScore} 已明显高于重扫成本 ${costScore}:值得完整重扫一遍。`;
  } else if (costScore >= 55 && riskScore < 40) {
    decision = "inspect_gaps";
    reason =
      `重扫成本 ${costScore} 高于遗漏风险 ${riskScore}:上次扫的是同一批数据,` +
      `重扫一遍结果不会变。先补上次没覆盖的部分更划算。`;
  } else if (riskScore >= 25) {
    decision = "rescan_incremental";
    reason =
      `遗漏风险 ${riskScore} 中等、重扫成本 ${costScore} 也不低:只扫上次之后的新增部分,` +
      `不必全量重来。`;
  } else {
    decision = "inspect_gaps";
    reason = `遗漏风险 ${riskScore} 低:上次覆盖已够,先看有没有真的漏项即可。`;
  }

  const label: Record<ReviewDecisionKind, string> = {
    scan_first: "先扫一次",
    rescan: "完整重扫",
    rescan_incremental: "只扫新增",
    inspect_gaps: "先查缺口,不重扫",
  };

  return {
    decision,
    decisionLabel: label[decision],
    rescanCost: { score: costScore, factors: costFactors },
    omissionRisk: { score: riskScore, factors: riskFactors },
    gaps,
    newTxCount,
    reason,
  };
}

/**
 * 找到客户想撤回的那条异常。
 *
 * 支持三种指代(按可靠性从高到低):序号 → 金额 → 对手方。
 * 找不到或指向多条时**返回 null 让上层追问**,而不是猜一条撤掉 ——
 * 撤回错了会让真正的风险被"洗白",比不撤回严重得多。
 */
export function resolveAnomaly(
  anomalies: ReviewedAnomaly[],
  text: string,
): { hit: ReviewedAnomaly } | { ambiguous: ReviewedAnomaly[] } | { none: true } {
  const open = anomalies.filter((a) => a.status === "open");
  if (open.length === 0) return { none: true };

  const ordinal = text.match(/第\s*([0-9一二三四五六七八九十]+)\s*(条|笔|个)/);
  if (ordinal) {
    const map: Record<string, number> = { 一: 1, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9, 十: 10 };
    const raw = ordinal[1]!;
    const idx = /^\d+$/.test(raw) ? Number(raw) : (map[raw] ?? 0);
    const hit = open[idx - 1];
    return hit ? { hit } : { none: true };
  }

  const amounts = [...text.matchAll(/(\d[\d,]*(?:\.\d+)?)/g)]
    .map((m) => Number(m[1]!.replace(/,/g, "")))
    .filter((n) => Number.isFinite(n) && n > 0);
  if (amounts.length > 0) {
    const hits = open.filter((a) => amounts.some((n) => Math.abs(a.amount - n) < 0.01));
    if (hits.length === 1) return { hit: hits[0]! };
    if (hits.length > 1) return { ambiguous: hits };
  }

  const byName = open.filter((a) => a.counterpartyName && text.includes(a.counterpartyName));
  if (byName.length === 1) return { hit: byName[0]! };
  if (byName.length > 1) return { ambiguous: byName };

  if (open.length === 1) return { hit: open[0]! };
  return { ambiguous: open };
}
