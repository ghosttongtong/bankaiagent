/**
 * 来源标注(Provenance)
 *
 * 需求原话:"回答涉及金额或规则时,标注来源、时效、主体、计算过程。"
 *
 * ★ 为什么值得单独做一层,而不是在每个回复里手写一句"数据来源:xxx":
 *
 *   1. **手写的出处会漂移。** 一旦口径改了(比如账单从"近 30 天"改成"自然月"),
 *      十几处硬编码的说明总会漏改一两处,而漏掉的那一处恰好是客户截图投诉的那一处。
 *      这里把口径与数字**一起**产生:能力在执行时把"我用了哪张表、查了哪段时间、
 *      几笔、怎么加起来的"登记进来,渲染时统一输出。
 *
 *   2. **规则也要有出处。** 客户问"凭什么要我人脸验证",回答"系统判定"是不可接受的;
 *      要能说出命中了哪条规则、规则约束的是谁、什么时候生效。规则与数据在
 *      客户眼里都是"你说的话",凭什么信你 —— 出处就是凭据。
 *
 *   3. **计算过程必须可复现。** `计算:[餐饮 1,240.00, 交通 380.50] → 合计 1,620.50`
 *      这种写法让客户(和审计员)能自己把数字加一遍。加得起来,才叫可信。
 */

import { randomUUID } from "node:crypto";

import { fmtMoney } from "../util/format.ts";
import type { PolicyReason } from "../types.ts";
import type { SourceCitation } from "./turnExtras.ts";

// ============================================================================
// 时间与金额口径
// ============================================================================

const TZ = "Asia/Shanghai";

/** 东八区"今天"的年月日 */
export function shanghaiParts(ts: number): { y: number; m: number; d: number } {
  const s = new Date(ts).toLocaleDateString("en-CA", { timeZone: TZ }); // YYYY-MM-DD
  const [y, m, d] = s.split("-").map((x) => Number(x));
  return { y: y ?? 1970, m: m ?? 1, d: d ?? 1 };
}

/** 2026-10-16 */
export function dayText(ts: number): string {
  const { y, m, d } = shanghaiParts(ts);
  return `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

/** 本月起点(东八区自然月)与"截至现在" */
export function monthRange(now: number): { from: number; to: number; label: string } {
  const { y, m } = shanghaiParts(now);
  // 东八区 00:00 对应 UTC 前一天 16:00
  const from = Date.UTC(y, m - 1, 1, 0, 0, 0) - 8 * 3600 * 1000;
  return { from, to: now, label: `本月(${y}-${String(m).padStart(2, "0")}-01 ~ 至今)` };
}

/** 两位小数金额(口径见 util/format.ts,单一实现) */
export function moneyText(v: number): string {
  return fmtMoney(v);
}

// ============================================================================
// 收集器
// ============================================================================

/**
 * 本轮的来源收集器。
 *
 * 由编排器每轮创建一个,交给能力使用;回合出口统一渲染。
 * 接口刻意做得很小:只有"登记一条来源"这一个动作。
 */
export class ProvenanceCollector {
  private readonly items = new Map<string, SourceCitation>();
  private readonly now: () => number;

  constructor(now: () => number) {
    this.now = now;
  }

  /** 登记一条来源(同 id 只保留首次,避免重复刷屏) */
  cite(c: SourceCitation): void {
    if (!this.items.has(c.id)) this.items.set(c.id, c);
  }

  /**
   * 登记一个金额类数字。
   *
   * @param dataPoint 数据点名称,如「本月支出合计」
   * @param value     数值(用于展示与计算过程)
   */
  monetary(input: {
    dataPoint: string;
    value?: number;
    source: string;
    subject?: string;
    effective: string;
    calculation?: string[];
    note?: string;
    id?: string;
  }): void {
    const topic =
      input.value != null
        ? `${input.dataPoint} ${moneyText(input.value)} 元`
        : input.dataPoint;
    this.cite({
      id: input.id ?? `data:${input.dataPoint}`,
      topic,
      source: input.source,
      subject: input.subject ?? "客户本人",
      effective: input.effective,
      asOf: this.now(),
      ...(input.calculation && input.calculation.length > 0 ? { calculation: input.calculation } : {}),
      ...(input.note ? { note: input.note } : {}),
      kind: "data",
    });
  }

  /** 登记一条规则裁决(策略引擎、合规闸门等) */
  rule(reason: PolicyReason): void {
    const evidence = (reason as { evidence?: unknown }).evidence;
    this.cite({
      id: `rule:${reason.ruleId}`,
      topic: `${reason.ruleId} ${reason.message}`,
      source: "策略引擎(确定性规则库,零 LLM 参与)",
      subject: "本笔交易",
      effective: "规则版本 2026-01 · 命中即生效,没有管理员跳过路径",
      asOf: this.now(),
      kind: "rule",
      ...(evidence ? { note: `判定证据:${typeof evidence === "string" ? evidence : JSON.stringify(evidence)}` } : {}),
    });
  }

  /** 规则条目太多时只保留有解释价值的那些 */
  rules(reasons: PolicyReason[], limit = 4): void {
    /**
     * ★ 只过滤"纯内部计分"的规则(风险分、能力基线、渠道基线)。
     *
     *   这些是引擎内部的中间量,列给客户看毫无意义。
     *   但**降级类规则必须留下** —— 「为什么这笔只要确认、不用人脸」
     *   恰恰是客户最会问、也最该被正面回答的一件事;
     *   把它过滤掉,客户就只在自己被"升级"要求验证时看得到规则,
     *   于是规则在他眼里变成了"限制我的东西",而不是"保护我的东西"。
     */
    const skip = /^R-(RISK-SCORE|CAPABILITY-BASELINE|CHANNEL-BASELINE)/;
    for (const r of reasons.filter((x) => !skip.test(x.ruleId)).slice(0, limit)) this.rule(r);
  }

  /** 人工审批通道说明 —— 这条也是"规则",客户必须知道凭什么是人工审 */
  humanReview(input: {
    capability: string;
    lane: string;
    materials: string[];
    channel: string;
    sla: string;
    asOf?: number;
  }): void {
    this.cite({
      id: `human_review:${input.capability}`,
      topic: `人工审批要求(${input.lane})`,
      source: "银行业务规则库 · 人工审批事项清单",
      subject: "本笔申请",
      effective: input.sla,
      asOf: input.asOf ?? this.now(),
      kind: "rule",
      calculation: input.materials.map((m, i) => `${i + 1}. ${m}`),
      note: `受理通道:${input.channel}`,
    });
  }

  list(): SourceCitation[] {
    return [...this.items.values()].sort((a, b) => {
      // 数据类在前(客户最关心数字),规则类在后
      if (a.kind !== b.kind) return a.kind === "data" ? -1 : 1;
      return a.topic.localeCompare(b.topic, "zh-CN");
    });
  }

  get size(): number {
    return this.items.size;
  }

  /** 供审计留痕:本轮回写了哪些出处 */
  toAuditPayload(): Array<Record<string, unknown>> {
    return this.list().map((c) => ({
      id: c.id,
      topic: c.topic,
      source: c.source,
      subject: c.subject,
      effective: c.effective,
      asOf: c.asOf,
      kind: c.kind,
      ...(c.calculation ? { calculation: c.calculation } : {}),
    }));
  }
}

// ============================================================================
// 常用来源模板(把口径写在一处,避免各处漂移)
// ============================================================================

export const SOURCES = {
  ledger: "银行核心系统 · 交易流水(已清算)",
  accounts: "银行核心系统 · 账户主档",
  cards: "银行核心系统 · 卡账户(与 App 展示同源)",
  wealth: "银行核心系统 · 理财产品库与净值表",
  products: "银行核心系统 · 产品说明书与费率表",
  schedule: "银行核心系统 · 定时转账指令表",
  bill: "银行核心系统 · 交易流水 + 账单分析纯函数引擎",
  policy: "策略引擎(确定性规则库,零 LLM 参与)",
  audit: "审计哈希链(逐条可校验)",
} as const;

/** 生成一个稳定的引用 ID(供自定义来源使用) */
export function citationId(prefix: string): string {
  return `${prefix}:${randomUUID().slice(0, 8)}`;
}
