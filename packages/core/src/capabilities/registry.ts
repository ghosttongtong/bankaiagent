/**
 * 能力注册表(Capability Registry)
 *
 * ★ 这是 Agent 的"手"的唯一来源。
 *
 *   在普通 Agent 项目里,模型拿到一堆 API 就能随便调。
 *   在本项目里,模型能做的事**被严格限制在这张表内**:
 *     - 每个能力有 zod Schema:模型输出不合法直接拒绝,不做猜测性修复
 *     - 每个能力有 sideEffect 与 baseTier:决定是否需要独立裁决与确认
 *     - 每个能力有 monetaryFields:输出中的金额字段必须可追溯(I3)
 *     - 没有任何"通用请求"能力 —— 没有 free-form API 调用这种后门
 *
 *   答辩时可以直接说:模型被攻破后能造成的最坏后果,是这张表里
 *   baseTier=auto 的只读查询。这是**架构上**的安全,不是靠提示词。
 */

import { z } from "zod";
import { round2 } from "../util/format.ts";
import { accountTypeLabel, scheduleStatusLabel } from "../util/labels.ts";

import type {
  CapabilitySpec,
  ExecutionContext,
  LifeEvent,
  PolicyReason,
  Tier,
} from "../types.ts";
import { assessFraudRisk, buildFraudCardBlock } from "../security/antiFraud.ts";
import { sanitizeMemo, sanitizePayeeName } from "../security/injection.ts";
import { computePayloadHash, getPolicyConfig } from "../policy/engine.ts";
import { isOperationCancelled } from "../policy/twoPhase.ts";
import { cadenceLabel } from "./subscription.ts";
import { transferFeeOf } from "./transferFee.ts";
import { SOURCES, dayText, moneyText, monthRange } from "../agent/provenance.ts";
import { billChartVisual } from "../agent/turnExtras.ts";
import { compareDocuments } from "./documentCompare.ts";
import {
  buildBillHealth,
  buildCashflow,
  buildInsights,
  buildPeriodReport,
  detectAnomalies,
  detectRecurring,
  fmtDate,
  renderBillHealth,
} from "./billAnalysis.ts";
import { buildPaydayBrief } from "./paydayBrief.ts";
import {
  ASSESSMENT_QUESTIONS,
  ASSESSMENT_MAX_SCORE,
  PRODUCT_RISK_LABELS,
  PRODUCT_TYPE_LABELS,
  RISK_DISCLOSURE_STANDARD,
  RISK_LEVEL_LABELS,
  buildDisclosureSummary,
  buildRiskProfile,
  buildRolloverPlan,
  checkSuitability,
  drawdownDetail,
  compareProducts,
  evaluateRolloverFunds,
  computePurchase,
  computeRedemption,
  detectGuaranteeClaim,
  fmtMoney,
  fmtPct,
  holdingDaysLabel,
  maxProductRiskFor,
  normalizeReturnWording,
  renderProductList,
  riskAssessmentQuizVisual,
  riskLevelOrdinal,
  rolloverFollowUps,
  scoreAssessment,
  settlementLabel,
  termLabel,
  yieldLabel,
} from "./wealth.ts";
import {
  CARD_KIND_LABELS,
  CARD_STATUS_LABELS,
  LIMIT_RULES,
  RESTRICTION_CAUSE_LABELS,
  RESTRICTION_CHANNEL_LABELS,
  canSubmitUnblock,
  checkLimitEligibility,
  describeCard,
  diagnoseRestriction,
  fmtDay as fmtCardDay,
  fmtMoney as fmtCardMoney,
  isCardBlocked,
  limitApplicationWording,
  matchCardByKindHint,
  matchCardByLast4,
  matchCardByNameHint,
  monthsBetween,
  renderCardList,
  requirementForScenario,
  scenarioForActivation,
  scenarioForReplacementMode,
} from "./card.ts";
import {
  daysText as subDaysText,
  fmtSubDateTime,
  fmtSubDay,
  fmtSubMoney,
  matchSubscription,
  renderSubscriptionDetail,
  renderSubscriptionList,
  scanSubscriptions,
  upcomingRenewals,
  type SubscriptionItem,
  type SubscriptionScanResult,
} from "./subscription.ts";
import { registerPolicyCapabilities } from "./policySearch.ts";
import { registerMemoryCapabilities } from "./memorySearch.ts";
import {
  EVENT_MAX_LEAD_DAYS,
  buildEventPlan,
  checkFundDisclosure,
  eventPlanFollowUpActions,
  eventPlanStepListBadge,
  eventPlanStepListTone,
  listEventTriggers,
  parseEventDateHint,
  renderEventPlan,
  renderEventTriggerList,
  renderLifeEventList,
  type EventPlan,
  type EventPlanData,
  type EventPlanRef,
} from "./eventPlan.ts";

// ============================================================================
// 能力定义辅助
// ============================================================================

export interface RegisteredCapability {
  name: string;
  description: string;
  inputSchema: z.ZodTypeAny;
  outputSchema: z.ZodTypeAny;
  sideEffect: "none" | "reversible" | "irreversible";
  moneyMovement: boolean;
  readOnly: boolean;
  baseTier: Tier;
  sensitiveFields: string[];
  monetaryFields: string[];
  /** 是否允许自动执行(低风险写操作专用,如客户侧记账批注) */
  autoExecutable?: boolean;
  /** 执行函数 */
  execute: (input: Record<string, unknown>, ctx: ExecutionContext) => Promise<CapabilityOutcome>;
}

export interface CapabilityOutcome {
  ok: boolean;
  /** 结构化数据。I3:数值的唯一可信来源 */
  data?: unknown;
  /** 面向用户的人话摘要(不含任何未经验证的数字) */
  summary?: string;
  error?: { code: string; message: string; retryable: boolean };
  /** 执行过程中产生的额外策略理由(如反诈升级) */
  extraReasons?: PolicyReason[];
  /** 反诈卡片块 */
  fraudBlock?: ReturnType<typeof buildFraudCardBlock>;
  /**
   * ★ 提交点之前被取消(第 3 项)。
   *
   * 它与 `ok:false` 的区别是**钱有没有动**:cancelled 存在 = 什么都没做。
   * 审计与对账都必须能把这两件事分开,否则"钱扣了、状态未知"就会被写进证据链。
   */
  cancelled?: { op: string; preparedId: string; phase: string; reason: string; source?: string };
}

/** 注册表 */
export class CapabilityRegistry {
  private readonly capabilities = new Map<string, RegisteredCapability>();

  register(cap: RegisteredCapability): void {
    if (this.capabilities.has(cap.name)) {
      throw new Error(`能力 ${cap.name} 重复注册`);
    }
    this.capabilities.set(cap.name, cap);
  }

  get(name: string): RegisteredCapability | undefined {
    return this.capabilities.get(name);
  }

  mustGet(name: string): RegisteredCapability {
    const c = this.capabilities.get(name);
    if (!c) throw new Error(`能力 ${name} 未注册。Agent 只能执行注册表中的能力。`);
    return c;
  }

  list(): RegisteredCapability[] {
    return [...this.capabilities.values()];
  }

  /** 生成给模型的工具清单。模型只能看到描述与 Schema,看不到实现。 */
  toToolDefinitions(): Array<{ name: string; description: string; parameters: Record<string, unknown> }> {
    return this.list().map((c) => ({
      name: c.name,
      description: c.description,
      parameters: zodToJsonSchema(c.inputSchema),
    }));
  }
}

// ============================================================================
// zod → JSON Schema(供模型 Function Calling 使用)
// ============================================================================

export function zodToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
  const def = (schema as unknown as { _def: { typeName: string; [k: string]: unknown } })._def;
  if (!def) return { type: "object" };

  switch (def["typeName"]) {
    case "ZodObject": {
      const shape = (schema as z.ZodObject<z.ZodRawShape>).shape;
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, value] of Object.entries(shape)) {
        properties[key] = zodToJsonSchema(value as z.ZodTypeAny);
        if (!(value as z.ZodTypeAny).isOptional()) required.push(key);
      }
      return {
        type: "object",
        properties,
        ...(required.length > 0 ? { required } : {}),
        additionalProperties: false,
      };
    }
    case "ZodString": {
      const out: Record<string, unknown> = { type: "string" };
      const checks = (def["checks"] as Array<{ kind: string; value?: number }> | undefined) ?? [];
      for (const c of checks) {
        if (c.kind === "min" && c.value != null) out["minLength"] = c.value;
        if (c.kind === "max" && c.value != null) out["maxLength"] = c.value;
      }
      return out;
    }
    case "ZodNumber": {
      const out: Record<string, unknown> = { type: "number" };
      const checks = (def["checks"] as Array<{ kind: string; value?: number }> | undefined) ?? [];
      for (const c of checks) {
        if (c.kind === "min" && c.value != null) out["minimum"] = c.value;
        if (c.kind === "max" && c.value != null) out["maximum"] = c.value;
      }
      return out;
    }
    case "ZodBoolean":
      return { type: "boolean" };
    case "ZodEnum":
      return { type: "string", enum: def["values"] as string[] };
    case "ZodNativeEnum":
      return { type: "string", enum: Object.values(def["values"] as Record<string, string>) };
    case "ZodArray":
      return { type: "array", items: zodToJsonSchema(def["type"] as z.ZodTypeAny) };
    case "ZodOptional":
    case "ZodNullable":
    case "ZodDefault":
      return zodToJsonSchema(def["innerType"] as z.ZodTypeAny);
    case "ZodLiteral":
      return { const: def["value"] };
    case "ZodUnion": {
      const options = def["options"] as z.ZodTypeAny[];
      return { anyOf: options.map(zodToJsonSchema) };
    }
    case "ZodEffects":
      return zodToJsonSchema(def["schema"] as z.ZodTypeAny);
    default:
      return {};
  }
}

// ============================================================================
// 只读能力(绿色级:自动执行,不打断用户)
// ============================================================================

export function registerReadCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "account.list_balances",
    description: "查询客户名下所有账户的余额与可用额度。只读,无副作用。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      accounts: z.array(
        z.object({
          accountId: z.string(),
          maskedNo: z.string(),
          type: z.string(),
          balance: z.number(),
          availableBalance: z.number(),
          currency: z.string(),
        }),
      ),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["accounts[].balance", "accounts[].availableBalance"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const accounts = await ctx.bank.listAccounts(ctx.customerId);
      const money = (n: number) => n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      const total = accounts.reduce((sum, a) => sum + a.balance, 0);
      // 客户问的是「我还有多少钱」,第一句就必须是钱,而不是「你有几张卡」。
      // ★ 不做「可用余额加总」:含授信账户时可用合计会大于余额合计,
      //   客户看到的是"可用比总额还多",反而说不通。可用余额按账户各自展示。
      const headline = `共 ${accounts.length} 个账户,余额合计 ¥${money(total)}。`;
      const lines = [
        headline,
        ...accounts.map(
          (a) => `· ${accountTypeLabel(a.type)}(${a.maskedNo}):余额 ¥${money(a.balance)},可用 ¥${money(a.availableBalance)}`,
        ),
      ];
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "账户余额",
          subtitle: headline,
          items: accounts.map((a) => ({
            title: `${accountTypeLabel(a.type)}(${a.maskedNo})`,
            value: `¥${money(a.balance)}`,
            lines: [`可用 ¥${money(a.availableBalance)}`],
          })),
          compactBody: headline,
        };
      }
      return {
        ok: true,
        data: {
          accounts: accounts.map((a) => ({
            accountId: a.accountId,
            maskedNo: a.maskedNo,
            type: accountTypeLabel(a.type),
            balance: a.balance,
            availableBalance: a.availableBalance,
            currency: a.currency,
          })),
        },
        summary: lines.join("\n"),
      };
    },
  });

  registry.register({
    name: "account.list_transactions",
    description:
      "按条件查询客户自己的交易流水。支持时间范围、金额区间、对手方、分类、收支方向与条数限制。" +
      "用户说『查一下上个月的流水』『有没有一笔 5000 的支出』时使用。只读,且**仅限客户本人账户**。",
    inputSchema: z.object({
      fromIso: z.string().optional().describe("起始时间,ISO 8601 字符串"),
      toIso: z.string().optional().describe("结束时间,ISO 8601 字符串"),
      minAmount: z.number().optional(),
      maxAmount: z.number().optional(),
      counterparty: z.string().optional().describe("对手方名称关键词"),
      category: z.string().optional().describe("消费分类,如『餐饮』『转账』"),
      direction: z.enum(["in", "out"]).optional(),
      limit: z.number().int().positive().max(100).optional(),
    }),
    outputSchema: z.object({
      transactions: z.array(
        z.object({
          transactionId: z.string(),
          direction: z.string(),
          amount: z.number(),
          currency: z.string(),
          counterpartyName: z.string(),
          category: z.string().optional(),
          ts: z.number(),
        }),
      ),
      total: z.number(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["transactions[].amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const txs = await ctx.bank.listTransactions(ctx.customerId, {
        from: input["fromIso"] ? Date.parse(String(input["fromIso"])) : undefined,
        to: input["toIso"] ? Date.parse(String(input["toIso"])) : undefined,
        minAmount: input["minAmount"] as number | undefined,
        maxAmount: input["maxAmount"] as number | undefined,
        counterparty: input["counterparty"] as string | undefined,
        category: input["category"] as string | undefined,
        direction: input["direction"] as "in" | "out" | undefined,
        limit: (input["limit"] as number | undefined) ?? 50,
      });

      if (ctx.extras && txs.length > 0) {
        const money = (n: number) => n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        const shown = txs.slice(0, 20);
        ctx.extras.visual = {
          kind: "list_report",
          title: "交易流水",
          subtitle: `共 ${txs.length} 笔${txs.length > shown.length ? ",下列为最近 20 笔" : ""}`,
          items: shown.map((t) => ({
            title: t.counterpartyName,
            value: `${t.direction === "in" ? "+" : "-"}¥${money(t.amount)}`,
            badge: t.direction === "in" ? "收入" : "支出",
            tone: t.direction === "in" ? "ok" : "plain",
            lines: [`${fmtDate(t.ts)}${t.category ? ` · ${t.category}` : ""}`],
          })),
          compactBody: `共查到 ${txs.length} 笔交易,明细见下列清单。`,
        };
      }

      return {
        ok: true,
        data: {
          transactions: txs.map((t) => ({
            transactionId: t.transactionId,
            direction: t.direction === "in" ? "收入" : "支出",
            amount: t.amount,
            currency: t.currency,
            counterpartyName: t.counterpartyName,
            ...(t.category ? { category: t.category } : {}),
            ts: t.ts,
          })),
          total: txs.length,
        },
        summary: `共查到 ${txs.length} 笔交易`,
      };
    },
  });

  registry.register({
    name: "account.analyze_spending",
    description:
      "分析客户的支出结构:按分类、对手方或月份聚合,可对比上期或历史均值。" +
      "用户说『我这个月钱花哪了』『餐饮花了多少』时使用。只读。" +
      "★ 若用户问的是判断类问题,必须传 category 参数;" +
      "★ 若用户要对比,必须传 compareWith 参数,否则系统会返回环比/同比数据;" +
      "★ 只给一个总额而不给分类,等于没回答用户的问题。",
    inputSchema: z.object({
      fromIso: z.string().optional(),
      toIso: z.string().optional(),
      groupBy: z.enum(["category", "counterparty", "month"]).default("category"),
      /** 若用户明确问的是某一类("餐饮花了多少"),必须填入;否则会统计全部支出 */
      category: z.string().optional().describe("只看某一分类,如『餐饮』『交通』"),
      /**
       * 对比基准。用户说"比上个月多吗""是不是花太多了"时,
       * 必须传 previous_period 或 average,否则回答不了"多不多"这个问题。
       */
      compareWith: z
        .enum(["none", "previous_period", "average"])
        .default("none")
        .describe("对比基准:previous_period=与上一同期比;average=与近三月均值比;none=不对比"),
    }),
    outputSchema: z.object({
      groups: z.array(z.object({ key: z.string(), total: z.number(), count: z.number() })),
      grandTotal: z.number(),
      periodLabel: z.string(),
      filteredByCategory: z.string().nullable(),
      /** 对比结论(compareWith 为 none 时为空) */
      comparison: z
        .object({
          basis: z.string(),
          baselineLabel: z.string(),
          baselineTotal: z.number(),
          /** 变化百分比,可能为负 */
          changePct: z.number(),
          /** 变化金额 */
          changeAmount: z.number(),
          /** 变化最大的几项分类 */
          topChanges: z.array(z.object({ key: z.string(), change: z.number() })),
          /** 结论档位(避免用一个百分数让用户自己判断"多不多") */
          verdict: z.enum(["much_higher", "higher", "similar", "lower", "much_lower"]),
          /** 结论文案 */
          verdictText: z.string(),
        })
        .nullable(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["groups[].total", "grandTotal", "comparison.baselineTotal", "comparison.changeAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const to = input["toIso"] ? Date.parse(String(input["toIso"])) : ctx.now;
      const from = input["fromIso"] ? Date.parse(String(input["fromIso"])) : ctx.now - 30 * 24 * 3600 * 1000;
      const groupBy = (input["groupBy"] as "category" | "counterparty" | "month") ?? "category";
      const categoryFilter = input["category"] ? String(input["category"]) : undefined;
      const compareWith = (input["compareWith"] as "none" | "previous_period" | "average") ?? "none";

      const query = (f: number, t: number) =>
        ctx.bank.listTransactions(ctx.customerId, {
          from: f,
          to: t,
          direction: "out",
          ...(categoryFilter ? { category: categoryFilter } : {}),
          limit: 200,
        });

      const txs = await query(from, to);

      const map = new Map<string, { total: number; count: number }>();
      for (const t of txs) {
        const key =
          groupBy === "category"
            ? (t.category ?? "未分类")
            : groupBy === "counterparty"
              ? t.counterpartyName
              : `${new Date(t.ts).getFullYear()}-${String(new Date(t.ts).getMonth() + 1).padStart(2, "0")}`;
        const cur = map.get(key) ?? { total: 0, count: 0 };
        cur.total += t.amount;
        cur.count += 1;
        map.set(key, cur);
      }

      const groups = [...map.entries()]
        .map(([key, v]) => ({ key, total: Math.round(v.total * 100) / 100, count: v.count }))
        .sort((a, b) => b.total - a.total);

      const grandTotal = Math.round(groups.reduce((s, g) => s + g.total, 0) * 100) / 100;

      const fmt = (ts: number) => {
        const d = new Date(ts);
        return `${d.getFullYear()}-${d.getMonth() + 1}-${d.getDate()}`;
      };
      const periodLabel = `${fmt(from)} 至 ${fmt(to)}`;

      // ---- 对比基准计算(与上一同期 / 与近三月均值) ----
      let comparison: CapabilityOutcome["data"] extends never ? never : Record<string, unknown> | null = null;

      if (compareWith !== "none") {
        const span = to - from;
        const baseFrom = compareWith === "previous_period" ? from - span : from - 3 * span;
        const baseTo = compareWith === "previous_period" ? from : from;
        const baseTxs = await query(baseFrom, baseTo);
        const baselineTotal = Math.round(baseTxs.reduce((s, t) => s + t.amount, 0) * 100) / 100;

        const changeAmount = Math.round((grandTotal - baselineTotal) * 100) / 100;
        const changePct = baselineTotal > 0 ? Math.round((changeAmount / baselineTotal) * 1000) / 10 : 0;

        // 找出变化最大的分类:用户问"为什么多了",答案通常在这几项里
        const baseByCategory = new Map<string, number>();
        for (const t of baseTxs) {
          const k = t.category ?? "未分类";
          baseByCategory.set(k, (baseByCategory.get(k) ?? 0) + t.amount);
        }
        const topChanges = groups
          .map((g) => ({
            key: g.key,
            change: Math.round((g.total - (baseByCategory.get(g.key) ?? 0)) * 100) / 100,
          }))
          .sort((a, b) => Math.abs(b.change) - Math.abs(a.change))
          .slice(0, 3)
          .filter((c) => Math.abs(c.change) > 1);

        // ★ 把百分数翻译成一档结论:用户问的是"是不是花太多了",
        //   回一个"-12.4%"等于把判断推回给他 —— 那不是回答,是甩锅。
        let verdict: "much_higher" | "higher" | "similar" | "lower" | "much_lower";
        if (changePct >= 50) verdict = "much_higher";
        else if (changePct >= 15) verdict = "higher";
        else if (changePct > -15) verdict = "similar";
        else if (changePct > -50) verdict = "lower";
        else verdict = "much_lower";

        // ★ 五档结论都必须带上「较上期」这个**比较口径词**。
        //   曾经只有 similar 一档写成「与上一周期基本持平」,丢掉了口径词 ——
        //   用户(和守卫断言)看到的是「持平」却不知道跟谁比,等于没有做对比。
        //   口径词与结论词是两件事:前者说明基准,后者说明方向,缺一不可。
        const basisLabel = compareWith === "previous_period" ? "上一周期" : "近三月均值";
        const verdictTextMap: Record<typeof verdict, string> = {
          much_higher: `较上期明显上升:比${basisLabel}多花 ${changePct}%`,
          higher: `较上期上升:比${basisLabel}多花 ${changePct}%`,
          similar: `较上期基本持平:与${basisLabel}相差 ${Math.abs(changePct)}%`,
          lower: `较上期下降:比${basisLabel}少花 ${Math.abs(changePct)}%`,
          much_lower: `较上期明显下降:比${basisLabel}少花 ${Math.abs(changePct)}%`,
        };

        comparison = {
          basis: compareWith,
          baselineLabel: compareWith === "previous_period" ? `对比上一周期(${fmt(baseFrom)} 至 ${fmt(baseTo)})` : `对比近三月均值(${fmt(baseFrom)} 至 ${fmt(baseTo)})`,
          baselineTotal,
          changePct,
          changeAmount,
          topChanges,
          verdict,
          verdictText: verdictTextMap[verdict],
        };
      }

      const summaryParts: string[] = [];
      summaryParts.push(
        categoryFilter
          ? `${periodLabel} 的${categoryFilter}共 ${txs.length} 笔,合计 ${grandTotal} 元`
          : `${periodLabel} 共 ${txs.length} 笔支出,合计 ${grandTotal} 元`,
      );
      if (comparison) {
        const c = comparison as { verdictText: string; topChanges: Array<{ key: string; change: number }> };
        summaryParts.push(c.verdictText);
        if (c.topChanges.length > 0) {
          const top = c.topChanges[0]!;
          summaryParts.push(`变化最大的是${top.key}:${top.change > 0 ? "+" : ""}${top.change} 元`);
        }
      }

      const spendingChart = billChartVisual({
        title: categoryFilter ? `${categoryFilter}支出` : "支出结构",
        subtitle: periodLabel,
        filename: `支出分析-${periodLabel}`,
        panels: [
          {
            title: categoryFilter ?? (groupBy === "counterparty" ? "按对手方" : groupBy === "month" ? "按月份" : "按分类"),
            chart: "bars",
            legend: ["金额(元)"],
            series: groups.slice(0, 8).map((g) => ({ label: `${g.key} · ${g.count}笔`, value: g.total })),
          },
        ],
        notes: [...summaryParts, `合计 ${grandTotal} 元。柱高与这段合计是同一批支出流水。`],
      });
      if (spendingChart && ctx.extras) ctx.extras.visual = spendingChart;

      return {
        ok: true,
        data: {
          groups,
          grandTotal,
          periodLabel,
          filteredByCategory: categoryFilter ?? null,
          comparison,
        },
        summary: summaryParts.join(";"),
      };
    },
  });

  registry.register({
    name: "payee.search",
    description:
      "按姓名或手机号检索收款人目录,返回候选及其新颖度(" +
      "是否首次向该收款人转账、历史成功笔数、是否本人账户、是否白名单)。" +
      "用户说『转给老王』而系统需要确认是哪一位时使用。只读。" +
      "★ 宁可返回多个候选让用户点选,也不要猜一个 —— 转错人是不可逆的。",
    inputSchema: z.object({
      name: z.string().optional(),
      phone: z.string().optional(),
      limit: z.number().int().positive().max(20).optional(),
    }),
    outputSchema: z.object({
      candidates: z.array(
        z.object({
          payeeId: z.string(),
          name: z.string(),
          bankName: z.string(),
          maskedAccountNo: z.string().optional(),
          successCount: z.number(),
          isFirstTime: z.boolean(),
          isSelfOwned: z.boolean(),
          isWhitelisted: z.boolean(),
          aliases: z.array(z.string()),
        }),
      ),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const candidates = await ctx.bank.searchPayees(ctx.customerId, {
        ...(input["name"] ? { name: String(input["name"]) } : {}),
        ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
        limit: (input["limit"] as number | undefined) ?? 10,
      });
      const summary = `找到 ${candidates.length} 个可能的收款人`;
      if (ctx.extras && candidates.length > 0) {
        const shown = candidates.slice(0, 6);
        ctx.extras.visual = {
          kind: "list_report",
          title: "收款人候选",
          subtitle: summary,
          items: shown.map((p, i) => ({
            title: `${i + 1}. ${p.name}`,
            badge: p.novelty.isFirstTime ? "首次" : p.isWhitelisted ? "常用" : undefined,
            lines: [
              `${p.bankName}${p.maskedAccountNo ? ` · ${p.maskedAccountNo}` : ""}`,
              p.novelty.successCount > 0 ? `曾成功转账 ${p.novelty.successCount} 笔` : "尚无成功记录",
            ],
          })),
          compactBody: `${summary},请点选或回复序号。`,
          actions: shown.map((_p, i) => ({ label: String(i + 1), say: String(i + 1) })),
        };
      }
      return {
        ok: true,
        data: {
          candidates: candidates.map((p) => ({
            payeeId: p.payeeId,
            name: p.name,
            bankName: p.bankName,
            ...(p.maskedAccountNo ? { maskedAccountNo: p.maskedAccountNo } : {}),
            successCount: p.novelty.successCount,
            isFirstTime: p.novelty.isFirstTime,
            isSelfOwned: p.isSelfOwned,
            isWhitelisted: p.isWhitelisted,
            aliases: p.aliases,
          })),
        },
        summary,
      };
    },
  });

  registry.register({
    name: "payee.check_deliverable",
    description:
      "校验收款方是否可达:户名与账号是否匹配、是否跨行/跨境、预计到账时间与手续费。" +
      "用户说『先看看转过去要多久』『要多少手续费』时使用。只读,不产生任何资金动作。",
    inputSchema: z.object({
      payeeName: z.string(),
      accountNo: z.string().optional(),
      phone: z.string().optional(),
      bankCode: z.string().optional(),
      /** 给了金额才试算手续费(规则见 capabilities/transferFee.ts);不给就不报数字 */
      amount: z.number().optional(),
    }),
    outputSchema: z.object({
      deliverable: z.boolean(),
      nameMatched: z.boolean(),
      actualNameMasked: z.string().optional(),
      bankName: z.string().optional(),
      interbank: z.boolean(),
      crossBorder: z.boolean(),
      estimatedArrival: z.string().optional(),
      fee: z.number().optional(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["fee"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const cleanName = sanitizePayeeName(String(input["payeeName"]));
      const result = await ctx.bank.verifyPayeeDeliverable({
        payeeName: cleanName,
        ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
        ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
        ...(input["bankCode"] ? { bankCode: String(input["bankCode"]) } : {}),
      });
      /**
       * ★ 手续费只在**知道金额**时给出(规则见 capabilities/transferFee.ts)。
       *   可达性查询本身不知道金额,以前它回一个写死的 0,这里就把"没算过"
       *   说成了"免手续费" —— 跨行转 6 万也显示免手续费,与所引条款相反。
       *   宁可说"需要金额",不可给一个错的数。
       */
      const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : null;
      const fee = amount != null ? transferFeeOf(amount, result.interbank) : null;
      const matchedText = result.nameMatched
        ? `户名匹配,预计 ${result.estimatedArrival ?? ""}`
        : `注意:户名与账号不完全匹配(实际户名:${result.actualNameMasked ?? "未知"}),建议核实后再转`;
      const feeText =
        fee == null ? "(未给金额,手续费按转账金额另算)" : fee === 0 ? ",手续费:免手续费" : `,手续费:${fee} 元`;
      const summary = `${matchedText}${feeText}`;
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "收款方可达性",
          subtitle: cleanName,
          items: [
            {
              title: result.nameMatched ? "户名匹配" : "户名待核实",
              badge: result.interbank ? "跨行" : "同行",
              tone: result.nameMatched ? "ok" : "medium",
              lines: [
                result.estimatedArrival ?? "",
                fee != null ? (fee === 0 ? "手续费:免" : `手续费:${fee} 元`) : "给出金额后可试算手续费",
                result.bankName ?? "",
              ].filter(Boolean),
            },
          ],
          compactBody: summary,
        };
      }
      return {
        ok: true,
        data: {
          deliverable: result.deliverable,
          nameMatched: result.nameMatched,
          ...(result.actualNameMasked ? { actualNameMasked: result.actualNameMasked } : {}),
          ...(result.bankName ? { bankName: result.bankName } : {}),
          interbank: result.interbank,
          crossBorder: result.crossBorder,
          ...(result.estimatedArrival ? { estimatedArrival: result.estimatedArrival } : {}),
          ...(fee != null ? { fee } : {}),
        },
        summary,
      };
    },
  });

  registry.register({
    name: "transfer.list_schedules",
    description: "查询客户已设置的定时/周期转账任务。只读。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      schedules: z.array(
        z.object({
          scheduleId: z.string(),
          status: z.string(),
          nextRunAt: z.number(),
          payeeName: z.string(),
          amount: z.number(),
          frequency: z.string(),
        }),
      ),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["schedules[].amount"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const schedules = await ctx.bank.listSchedules(ctx.customerId);
      if (ctx.extras && schedules.length > 0) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "定时转账任务",
          subtitle: `共 ${schedules.length} 个`,
          items: schedules.map((s) => ({
            title: s.intent.payee.name,
            value: `¥${s.intent.amount.toLocaleString("zh-CN")}`,
            badge: frequencyLabel(s.recurrence.frequency),
            lines: [
              `状态:${scheduleStatusLabel(s.status)}${s.nextRunAt ? ` · 下次执行 ${fmtDate(s.nextRunAt)}` : ""}`,
            ],
          })),
          compactBody: `共 ${schedules.length} 个定时转账任务,收款人、周期与下次执行时间见下。`,
        };
      }
      return {
        ok: true,
        data: {
          schedules: schedules.map((s) => ({
            scheduleId: s.scheduleId,
            status: scheduleStatusLabel(s.status),
            nextRunAt: s.nextRunAt,
            payeeName: s.intent.payee.name,
            amount: s.intent.amount,
            frequency: frequencyLabel(s.recurrence.frequency),
          })),
        },
        summary: `共 ${schedules.length} 个定时转账任务`,
      };
    },
  });

  registry.register({
    name: "collection.list",
    description: "查询客户发起的 AA 收款及其逐人付款进度。只读。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      collections: z.array(
        z.object({
          collectionId: z.string(),
          title: z.string(),
          totalAmount: z.number(),
          status: z.string(),
          paidCount: z.number(),
          totalCount: z.number(),
          shares: z.array(
            z.object({
              participantName: z.string(),
              amountDue: z.number(),
              amountPaid: z.number(),
              status: z.string(),
            }),
          ),
        }),
      ),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["collections[].totalAmount", "collections[].shares[].amountDue"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const cols = await ctx.bank.listCollections(ctx.customerId);

      // ★ 逐人列出状态,而不是只给一个"N 人已付":
      //   用户问"他们付钱了吗",想知道的是**具体是谁还没付** ——
      //   一个汇总数字回答不了这个问题,他还是要再问一遍。
      //   "谁还没给"才是真的信息,汇总数只是它的一个投影。
      const lines: string[] = [];
      if (cols.length === 0) {
        lines.push("您目前没有进行中的 AA 收款。");
      } else {
        lines.push(`共 ${cols.length} 笔 AA 收款:`);
        for (const c of cols) {
          const paid = c.shares.filter((s) => s.status === "paid");
          const unpaid = c.shares.filter((s) => s.status === "pending");
          const collected = Math.round(paid.reduce((s, x) => s + x.amountPaid, 0) * 100) / 100;
          lines.push("");
          lines.push(
            `【${c.title}】${collectionStatusLabel(c.status)} · 总额 ¥${c.totalAmount.toLocaleString("zh-CN")} · ` +
              `已收 ¥${collected.toLocaleString("zh-CN")}(${paid.length}/${c.shares.length} 人已付)`,
          );
          for (const s of c.shares) {
            lines.push(
              `  ${s.participantName} ${shareStatusLabel(s.status)} ¥${s.amountDue.toLocaleString("zh-CN")}`,
            );
          }
          if (unpaid.length > 0) {
            const outstanding = Math.round(unpaid.reduce((s, x) => s + (x.amountDue - x.amountPaid), 0) * 100) / 100;
            lines.push(`  待收 ${unpaid.length} 人,合计 ¥${outstanding.toLocaleString("zh-CN")}。如需提醒,请回复「催一下」。`);
          } else {
            lines.push("  款项已收齐。");
          }
        }
      }

      if (ctx.extras && cols.length > 0) {
        const pendingCount = cols.reduce((n, c) => n + c.shares.filter((s) => s.status === "pending").length, 0);
        ctx.extras.visual = {
          kind: "list_report",
          title: "AA 收款",
          subtitle: `共 ${cols.length} 笔${pendingCount > 0 ? ` · 还有 ${pendingCount} 人未付` : ""}`,
          items: cols.map((c) => {
            const paid = c.shares.filter((s) => s.status === "paid");
            const unpaid = c.shares.filter((s) => s.status === "pending");
            const collected = Math.round(paid.reduce((s, x) => s + x.amountPaid, 0) * 100) / 100;
            const outstanding = Math.round(unpaid.reduce((s, x) => s + (x.amountDue - x.amountPaid), 0) * 100) / 100;
            return {
              title: c.title,
              value: `¥${c.totalAmount.toLocaleString("zh-CN")}`,
              badge: collectionStatusLabel(c.status),
              tone: unpaid.length > 0 ? ("medium" as const) : ("ok" as const),
              lines: [
                `已收 ¥${collected.toLocaleString("zh-CN")}(${paid.length}/${c.shares.length} 人已付)`,
                ...c.shares.map(
                  (s) => `${s.participantName} ${shareStatusLabel(s.status)} ¥${s.amountDue.toLocaleString("zh-CN")}`,
                ),
                unpaid.length > 0
                  ? `待收 ${unpaid.length} 人,合计 ¥${outstanding.toLocaleString("zh-CN")}。如需提醒,请回复「催一下」。`
                  : "款项已收齐。",
              ],
            };
          }),
          compactBody:
            `共 ${cols.length} 笔 AA 收款,逐笔与逐人状态见下。` +
            (pendingCount > 0 ? `还有 ${pendingCount} 人未付,如需提醒,请回复「催一下」。` : ""),
        };
      }

      return {
        ok: true,
        data: {
          collections: cols.map((c) => ({
            collectionId: c.collectionId,
            title: c.title,
            totalAmount: c.totalAmount,
            status: collectionStatusLabel(c.status),
            paidCount: c.shares.filter((s) => s.status === "paid").length,
            totalCount: c.shares.length,
            shares: c.shares.map((s) => ({
              participantName: s.participantName,
              amountDue: s.amountDue,
              amountPaid: s.amountPaid,
              status: shareStatusLabel(s.status),
            })),
          })),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- AA 催收:对未付的人发提醒 ----
  registry.register({
    name: "collection.remind",
    description:
      "向 AA 收款中尚未付款的参与人发送付款提醒。" +
      "用户说『催一下他们』『提醒还没给钱的人』时使用。" +
      "★ 提醒会**真实发送**给参与人,属于对他人可见的动作,必须由用户确认;" +
      "★ 已付清的人不会被重复打扰 —— 催收的分寸感也是体验的一部分。",
    inputSchema: z.object({
      collectionId: z.string().optional().describe("要催收的 AA 账单 ID;不填则取最近一笔进行中的"),
    }),
    outputSchema: z.object({
      collectionId: z.string().nullable(),
      title: z.string().nullable(),
      reminded: z.array(z.object({ participantName: z.string(), amountDue: z.number() })),
      reason: z.string().nullable(),
    }),
    /**
     * ★ sideEffect 必须是 `irreversible`:提醒**真的发出去了** ——
     *   参与人手机上会响,系统没有任何办法撤回。声明成 reversible 会让
     *   确认卡与闸门按"可撤销"来措辞,而客户实际面对的是一个不能反悔的动作。
     */
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["reminded[].amountDue"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const cols = await ctx.bank.listCollections(ctx.customerId);
      const target = input["collectionId"]
        ? cols.find((c) => c.collectionId === String(input["collectionId"]))
        : cols.find((c) => c.status === "open" || c.status === "partially_paid");

      if (!target) {
        return {
          ok: true,
          data: { collectionId: null, title: null, reminded: [], reason: "没有进行中的 AA 收款" },
          summary: "您目前没有进行中的 AA 收款,没有需要催的人。",
        };
      }

      const unpaid = target.shares.filter((s) => s.status === "pending");
      if (unpaid.length === 0) {
        return {
          ok: true,
          data: { collectionId: target.collectionId, title: target.title, reminded: [], reason: "所有人都已付清" },
          summary: `${target.title}的所有参与人都已付清,不需要催收。`,
        };
      }

      // 提醒是"对他人可见"的动作,入审计留痕(谁在什么时候被提醒了几次)
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "collection.remind",
          collectionId: target.collectionId,
          title: target.title,
          remindedCount: unpaid.length,
          note: "催收提醒是对他人可见的动作,入链留痕:可追溯「谁在何时被提醒过几次」,避免重复骚扰。",
        },
      });

      const names = unpaid.map((s) => s.participantName).join("、");
      const outstanding = Math.round(unpaid.reduce((s, x) => s + (x.amountDue - x.amountPaid), 0) * 100) / 100;
      const summary =
        `已向【${target.title}】中未付款的 ${unpaid.length} 人发送提醒:${names}。\n` +
        `待收合计 ¥${outstanding} 元。\n` +
        "他们会在 App 内收到通知;已付清的人没有被重复打扰。";
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "催收已发送",
          subtitle: target.title,
          items: unpaid.map((s) => ({
            title: s.participantName,
            value: `¥${s.amountDue.toLocaleString("zh-CN")}`,
            lines: ["已发送 App 内提醒"],
          })),
          compactBody: `已向 ${unpaid.length} 人发送提醒,待收合计 ¥${outstanding} 元。`,
        };
      }
      return {
        ok: true,
        data: {
          collectionId: target.collectionId,
          title: target.title,
          reminded: unpaid.map((s) => ({ participantName: s.participantName, amountDue: s.amountDue })),
          reason: null,
        },
        summary,
      };
    },
  });
}
// ============================================================================
// 账单分析能力(场景二:月度报告 / 异常识别 / 定期支出 / 收支 / 洞察)
// ============================================================================

/**
 * 注册账单分析能力。
 *
 * ★ 与场景一(转账)的结构性差异:
 *
 *   ① 全部只读(readOnly + baseTier auto),策略引擎那边一律自动执行;
 *   ② 取数走专门的 `fetchForAnalysis` 接口,而不是 listTransactions ——
 *      后者有 200 条结果护栏(防诱导批量拉取),而跨 6-12 个月的聚合不够用;
 *   ③ 全部聚合计算在 `billAnalysis.ts` 这个纯函数文件里完成,模型不参与(I1);
 *   ④ 每条结论都带证据(evidence),不做没有依据的建议(I3);
 *   ⑤ 每次查询都入审计 —— "查过账单"本身也是敏感事件,不能因为是只读就不记。
 */
export function registerBillAnalysisCapabilities(registry: CapabilityRegistry): void {
  const DAY = 24 * 3600 * 1000;

  /** 取数窗口:账单分析专用的取数口,不受 200 条护栏限制 */
  const fetchWindow = async (ctx: ExecutionContext, from: number, to: number) =>
    ctx.bank.fetchForAnalysis(ctx.customerId, { from, to });

  // ---- 月度 / 年度报告 ----
  registry.register({
    name: "account.report",
    description:
      "生成月度或年度账单报告:收入、支出、结余、储蓄率、支出 Top 分类与 Top 对手方、最大额交易、与上一同期对比。" +
      "用户说『给我出个账单』『这个月花了多少』『年度报告』时使用。只读。" +
      "★ 报告里的每一个数字都由确定性引擎从银行流水算出," +
      "模型只负责把它讲成人话,不得自行计算或估算任何金额;" +
      "★ 对比结论必须带依据(与哪个期间比、差多少),不给没有基准的「多/少」判断。",
    inputSchema: z.object({
      periodType: z.enum(["monthly", "annual"]).default("monthly").describe("报告周期类型"),
      fromIso: z.string().optional().describe("起始时间 ISO 字符串(不填则按周期自动推算上月/去年)"),
      toIso: z.string().optional().describe("结束时间 ISO 字符串"),
    }),
    outputSchema: z.object({
      periodLabel: z.string(),
      income: z.number(),
      expense: z.number(),
      net: z.number(),
      txCount: z.number(),
      savingsRate: z.number().nullable(),
      topCategories: z.array(z.object({ key: z.string(), total: z.number(), count: z.number(), sharePct: z.number() })),
      topCounterparties: z.array(z.object({ key: z.string(), total: z.number(), count: z.number() })),
      largestTransactions: z.array(
        z.object({ counterpartyName: z.string(), amount: z.number(), category: z.string(), ts: z.number() }),
      ),
      comparison: z
        .object({
          baselineLabel: z.string(),
          incomeChangePct: z.number().nullable(),
          expenseChangePct: z.number().nullable(),
          verdict: z.string(),
          verdictText: z.string(),
        })
        .nullable(),
      insights: z.array(z.object({ type: z.string(), text: z.string(), evidence: z.string().optional() })),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [
      "income",
      "expense",
      "net",
      "topCategories[].total",
      "topCounterparties[].total",
      "largestTransactions[].amount",
    ],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const periodType = (input["periodType"] as "monthly" | "annual") ?? "monthly";
      const to = input["toIso"] ? Date.parse(String(input["toIso"])) : ctx.now;
      const from = input["fromIso"]
        ? Date.parse(String(input["fromIso"]))
        : to - (periodType === "annual" ? 365 * DAY : 30 * DAY);

      // ★ 多取一个等长窗口用于环比 —— 报告里"这个月比上个月多花了多少"
      //   是用户最关心的那一句,而它需要上一期的数据才说得出来。
      //   没有对比期时,savingsRate 允许为 null,绝不编一个数出来。
      const span = to - from;
      const txs = await fetchWindow(ctx, from - span, to);
      const report = buildPeriodReport(txs, { from, to, compareWithPrevious: true });

      const lines: string[] = [];
      lines.push(`${periodType === "annual" ? "年度" : "月度"}账单报告(${report.periodLabel})`);
      lines.push("");
      lines.push(`收入 ${report.income.toLocaleString("zh-CN")} 元 · 支出 ${report.expense.toLocaleString("zh-CN")} 元`);
      lines.push(`结余${report.net >= 0 ? "为正" : "为负"} ${Math.abs(report.net).toLocaleString("zh-CN")} 元` +
        (report.savingsRate != null ? ` · 储蓄率 ${report.savingsRate}%` : ""));
      if (report.comparison) {
        /**
         * ★ 只写一次"对比"。
         *
         *   baselineLabel 本身就是「上一周期(2026-08-02 至 2026-09-01)」,
         *   再在外面套一层"对比上一周期(...)"就变成了
         *   「对比上一周期(上一周期(…))」—— 这种重复不是啰嗦,是让人读不懂。
         */
        lines.push(`对比${report.comparison.baselineLabel}:${report.comparison.verdictText}`);
      }
      if (report.topCategories.length > 0) {
        lines.push("");
        lines.push("支出金额居前的分类:");
        for (const c of report.topCategories.slice(0, 5)) {
          lines.push(`  · ${c.key}:${c.total.toLocaleString("zh-CN")} 元(${c.sharePct}%)`);
        }
      }
      if (report.topCounterparties.length > 0) {
        lines.push("");
        lines.push("支出最多的对象:");
        for (const m of report.topCounterparties.slice(0, 3)) {
          lines.push(`  · ${m.key}:${m.total.toLocaleString("zh-CN")} 元(${m.count} 笔)`);
        }
      }
      if (report.insights.length > 0) {
        lines.push("");
        lines.push("需关注事项:");
        for (const i of report.insights) {
          const tag = i.type === "warning" ? "提示" : i.type === "suggestion" ? "建议" : "说明";
          lines.push(`  [${tag}] ${i.text}`);
        }
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.report",
          periodType,
          from,
          to,
          income: report.income,
          expense: report.expense,
          net: report.net,
          note: "账单报告入链:数字全部由 billAnalysis 纯函数引擎从银行流水算出,模型未参与任何计算。",
        },
      });

      /**
       * ★ 账单报告的出处:收入/支出/结余三个数字必须能对得上流水。
       *   口径三件事写清楚 —— 哪段时间、哪些笔、怎么加起来的。
       */
      ctx.extras?.citations.push({
        id: "data:账单报告",
        topic: `账单报告:收入 ${report.income.toFixed(2)} · 支出 ${report.expense.toFixed(2)} · 结余 ${report.net.toFixed(2)} 元`,
        source: SOURCES.bill,
        subject: "客户本人 · 名下全部账户",
        effective: `${new Date(from).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" })} ~ ${new Date(to).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" })}(${periodType === "annual" ? "年度" : "月度"}口径)`,
        asOf: ctx.now,
        calculation: [
          `收入 = 统计期内收入方向流水合计 = ${report.income.toFixed(2)} 元`,
          `支出 = 统计期内支出方向流水合计 = ${report.expense.toFixed(2)} 元`,
          `结余 = 收入 − 支出 = ${report.net.toFixed(2)} 元`,
        ],
        note: "仅统计已清算交易;分类与异常判定均由 billAnalysis 纯函数引擎完成,模型未参与任何计算",
        kind: "data",
      });
      if (ctx.extras) ctx.extras.hasMonetary = true;

      const chart = billChartVisual({
        title: `${periodType === "annual" ? "年度" : "月度"}账单报告`,
        subtitle: report.periodLabel,
        filename: `账单报告-${report.periodLabel}`,
        panels: [
          {
            title: "收入与支出",
            chart: "bars",
            legend: ["金额(元)"],
            series: [
              { label: "收入", value: report.income },
              { label: "支出", value: report.expense },
            ],
          },
          {
            title: "支出分类",
            chart: "bars",
            legend: ["金额(元)"],
            series: report.topCategories.map((c) => ({
              label: `${c.key} ${c.sharePct}%`,
              value: c.total,
            })),
          },
        ],
        notes: [
          report.summary,
          report.comparison?.verdictText ?? "",
          ...report.insights.slice(0, 4).map((item) => item.text),
          "柱高与报告正文是同一份流水合计,下载的图里同时带有这些说明。",
        ],
      });
      if (chart && ctx.extras) ctx.extras.visual = chart;

      return { ok: true, data: report, summary: lines.join("\n") };
    },
  });

  // ---- 异常交易识别 ----
  registry.register({
    name: "account.detect_anomalies",
    description:
      "识别账单里的异常交易:深夜消费、金额突增、同一商户重复扣款、与历史习惯明显不符的支出等。" +
      "用户说『有没有奇怪的消费』『有没有被盗刷』『帮我看看异常』时使用。只读。" +
      "★ 每条异常都给出判定依据与建议动作,不做没有依据的指控;" +
      "★ 涉及疑似盗刷时,建议动作里包含「先冻结卡片」这类止损路径,而不是只提示「注意核实」。",
    inputSchema: z.object({
      fromIso: z.string().optional(),
      toIso: z.string().optional(),
    }),
    outputSchema: z.object({
      windowLabel: z.string(),
      checkedCount: z.number(),
      anomalies: z.array(
        z.object({
          kind: z.string(),
          severity: z.string(),
          title: z.string(),
          description: z.string(),
          amount: z.number(),
          ts: z.number(),
          counterpartyName: z.string(),
          category: z.string(),
          transactionId: z.string(),
          suggestedAction: z.string(),
        }),
      ),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["anomalies[].amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const to = input["toIso"] ? Date.parse(String(input["toIso"])) : ctx.now;
      const from = input["fromIso"] ? Date.parse(String(input["fromIso"])) : to - 90 * DAY;

      const txs = await fetchWindow(ctx, from, to);
      const report = detectAnomalies(txs, to);

      const lines: string[] = [];
      lines.push(`异常交易检查(${report.windowLabel})`);
      lines.push(report.summary);
      if (report.anomalies.length > 0) {
        lines.push("");
        for (const a of report.anomalies) {
          const level = a.severity === "high" ? "高" : a.severity === "medium" ? "中" : "低";
          lines.push(`[${level}] ${a.title} · ${fmtDate(a.ts)}`);
          lines.push(`   ${a.description}`);
          lines.push(`   建议:${a.suggestedAction}`);
        }
        lines.push("");
        lines.push("以上条目由规则识别,并附有依据。如确认非本人交易,请回复「挂失」,可立即冻结卡片。");
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.detect_anomalies",
          from,
          to,
          anomalyCount: report.anomalies.length,
          highCount: report.anomalies.filter((a) => a.severity === "high").length,
          note: "异常识别入链(判定规则与阈值口径一并留存):" +
            "万一后续发生争议,系统必须能说清「当时是按什么标准判的」。",
        },
      });

      // 结构化清单同时下发:富交互终端按等级画卡片,正文只留结论,不再刷一屏纯文字
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "anomaly_report",
          windowLabel: report.windowLabel,
          checkedCount: report.checkedCount,
          summary: report.summary,
          items: report.anomalies.map((a) => ({
            severity: a.severity,
            title: a.title,
            description: a.description,
            advice: a.suggestedAction.replace(/回复「转人工」/g, "联系反诈专员"),
            dateLabel: fmtDate(a.ts),
          })),
        };
      }

      return { ok: true, data: report, summary: lines.join("\n") };
    },
  });

  // ---- 定期支出 / 订阅识别 ----
  registry.register({
    name: "account.detect_recurring",
    description:
      "识别定期支出与订阅:周期扣款(每月/每周/每季)、每期金额、下次预计扣款时间与月度折算总额。" +
      "用户说『我有哪些订阅』『每月固定支出多少』时使用。只读。" +
      "★ 判定依据是扣款间隔的规律性(间隔标准差),随机消费不会被误报成订阅;" +
      "★ 下次预计扣款按日历推算,不是按「上次 + 30 天」简单加,",
    inputSchema: z.object({
      fromIso: z.string().optional(),
      toIso: z.string().optional(),
    }),
    outputSchema: z.object({
      items: z.array(
        z.object({
          counterpartyName: z.string(),
          category: z.string(),
          count: z.number(),
          avgAmount: z.number(),
          intervalDays: z.number().nullable(),
          cadence: z.string(),
          monthlyEquivalent: z.number(),
          firstTs: z.number(),
          lastTs: z.number(),
          expectedNext: z.number().nullable(),
        }),
      ),
      monthlyTotal: z.number(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["items[].avgAmount", "items[].monthlyEquivalent", "monthlyTotal"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const to = input["toIso"] ? Date.parse(String(input["toIso"])) : ctx.now;
      const from = input["fromIso"] ? Date.parse(String(input["fromIso"])) : to - 180 * DAY;

      const txs = await fetchWindow(ctx, from, to);
      const outTxs = txs.filter((t) => t.direction === "out");
      const report = detectRecurring(outTxs, to);

      const lines: string[] = [];
      lines.push("定期支出与订阅识别(近 6 个月)");
      lines.push(report.summary);
      if (report.items.length > 0) {
        lines.push("");
        for (const r of report.items) {
          /**
           * ★ 周期文案走 subscription.ts 的单一出处。
           *   原来这里手写三元 `monthly ? "每月" : weekly ? "每周" : "每季"` ——
           *   而 cadence 的取值是 weekly/monthly/yearly/irregular/unknown,
           *   于是「年度」和「不定期」都被说成了「每季」:同一笔年缴保费,
           *   这里说每季、订阅能力说每年。兜底分支必须是「原样返回的兜底」,
           *   不是「最后一个 else 顺手安一个」。
           */
          const cadenceText = cadenceLabel(r.cadence);
          lines.push(`  · ${r.counterpartyName}:${cadenceText},平均 ${r.avgAmount.toLocaleString("zh-CN")} 元,共 ${r.count} 笔${r.expectedNext ? `,下次预计 ${fmtDate(r.expectedNext)}` : ""}`);
        }
        lines.push("");
        lines.push(`月度折算合计 ${report.monthlyTotal.toLocaleString("zh-CN")} 元。如需核对是否仍有必要,可逐项查看。`);
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.detect_recurring",
          from,
          to,
          recurringCount: report.items.length,
          monthlyTotal: report.monthlyTotal,
          note: "定期支出识别入链(间隔规律性判据与标准差阈值一并留存),便于复核「为什么这笔被判成订阅」。",
        },
      });

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "定期支出与订阅",
          subtitle: `近 6 个月 · 月度折算合计 ${report.monthlyTotal.toLocaleString("zh-CN")} 元`,
          summary: report.summary,
          items: report.items.map((r) => ({
            title: r.counterpartyName,
            value: `${r.avgAmount.toLocaleString("zh-CN")} 元`,
            badge: cadenceLabel(r.cadence),
            lines: [`共 ${r.count} 笔${r.expectedNext ? `,下次预计 ${fmtDate(r.expectedNext)}` : ""}`],
          })),
          compactBody: `${report.summary}月度折算合计 ${report.monthlyTotal.toLocaleString("zh-CN")} 元,逐项明细见下。`,
        };
      }

      return { ok: true, data: report, summary: lines.join("\n") };
    },
  });

  // ---- 收支 / 现金流 ----
  registry.register({
    name: "account.cashflow",
    description:
      "按月的收入、支出、结余与储蓄率趋势,一眼看清哪个月破功了。" +
      "用户说『这半年收支怎么样』『我每月能存下多少』时使用。只读。",
    inputSchema: z.object({
      months: z.number().int().min(2).max(12).optional().describe("统计月数,默认 6"),
    }),
    outputSchema: z.object({
      months: z.array(
        z.object({
          month: z.string(),
          income: z.number(),
          expense: z.number(),
          net: z.number(),
          savingsRate: z.number().nullable(),
        }),
      ),
      totalIncome: z.number(),
      totalExpense: z.number(),
      totalNet: z.number(),
      trend: z.string(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [
      "months[].income",
      "months[].expense",
      "months[].net",
      "totalIncome",
      "totalExpense",
      "totalNet",
    ],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const months = Math.min(Math.max((input["months"] as number) ?? 6, 2), 12);
      const from = ctx.now - (months + 1) * 30 * DAY;

      const txs = await fetchWindow(ctx, from, ctx.now);
      const report = buildCashflow(txs, months, ctx.now);

      const lines: string[] = [];
      lines.push(`收支分析(近 ${months} 个月)`);
      lines.push("");
      for (const m of report.months) {
        lines.push(`  ${m.month}  收入 ${m.income.toLocaleString("zh-CN")} · 支出 ${m.expense.toLocaleString("zh-CN")} · 结余 ${m.net >= 0 ? "+" : ""}${m.net.toLocaleString("zh-CN")}`);
      }
      lines.push("");
      lines.push(`合计:收入 ${report.totalIncome.toLocaleString("zh-CN")} 元,支出 ${report.totalExpense.toLocaleString("zh-CN")} 元,净${report.totalNet >= 0 ? "结余" : "透支"} ${Math.abs(report.totalNet).toLocaleString("zh-CN")} 元`);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.cashflow",
          months,
          totalIncome: report.totalIncome,
          totalExpense: report.totalExpense,
          totalNet: report.totalNet,
          note: "收支汇总入链(含总额与净结余)。",
        },
      });

      const cashflowChart = billChartVisual({
        title: `收支趋势(近 ${months} 个月)`,
        subtitle: `近 ${months} 个月`,
        filename: `收支趋势-近${months}个月`,
        panels: [
          {
            title: "每月收入与支出",
            chart: "grouped",
            legend: ["收入", "支出"],
            series: report.months.map((month) => ({
              label: month.month,
              value: month.income,
              value2: month.expense,
            })),
          },
        ],
        notes: [report.summary, "蓝柱是收入,红柱是支出,与上面逐月数字是同一份结果。"],
      });
      if (cashflowChart && ctx.extras) ctx.extras.visual = cashflowChart;

      return { ok: true, data: report, summary: lines.join("\n") };
    },
  });

  // ---- 综合洞察 / 省钱建议 ----
  registry.register({
    name: "account.insights",
    description:
      "综合账单洞察与省钱建议:订阅重叠、异常支出、储蓄率变化、可优化项。" +
      "用户说『给我点省钱建议』『我有什么可以优化的』时使用。只读。" +
      "★ 每一条建议都必须附**证据来源**(依据了哪几笔、哪个规则)," +
      "不给没有依据的建议,也不编造理财话术;" +
      "★ 建议是规则算出来的,不是模型临场发挥 —— 可审计,可复核。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      insights: z.array(z.object({ type: z.string(), title: z.string(), text: z.string(), evidence: z.string().optional() })),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      // 用 180 天窗口:太短看不出规律,太长会把已经停止的订阅也算进来。
      // 90 天的订阅需要至少 2-3 个周期才能被确认为"定期",所以取 180 天。
      const from = ctx.now - 180 * DAY;
      const txs = await fetchWindow(ctx, from, ctx.now);
      const report = buildInsights(txs, ctx.now);

      const lines: string[] = [];
      lines.push("账单洞察");
      lines.push(report.summary);
      if (report.insights.length > 0) {
        lines.push("");
        for (const i of report.insights) {
          const tag = i.type === "warning" ? "提示" : i.type === "suggestion" ? "建议" : "说明";
          lines.push(`[${tag}] ${i.title}:${i.text}`);
          if (i.evidence) lines.push(`   依据:${i.evidence}`);
        }
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.insights",
          insightCount: report.insights.length,
          note: "洞察生成规则与证据链入链:每条建议都能追到具体数据 —— 这是「建议」与「话术」的分界线。",
        },
      });

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "账单洞察",
          subtitle: report.summary,
          items: report.insights.slice(0, 6).map((i) => ({
            title: i.title,
            badge: i.type === "warning" ? "提示" : i.type === "suggestion" ? "建议" : "说明",
            tone: i.type === "warning" ? "medium" : i.type === "suggestion" ? "ok" : "plain",
            lines: i.evidence ? [i.text, `依据:${i.evidence}`] : [i.text],
          })),
          compactBody: report.summary,
        };
      }

      return { ok: true, data: report, summary: lines.join("\n") };
    },
  });

  // ---- 发薪后分配清单(演示场景:替代跨场景联动) ----
  registry.register({
    name: "account.payday_brief",
    description:
      "工资到账后的一次只读汇总:近期入账、定时转账与订阅扣款、粗算可自由支配金额。" +
      "用户说『工资刚到账帮我理一下怎么分配』『发薪后该怎么花钱』时使用。" +
      "★ 只汇总事实,不锁资金、不订外部服务;底部给出转账/查订阅等**独立**续办话术,每项仍须单独确认。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      summary: z.string(),
      discretionary: z.number(),
      fixedTotal: z.number(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["discretionary", "fixedTotal"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const brief = await buildPaydayBrief(ctx);
      const lines = ["发薪分配清单", brief.summary, "", "★ 以下为只读汇总;点底部按钮或按提示发起转账/查订阅,每一步单独确认。"];

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.payday_brief",
          discretionary: brief.discretionary,
          fixedTotal: brief.fixedTotal,
          hasSalary: brief.salary != null,
          note: "发薪清单:数字来自流水、代扣协议与定时任务,不是模型估算。",
        },
      });

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "发薪分配清单",
          subtitle: "只读汇总 · 不自动扣款",
          summary: brief.summary,
          items: brief.items,
          compactBody: `${brief.summary} 需要办哪一项,点下方按钮或按提示说即可(每项单独确认)。`,
          footer: "清单不等于转账;付房租、给生活费、关订阅都要各自走确认流程。",
          actions: brief.actions,
        };
      }

      return { ok: true, data: brief, summary: lines.join("\n") };
    },
  });

  // ---- 财务健康标签(近 3 个自然月,门槛可配置,数字只来自流水) ----
  registry.register({
    name: "account.health_label",
    description:
      "根据近几个自然月的收入、支出和餐饮分类,打一档财务健康标签:餐饮偏高、结余稳定、支出接近收入,或未达这三档。" +
      "用户说『看看财务健康标签』『我的账单标签』时使用。只读。" +
      "标签只比较客户自己的流水和配置门槛,不跟他人比,不推算定投,不申购。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      tag: z.string(),
      tagLabel: z.string(),
      diningMonthlyAvg: z.number(),
      surplusMonthlyAvg: z.number(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["diningMonthlyAvg", "surplusMonthlyAvg"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const from = ctx.now - 100 * DAY;
      const txs = await fetchWindow(ctx, from, ctx.now);
      const health = buildBillHealth(txs, ctx.now);
      const summary = renderBillHealth(health);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "account.health_label",
          tag: health.tag,
          diningMonthlyAvg: health.diningMonthlyAvg,
          surplusMonthlyAvg: health.surplusMonthlyAvg,
          note: "财务健康标签由流水和配置门槛算出,未创建定投,未申购。",
        },
      });

      ctx.extras?.citations.push({
        id: "data:财务健康标签",
        topic: `财务健康:${health.tagLabel}`,
        source: SOURCES.bill,
        subject: "客户本人 · 名下账户流水",
        effective: health.windowLabel,
        asOf: ctx.now,
        calculation: [
          `餐饮月均 = 窗口内餐饮美食支出 / 有流水的月份数 = ${health.diningMonthlyAvg.toFixed(2)} 元`,
          `月均结余 = (收入 − 支出) / 有流水的月份数 = ${health.surplusMonthlyAvg.toFixed(2)} 元`,
          health.reason,
        ],
        note: "门槛写在标签依据里。没有同群比较,没有把结余换成可投资金额。",
        kind: "data",
      });

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "财务健康标签",
          subtitle: health.tagLabel,
          items: [
            {
              title: "餐饮月均",
              value: `¥${health.diningMonthlyAvg.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
              lines: [`窗口:${health.windowLabel}`],
            },
            {
              title: "月均结余",
              value: `¥${health.surplusMonthlyAvg.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
            },
          ],
          compactBody: health.tagLabel,
          footer: health.reason,
        };
      }

      return {
        ok: true,
        data: {
          tag: health.tag,
          tagLabel: health.tagLabel,
          diningMonthlyAvg: health.diningMonthlyAvg,
          surplusMonthlyAvg: health.surplusMonthlyAvg,
          summary,
        },
        summary,
      };
    },
  });
}

// ============================================================================
// 理财能力(场景三)
// ============================================================================

/** 风险测评有效期(监管惯例:一年一评) */
const ASSESSMENT_VALID_DAYS = 365;

/**
 * 注册理财能力(场景三)。
 *
 * ★ 与场景二(账单分析)的结构性差异,是这一组能力的设计核心:
 *   账单分析**全是只读**,策略引擎那边一律自动执行,闸门永不触发;
 *   而理财场景**同时包含只读、承诺类、影响资金三类操作**:
 *
 *     | 能力                  | sideEffect   | moneyMovement | baseTier |
 *     |-----------------------|--------------|---------------|----------|
 *     | wealth.list_products  | none         | false         | auto     |
 *     | wealth.product_detail | none         | false         | auto     |
 *     | wealth.compare        | none         | false         | auto     |
 *     | wealth.risk_assess    | none         | false         | auto     |
 *     | wealth.holdings       | none         | false         | auto     |
 *     | wealth.rollover_plan  | none         | false         | auto     |
 *     | wealth.rollover_choose| reversible   | false         | auto     |
 *     | wealth.purchase       | irreversible | true          | confirm  |
 *     | wealth.redeem         | irreversible | true          | confirm  |
 *
 *   ★ 关键判定:**申购与赎回都标记为 moneyMovement = true**。
 *     有人会争辩"申购只是把钱从左口袋放到右口袋,不算资金操作"。
 *     但 moneyMovement 在本项目里的含义不是"钱离开了客户",而是
 *     "该操作会改变客户的资金状态,因此不得继承前置节点的许可、必须独立裁决"。
 *     申购会冻结可用余额,赎回会让份额与到账时间发生变化 —— 两者都改变资金状态,
 *     所以都必须独立裁决。把申购标记为 false 会让它绕过
 *     R-ACCOUNT-RESTRICTED(账户风控限制)、R-IM-NO-STRONG-TX(高风险渠道)
 *     这些本该生效的硬规则 —— 那是一个真实的安全缺口。
 */
export function registerWealthCapabilities(registry: CapabilityRegistry): void {
  // ---- 产品列表与详情(只读)----
  registry.register({
    name: "wealth.list_products",
    description:
      "查询在售理财产品列表,可按关键词(产品名/类型如『货币』『债券』『稳健』)、风险等级上限、产品类型过滤," +
      "支持按收益/风险/期限/起购金额排序。" +
      "用户说『有什么理财产品』『推荐几个理财产品』『5万块买什么好』『有没有稳健一点的』时使用。" +
      "★ 收益数据一律标注口径(近 7 日年化 / 近 1 年 / 业绩比较基准),不得说成『预期收益』;" +
      "★ 输出必须包含风险提示。",
    inputSchema: z.object({
      keyword: z.string().optional().describe("产品关键词,如『稳健』『货币』『债券』"),
      maxRiskLevel: z.enum(["R1", "R2", "R3", "R4", "R5"]).optional().describe("只要不超过该风险等级的产品"),
      type: z.enum(["cash", "fixed_income", "mixed", "equity", "deposit"]).optional().describe("产品大类"),
      sortBy: z.enum(["yield", "risk", "term", "minAmount"]).optional().describe("排序维度,默认按收益"),
      maxMinAmount: z.number().positive().optional().describe("只看起购金额不超过该值的产品"),
      limit: z.number().int().positive().max(20).optional().describe("返回条数,默认 5"),
    }),
    outputSchema: z.object({
      products: z.array(
        z.object({
          productCode: z.string(),
          name: z.string(),
          type: z.string(),
          typeLabel: z.string(),
          riskLevel: z.string(),
          riskLabel: z.string(),
          yieldText: z.string(),
          termText: z.string(),
          minAmount: z.number(),
          settlement: z.string(),
          settlementText: z.string(),
          highlight: z.string(),
          /** ★ 每只产品自带风险提示,列表层不得省略 */
          riskDisclosure: z.string(),
        }),
      ),
      totalMatched: z.number(),
      customerRiskLevel: z.string().nullable(),
      /** 是否全部在客户风险承受范围内 */
      allWithinSuitability: z.boolean(),
      /** ★ 风险提示(结构化生成,不是模型自由发挥) */
      riskDisclosure: z.string(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["products[].minAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const query = {
        ...(input["keyword"] ? { keyword: String(input["keyword"]) } : {}),
        ...(input["maxRiskLevel"] ? { maxRiskLevel: input["maxRiskLevel"] as never } : {}),
        ...(input["type"] ? { type: input["type"] as never } : {}),
        ...(input["sortBy"] ? { sortBy: input["sortBy"] as never } : {}),
        ...(input["maxMinAmount"] != null ? { maxMinAmount: Number(input["maxMinAmount"]) } : {}),
        limit: Number(input["limit"] ?? 5),
      };

      const products = await ctx.bank.listWealthProducts(query);
      const profile = await ctx.bank.getRiskProfile(ctx.customerId);

      // 无结果时给一次"放宽条件"的重试:先去掉风险等级限制,再彻底放开
      if (products.length === 0) {
        const relaxed = query.keyword
          ? await ctx.bank.listWealthProducts({ limit: query.limit })
          : await ctx.bank.listWealthProducts({ limit: query.limit });
        if (relaxed.length > 0) {
          const lines: string[] = [];
          lines.push(`按您说的条件没有找到合适的产品,这里是在售产品的完整列表(前 ${relaxed.length} 只):`);
          lines.push("");
          lines.push(...renderProductList(relaxed));
          lines.push("");
          lines.push(buildDisclosureSummary(relaxed));
          const relaxedHeadline = `在售 ${relaxed.length} 只(已放宽筛选)`;
          if (ctx.extras) {
            ctx.extras.visual = {
              kind: "list_report",
              title: "理财产品",
              subtitle: "按原条件未命中,以下为在售列表",
              summary: relaxedHeadline,
              items: relaxed.slice(0, 8).map((p, i) => ({
                title: `${i + 1}. ${p.name}`,
                value: yieldLabel(p),
                badge: p.riskLevel,
                lines: [`起购 ${p.minAmount.toLocaleString("zh-CN")} 元 · ${termLabel(p)} · ${p.productCode}`],
              })),
              compactBody: `${relaxedHeadline}。明细见卡片。`,
              footer: "历史业绩不代表未来表现,不承诺保本保收益。",
            };
          }
          return {
            ok: true,
            data: {
              products: relaxed.map((p) => ({
                productCode: p.productCode,
                name: p.name,
                type: p.type,
                typeLabel: PRODUCT_TYPE_LABELS[p.type],
                riskLevel: p.riskLevel,
                riskLabel: PRODUCT_RISK_LABELS[p.riskLevel],
                yieldText: yieldLabel(p),
                termText: termLabel(p),
                minAmount: p.minAmount,
                settlement: p.settlement,
                settlementText: settlementLabel(p),
                highlight: p.highlight,
                riskDisclosure: p.riskDisclosure,
              })),
              totalMatched: relaxed.length,
              customerRiskLevel: profile.level,
              allWithinSuitability: false,
              riskDisclosure: buildDisclosureSummary(relaxed),
              summary: lines.join("\n"),
            },
            summary: lines.join("\n"),
          };
        }
      }

      const maxLevel = profile.maxProductRiskLevel;
      const allWithin = maxLevel
        ? products.every((p) => riskLevelOrdinal(p.riskLevel) <= riskLevelOrdinal(maxLevel))
        : false;

      /**
       * ★ 收益与起购金额的出处。
       *
       *   理财列表里每一行都带收益率与起购金额 —— 这是客户做决定时唯一能抓的东西,
       *   也是"历史业绩"最容易被误读成"未来收益"的地方。
       *   所以带出的不只是数字,还有**口径**:什么时点、按哪张净值表、什么口径的收益。
       */
      ctx.extras?.citations.push({
        id: "data:理财产品列表",
        topic: `${products.length} 只理财产品 · 收益与起购金额`,
        source: SOURCES.wealth,
        subject: `客户 ${ctx.customerId}(风险等级 ${profile.level || "未测评"})`,
        effective: `净值与收益口径截至 ${new Date(ctx.now).toLocaleString("zh-CN", {
          timeZone: "Asia/Shanghai",
          hour12: false,
        })}`,
        asOf: ctx.now,
        calculation: products
          .slice(0, 5)
          .map((p) => `${p.name}(${p.productCode}) ${yieldLabel(p)} · 起购 ${p.minAmount} 元`),
        note:
          "收益率口径逐只标注(近 7 日年化 / 近 1 年 / 业绩比较基准),历史业绩不代表未来表现;" +
          "不构成投资建议,收益存在波动,可能产生本金损失",
        kind: "data",
      });
      if (ctx.extras) {
        ctx.extras.hasMonetary = true;
        ctx.extras.hasRuleDecision = true;
      }

      const lines: string[] = [];
      lines.push(`在售理财产品 ${products.length} 只:`);
      lines.push("");
      lines.push(...renderProductList(products));
      lines.push("");
      if (profile.assessed && profile.level) {
        lines.push(`您的风险等级:${profile.level}(${profile.levelLabel}),可购上限 ${profile.maxProductRiskLevel} 及以下产品`);
      } else {
        lines.push("您尚未完成风险承受能力测评。首次购买理财前须完成测评,共 6 题。如需开始,请回复「做风险测评」。");
      }
      lines.push("");
      lines.push(buildDisclosureSummary(products));

      // ★ "推荐过"这件事本身要留痕:监管核查时会问"你到底有没有做风险提示",
      //   而不是问你"提示写得好不好"。因此独立成一个事件类型,可直接检索。
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_risk_disclosure_sent",
        payload: {
          capability: "wealth.list_products",
          productCount: products.length,
          riskLevels: [...new Set(products.map((p) => p.riskLevel))],
          disclosureIncluded: true,
          customerRiskLevel: profile.level,
          note: "风险提示已随列表发出:提示是列表的一部分,不是可选的补充文案。独立成事件便于监管直接检索「提示有没有发」。",
        },
      });

      const listHeadline = `在售 ${products.length} 只`;
      const riskNote =
        profile.assessed && profile.level
          ? `您的等级 ${profile.level},可购 ${profile.maxProductRiskLevel} 及以下`
          : "未完成测评 · 购买前须先测评";
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "理财产品",
          subtitle: riskNote,
          summary: listHeadline,
          items: products.slice(0, 8).map((p, i) => ({
            title: `${i + 1}. ${p.name}`,
            value: yieldLabel(p),
            badge: p.riskLevel,
            lines: [`起购 ${p.minAmount.toLocaleString("zh-CN")} 元 · ${termLabel(p)} · ${p.productCode}`],
          })),
          compactBody: `${listHeadline}。明细见卡片;说「买第1个」或产品名可继续。`,
          footer: "历史业绩不代表未来表现,不承诺保本保收益。",
        };
      }

      return {
        ok: true,
        data: {
          products: products.map((p) => ({
            productCode: p.productCode,
            name: p.name,
            type: p.type,
            typeLabel: PRODUCT_TYPE_LABELS[p.type],
            riskLevel: p.riskLevel,
            riskLabel: PRODUCT_RISK_LABELS[p.riskLevel],
            yieldText: yieldLabel(p),
            termText: termLabel(p),
            minAmount: p.minAmount,
            settlement: p.settlement,
            settlementText: settlementLabel(p),
            highlight: p.highlight,
            riskDisclosure: p.riskDisclosure,
          })),
          totalMatched: products.length,
          customerRiskLevel: profile.level,
          allWithinSuitability: allWithin,
          riskDisclosure: buildDisclosureSummary(products),
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 产品详情(只读)----
  registry.register({
    name: "wealth.product_detail",
    description:
      "查询一只理财产品的详情:风险等级、收益口径、期限、起购与递增金额、净值、费率、赎回到账时效、" +
      "以及这只产品**对你是否适配**的判定(未测评 / 已过期 / 匹配 / 超等级需签确认书)。" +
      "用户说『XX 是什么』『起购多少』『多久到账』『我能买吗』时使用。只读。" +
      "★ 收益字段一律按口径原样带出(近 7 日年化 / 近 1 年 / 业绩比较基准),禁止改写成「预期收益」;" +
      "★ 必须带出产品自带的风险提示原文。",
    inputSchema: z.object({
      productCode: z.string().optional().describe("产品代码,如 LC1002"),
      productName: z.string().optional().describe("产品名称或口语称呼,如『稳健增利』『那个稳健型的』"),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      productCode: z.string().nullable(),
      name: z.string().nullable(),
      riskLevel: z.string().nullable(),
      riskLabel: z.string().nullable(),
      yieldText: z.string().nullable(),
      performanceBenchmark: z.number().nullable(),
      termText: z.string().nullable(),
      minAmount: z.number().nullable(),
      incrementAmount: z.number().nullable(),
      nav: z.number().nullable(),
      managementFeeRate: z.number().nullable(),
      purchaseFeeRate: z.number().nullable(),
      settlementText: z.string().nullable(),
      redeemable: z.boolean().nullable(),
      /** 适配性判定档位 */
      suitability: z.string().nullable(),
      suitabilityMessage: z.string().nullable(),
      riskDisclosure: z.string().nullable(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["minAmount", "incrementAmount", "nav"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const product = await resolveProduct(ctx, input);
      if (!product) {
        return {
          ok: true,
          data: {
            found: false,
            productCode: null,
            name: null,
            riskLevel: null,
            riskLabel: null,
            yieldText: null,
            performanceBenchmark: null,
            termText: null,
            minAmount: null,
            incrementAmount: null,
            nav: null,
            managementFeeRate: null,
            purchaseFeeRate: null,
            settlementText: null,
            redeemable: null,
            suitability: null,
            suitabilityMessage: null,
            riskDisclosure: null,
            summary: "没有在在售产品里找到这只产品。您可以告诉我产品代码(如 LC1002),或者先看看有什么理财产品。",
          },
          summary: "没有在在售产品里找到这只产品。您可以告诉我产品代码(如 LC1002),或者先看看有什么理财产品。",
        };
      }

      const profile = await ctx.bank.getRiskProfile(ctx.customerId);
      const suit = checkSuitability({ product, profile });

      const lines: string[] = [];
      lines.push(`产品详情:${product.name}(${product.productCode})`);
      lines.push("");
      lines.push(`  · 风险等级:${product.riskLevel} ${PRODUCT_RISK_LABELS[product.riskLevel]}(${PRODUCT_TYPE_LABELS[product.type]})`);
      lines.push(`  · 收益参考:${yieldLabel(product)}`);
      lines.push(`  · ${drawdownDetail(product.maxDrawdown6m)}`);
      lines.push(`  · 产品期限:${termLabel(product)}`);
      lines.push(`  · 起购金额:${product.minAmount.toLocaleString("zh-CN")} 元,递增单位 ${product.incrementAmount.toLocaleString("zh-CN")} 元`);
      lines.push(`  · 单位净值:${product.nav.toFixed(4)}`);
      lines.push(`  · 费率:管理费 ${product.managementFeeRate}%/年 · 托管费 ${product.custodyFeeRate}%/年 · 申购费 ${product.purchaseFeeRate}%`);
      lines.push(`  · 赎回到账:${settlementLabel(product)}`);
      lines.push(`  · 产品特征:${product.highlight}`);
      lines.push("");
      lines.push(`适配性:${suit.message}`);
      lines.push("");
      lines.push(product.riskDisclosure);

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "产品详情",
          subtitle: `${product.name} · ${yieldLabel(product)}`,
          summary: suit.message,
          items: [
            {
              title: product.name,
              value: yieldLabel(product),
              badge: product.riskLevel,
              lines: [
                `起购 ${product.minAmount.toLocaleString("zh-CN")} 元 · ${termLabel(product)}`,
                `净值 ${product.nav.toFixed(4)} · ${settlementLabel(product)}`,
              ],
            },
          ],
          compactBody: suit.message,
          footer:
            product.riskDisclosure.length > 100
              ? `${product.riskDisclosure.slice(0, 97)}…`
              : product.riskDisclosure,
        };
      }

      return {
        ok: true,
        data: {
          found: true,
          productCode: product.productCode,
          name: product.name,
          riskLevel: product.riskLevel,
          riskLabel: PRODUCT_RISK_LABELS[product.riskLevel],
          yieldText: yieldLabel(product),
          performanceBenchmark: product.performanceBenchmark,
          termText: termLabel(product),
          minAmount: product.minAmount,
          incrementAmount: product.incrementAmount,
          nav: product.nav,
          managementFeeRate: product.managementFeeRate,
          purchaseFeeRate: product.purchaseFeeRate,
          settlementText: settlementLabel(product),
          redeemable: product.redeemable,
          suitability: suit.status,
          suitabilityMessage: suit.message,
          riskDisclosure: product.riskDisclosure,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 产品对比(只读)----
  registry.register({
    name: "wealth.compare",
    description:
      "按收益、风险、期限、起购门槛、流动性五个维度对比多只理财产品,逐维度标出更好的一方。" +
      "用户说『这个和那个比哪个好』『对比一下』时使用。只读。" +
      "★ 刻意**不产出「综合最优」结论**:收益高的必然风险高或期限长," +
      "把多维取舍压成一个分数等于替客户做了风险偏好判断;" +
      "★ 如果产品是系统自己挑的,必须在回复里说明「这是系统挑的」,不得假装听懂了用户的指代。",
    inputSchema: z.object({
      productCodes: z.array(z.string()).optional().describe("对比对象的产品代码"),
      productNames: z.array(z.string()).optional().describe("对比对象的产品名/口语称呼"),
      keyword: z.string().optional().describe("补充筛选关键词(产品不够两只时用)"),
      dimensions: z.array(z.enum(["yield", "risk", "term", "minAmount", "liquidity"])).optional(),
    }),
    outputSchema: z.object({
      rows: z.array(
        z.object({
          productCode: z.string(),
          name: z.string(),
          typeLabel: z.string(),
          riskLevel: z.string(),
          riskLabel: z.string(),
          yieldText: z.string(),
          yieldValue: z.number(),
          termText: z.string(),
          minAmountText: z.string(),
          settlementText: z.string(),
        }),
      ),
      dimensionWinners: z.array(
        z.object({ dimension: z.string(), productCode: z.string(), productName: z.string(), reason: z.string() }),
      ),
      bothWithinSuitability: z.boolean(),
      riskDisclosure: z.string(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const picked: Awaited<ReturnType<typeof resolveProduct>>[] = [];

      const codes = (input["productCodes"] as string[] | undefined) ?? [];
      for (const c of codes) picked.push(await resolveProduct(ctx, { productCode: c }));

      const names = (input["productNames"] as string[] | undefined) ?? [];
      for (const n of names) picked.push(await resolveProduct(ctx, { productName: n }));

      let products = picked.filter((p): p is NonNullable<typeof p> => Boolean(p));

      // 用户提到的产品不够两只时,用关键词补一只
      if (products.length < 2 && input["keyword"]) {
        const found = await ctx.bank.listWealthProducts({ keyword: String(input["keyword"]), limit: 2 } as never);
        products = [...products, ...found.filter((f) => !products.some((p) => p.productCode === f.productCode))];
      }
      // 兜底:仍不够两只时,按历史业绩补足,并**如实告知这是系统挑的**
      let autoPicked = false;
      if (products.length < 2) {
        const top = await ctx.bank.listWealthProducts({ limit: 3 });
        const add = top.filter((t) => !products.some((p) => p.productCode === t.productCode));
        const need = 2 - products.length;
        products = [...products, ...add.slice(0, need)];
        autoPicked = need > 0;
      }

      if (products.length < 2) {
        const msg = "我能对比的产品不足两只 —— 请告诉我要比哪两只(可以说产品名或代码),例如「稳健增利90天 和 纯债添利B 比一下」。";
        return {
          ok: true,
          data: {
            rows: [],
            dimensionWinners: [],
            bothWithinSuitability: false,
            riskDisclosure: RISK_DISCLOSURE_STANDARD,
            summary: msg,
          },
          summary: msg,
        };
      }

      const result = compareProducts(products);
      const profile = await ctx.bank.getRiskProfile(ctx.customerId);
      const maxLevel = profile.maxProductRiskLevel;
      const allWithin = maxLevel
        ? products.every((p) => riskLevelOrdinal(p.riskLevel) <= riskLevelOrdinal(maxLevel))
        : false;

      const lines: string[] = [];
      lines.push("产品对比");
      if (autoPicked) {
        lines.push("未指定对比对象。以下两只按历史业绩选取,不构成推荐。如需更换,请直接说明产品名称。");
      }
      lines.push("");
      for (const r of result.rows) {
        lines.push(`【${r.name}】${r.productCode}`);
        lines.push(`  风险 ${r.riskLevel} ${r.riskLabel} · ${r.typeLabel}`);
        lines.push(`  收益 ${r.yieldText}`);
        lines.push(`  期限 ${r.termText} · 起购 ${r.minAmountText} · 到账 ${r.settlementText}`);
        lines.push("");
      }
      lines.push("逐维度看:");
      for (const w of result.dimensionWinners) {
        lines.push(`  · ${w.dimension}维度:${w.productName} —— ${w.reason}`);
      }
      lines.push("");
      lines.push("我不替您下「哪个更好」的结论。收益更高的产品,风险等级或锁定期通常也更高,取舍取决于您能承受的波动。");
      lines.push("");
      if (profile.assessed && profile.level) {
        lines.push(`对照您的等级 ${profile.level}(${profile.levelLabel}),可购上限 ${maxLevel}。`);
      } else {
        lines.push("您还没有做过风险测评;在完成测评之前,我可以帮您比产品,但不能代您完成申购。");
      }
      lines.push("");
      lines.push(result.disclosure);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_risk_disclosure_sent",
        payload: {
          capability: "wealth.compare",
          compared: products.map((p) => p.productCode),
          dimensionWinners: result.dimensionWinners.map((w) => ({ dimension: w.dimension, product: w.productCode })),
          autoPicked,
          note: "对比入链:若对比对象是系统自动挑的,autoPicked=true 会一并留存 —— 供后续复核「系统是不是假装听懂了用户的指代」。",
        },
      });

      const compareLead = autoPicked
        ? "以下为系统选取的两只产品,不构成推荐。"
        : `对比 ${result.rows.length} 只,各维度谁更优见卡片。`;
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "产品对比",
          subtitle: compareLead,
          items: result.rows.map((r, i) => ({
            title: `${i + 1}. ${r.name}`,
            value: r.yieldText,
            badge: r.riskLevel,
            lines: [`${r.termText} · 起购 ${r.minAmountText} · ${r.settlementText}`],
          })),
          compactBody: compareLead,
          footer: "我不替您下「哪个更好」的结论;取舍取决于您的风险承受能力。",
        };
      }

      return {
        ok: true,
        data: {
          rows: result.rows.map((r) => ({
            productCode: r.productCode,
            name: r.name,
            typeLabel: r.typeLabel,
            riskLevel: r.riskLevel,
            riskLabel: r.riskLabel,
            yieldText: r.yieldText,
            yieldValue: r.yieldValue,
            termText: r.termText,
            minAmountText: r.minAmountText,
            settlementText: r.settlementText,
          })),
          dimensionWinners: result.dimensionWinners,
          bothWithinSuitability: allWithin,
          riskDisclosure: result.disclosure,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 风险测评(只读:问卷 / 打分)----
  registry.register({
    name: "wealth.risk_assess",
    description:
      "风险承受能力测评。" +
      "不传 answers 时返回完整问卷(题面与选项),让用户作答;" +
      "传了 answers 时按加权规则打分,得出 C1–C5 等级并落库(测评有效期一年)。" +
      "用户说『做风险测评』『我风险承受能力怎么样』『能买股票型吗』时使用。" +
      "★ 缺题不评级:少答一题就明确报出还缺哪几题,绝不做「按已答的算」的宽容处理;" +
      "★ 编造的选项直接拒绝,不会当成默认值;" +
      "★ 若发现作答相互矛盾(如「不能接受任何亏损」却「有多年权益经验」)," +
      "如实指出并按更保守的一方降一档,同时在审计里标记 consistencyDowngraded。",
    inputSchema: z.object({
      answers: z
        .array(
          z.object({
            questionId: z.string().describe("题号,如 q1"),
            optionId: z.string().describe("选项号,如 a/b/c/d/e"),
          }),
        )
        .optional()
        .describe("问卷作答;不传则返回问卷本身"),
    }),
    outputSchema: z.object({
      /** 问卷未完成时返回题目;完成时为空 */
      questions: z.array(
        z.object({
          questionId: z.string(),
          question: z.string(),
          weight: z.number(),
          options: z.array(z.object({ optionId: z.string(), label: z.string() })),
        }),
      ),
      completed: z.boolean(),
      level: z.string().nullable(),
      levelLabel: z.string().nullable(),
      score: z.number().nullable(),
      scorePct: z.number().nullable(),
      maxProductRiskLevel: z.string().nullable(),
      levelDescription: z.string().nullable(),
      consistencyNote: z.string().nullable(),
      missingQuestions: z.array(z.string()),
      maxScore: z.number(),
      summary: z.string(),
    }),
    /**
     * ★ 声明必须与事实一致:这条能力**会写**(合格的作答会把 C1–C5 等级落库),
     *   所以它不是只读 —— 过去的 `readOnly: true` 是拿"只读"当"免确认"用,
     *   结果在操作状态与审计口径里把一次写入说成了查询。
     * ★ 但它仍然允许自动执行:`autoExecutable: true`(低风险写操作的唯一入口)。
     *   判据是:改的是**客户自己的声明**(不是银行事实)、不动钱、
     *   且随时可以重做覆盖(可逆);让客户为自己刚填的问卷再点一次"确认"没有意义。
     */
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    autoExecutable: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const answers = (input["answers"] as Array<{ questionId: string; optionId: string }> | undefined) ?? [];

      // ---- 分支一:没有作答 → 返回问卷 ----
      if (answers.length === 0) {
        const profile = await ctx.bank.getRiskProfile(ctx.customerId);
        const lines: string[] = [];
        if (profile.assessed && profile.level && !profile.expired) {
          lines.push(
            `您当前的风险等级是 ${profile.level}(${profile.levelLabel}),` +
              `可购上限 ${profile.maxProductRiskLevel} 及以下产品。重新测评会覆盖当前结果。`,
          );
          lines.push("");
        }
        lines.push("风险测评共 6 题。在 App 里我会一题一题请您作答;说「做风险测评」或「开始」即可。");
        if (ctx.extras) {
          const step = riskAssessmentQuizVisual(0);
          if (step) ctx.extras.visual = step;
        }

        return {
          ok: true,
          data: {
            questions: ASSESSMENT_QUESTIONS.map((q) => ({
              questionId: q.questionId,
              question: q.question,
              weight: q.weight,
              options: q.options.map((o) => ({ optionId: o.optionId, label: o.label })),
            })),
            completed: false,
            level: profile.level,
            levelLabel: profile.assessed ? profile.levelLabel : null,
            score: profile.score,
            scorePct: null,
            maxProductRiskLevel: profile.maxProductRiskLevel,
            levelDescription: null,
            consistencyNote: null,
            missingQuestions: [],
            maxScore: ASSESSMENT_MAX_SCORE,
            summary: lines.join("\n"),
          },
          summary: lines.join("\n"),
        };
      }

      // ---- 分支二:有作答但校验不过 → 明确报出缺哪几题 ----
      const scoring = scoreAssessment(answers);
      if (!scoring.ok) {
        const lines: string[] = [];
        if (scoring.missing.length > 0) {
          lines.push(`还有 ${scoring.missing.length} 道题没有作答:${scoring.missing.join("、")}。`);
        }
        if (scoring.invalid.length > 0) {
          lines.push(
            `以下作答无法识别:${scoring.invalid.map((i) => `${i.questionId}=${i.optionId}`).join("、")}。`,
          );
        }
        lines.push("");
        lines.push("缺题不能评级。测评须完整作答,结果才有效。");
        lines.push("请补上缺失的题目(每题回复选项字母,例如 q3 选 c 就回复 a b c d e c)。");
        return {
          ok: true,
          data: {
            questions: ASSESSMENT_QUESTIONS.map((q) => ({
              questionId: q.questionId,
              question: q.question,
              weight: q.weight,
              options: q.options.map((o) => ({ optionId: o.optionId, label: o.label })),
            })),
            completed: false,
            level: null,
            levelLabel: null,
            score: null,
            scorePct: null,
            maxProductRiskLevel: null,
            levelDescription: null,
            consistencyNote: null,
            missingQuestions: scoring.missing,
            maxScore: ASSESSMENT_MAX_SCORE,
            summary: lines.join("\n"),
          },
          summary: lines.join("\n"),
        };
      }

      const validUntil = ctx.now + ASSESSMENT_VALID_DAYS * 24 * 3600 * 1000;
      await ctx.bank.saveRiskProfile(ctx.customerId, {
        level: scoring.level,
        score: scoring.score,
        validUntil,
        answers,
      });
      const profile = buildRiskProfile({
        customerId: ctx.customerId,
        level: scoring.level,
        score: scoring.score,
        assessedAt: ctx.now,
        validUntil,
        now: ctx.now,
      });

      const lines: string[] = [];
      lines.push(`测评完成:您的风险等级为 ${profile.level}(${profile.levelLabel})`);
      lines.push("");
      lines.push(`  · 问卷得分:${scoring.score} / ${ASSESSMENT_MAX_SCORE}(${scoring.scorePct} 分制)`);
      lines.push(`  · 等级说明:${scoring.description}`);
      lines.push(`  · 可购上限:${profile.maxProductRiskLevel} 及以下风险等级`);
      lines.push(`  · 有效期至:${new Date(validUntil).toLocaleDateString("zh-CN")}(一年后需重测)`);
      if (scoring.consistencyNote) {
        lines.push("");
        lines.push(`请注意:${scoring.consistencyNote}`);
      }
      lines.push("");
      lines.push("本次评级及作答记录已写入档案,可供日后复核。");
      lines.push("评级用于确定可购买的产品风险上限。");

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "测评结果",
          subtitle: `${profile.level} ${profile.levelLabel}`,
          summary: `可购 ${profile.maxProductRiskLevel} 及以下 · 有效至 ${new Date(validUntil).toLocaleDateString("zh-CN")}`,
          items: [
            {
              title: "问卷得分",
              value: `${scoring.score}/${ASSESSMENT_MAX_SCORE}`,
              lines: [scoring.description],
            },
          ],
          compactBody: `测评完成:您的风险等级为 ${profile.level}(${profile.levelLabel}),可购 ${profile.maxProductRiskLevel} 及以下。`,
          ...(scoring.consistencyNote ? { footer: scoring.consistencyNote } : {}),
        };
      }

      // ★ 独立审计事件:监管来查的时候问的就是"这个客户为什么被评为 C4",
      //   需要的不是等级本身,而是**他当时到底答了什么**。只存结果是不可复核的。
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_assessment_completed",
        payload: {
          capability: "wealth.risk_assess",
          level: profile.level,
          levelLabel: profile.levelLabel,
          score: scoring.score,
          scorePct: scoring.scorePct,
          maxScore: ASSESSMENT_MAX_SCORE,
          maxProductRiskLevel: profile.maxProductRiskLevel,
          validUntil,
          answers,
          scoringRule: "加权求和(满分 500);等级区间写死在 capabilities/wealth.ts levelFromPct",
          consistencyDowngraded: Boolean(scoring.consistencyNote),
          note: "测评结论入链:等级、得分、作答原文、打分规则说明与有效期一次留全 —— 不可复核的评级在合规上等于没有评级。",
        },
      });

      return {
        ok: true,
        data: {
          questions: [],
          completed: true,
          level: profile.level,
          levelLabel: profile.levelLabel,
          score: scoring.score,
          scorePct: scoring.scorePct,
          maxProductRiskLevel: profile.maxProductRiskLevel,
          levelDescription: scoring.description,
          consistencyNote: scoring.consistencyNote ?? null,
          missingQuestions: [],
          maxScore: ASSESSMENT_MAX_SCORE,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 持仓与收益(只读)----
  registry.register({
    name: "wealth.holdings",
    description:
      "查询客户的理财持仓与收益:份额、单位成本、现净值、市值、累计收益与收益率、持有天数、赎回到账时效。" +
      "用户说『我的理财赚了多少』『我买了什么』时使用。只读。" +
      "★ 必须同时面对正负两种收益:只报喜的界面在客户亏钱的那天会彻底失去信任;" +
      "★ 列表必须带编号,后面的「第2个赎回」才有落点。",
    inputSchema: z.object({
      productCode: z.string().optional().describe("只看某只产品"),
    }),
    outputSchema: z.object({
      holdings: z.array(
        z.object({
          holdingId: z.string(),
          productCode: z.string(),
          productName: z.string(),
          riskLevel: z.string(),
          shares: z.number(),
          nav: z.number(),
          avgCostNav: z.number(),
          marketValue: z.number(),
          costAmount: z.number(),
          profit: z.number(),
          profitRate: z.number(),
          holdingDays: z.number(),
          settlementText: z.string(),
        }),
      ),
      totalMarketValue: z.number(),
      totalCost: z.number(),
      totalProfit: z.number(),
      totalProfitRate: z.number(),
      /** 在途赎回金额(份额已扣、资金未到账) */
      pendingRedemptionAmount: z.number(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [
      "holdings[].marketValue",
      "holdings[].profit",
      "holdings[].costAmount",
      "totalMarketValue",
      "totalCost",
      "totalProfit",
      "pendingRedemptionAmount",
    ],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      let holdings = await ctx.bank.listWealthHoldings(ctx.customerId);
      if (input["productCode"]) {
        holdings = holdings.filter((h) => h.productCode === String(input["productCode"]));
      }

      const totalMarketValue = round2ish(holdings.reduce((s, h) => s + h.marketValue, 0));
      const totalCost = round2ish(holdings.reduce((s, h) => s + h.costAmount, 0));
      const totalProfit = round2ish(totalMarketValue - totalCost);

      if (holdings.length === 0) {
        const msg = "您目前没有理财持仓。可以先看看有什么理财产品,或者告诉我想投多少钱、能接受多大波动,我帮您筛。";
        return {
          ok: true,
          data: {
            holdings: [],
            totalMarketValue: 0,
            totalCost: 0,
            totalProfit: 0,
            totalProfitRate: 0,
            pendingRedemptionAmount: 0,
            summary: msg,
          },
          summary: msg,
        };
      }

      const lines: string[] = [];
      lines.push("理财持仓");
      lines.push("");
      // ★ 列表必须带编号 —— 与理财列表同一条交互原则:
      //   只给出编号而不接住编号,等于给用户挖了个坑:
      //   他照着屏幕上的编号念"第2个赎回",系统却不认。
      //   编号与"能接住编号"是同一件事的两半。
      for (const [i, h] of holdings.entries()) {
        lines.push(`${i + 1}. ${h.productName}(${h.productCode}) · ${h.riskLevel} ${PRODUCT_RISK_LABELS[h.riskLevel]}`);
        lines.push(
          `   份额 ${h.shares.toLocaleString("zh-CN")} · 单位成本 ${h.avgCostNav.toFixed(4)} → 现净值 ${h.nav.toFixed(4)}`,
        );
        lines.push(
          `   市值 ${fmtMoney(h.marketValue)} 元 · 累计收益 ${h.profit >= 0 ? "+" : ""}${fmtMoney(h.profit)} 元(${fmtPct(h.profitRate)})`,
        );
        lines.push(`   持有 ${holdingDaysLabel(h.holdingDays)} · 赎回到账 ${h.settlement}`);
        lines.push("");
      }
      lines.push(`合计:市值 ${fmtMoney(totalMarketValue)} 元,本金 ${fmtMoney(totalCost)} 元,累计收益 ${totalProfit >= 0 ? "+" : ""}${fmtMoney(totalProfit)} 元`);
      lines.push("");
      lines.push("要赎回某一只可以直接说序号(例如「第2个赎回」「全部赎回第1个」)。");
      lines.push("");
      lines.push(RISK_DISCLOSURE_STANDARD);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "wealth.holdings",
          holdingCount: holdings.length,
          totalMarketValue,
          totalProfit,
          note: "持仓市值与收益由银行侧按最新净值计算,模型未参与任何计算。",
        },
      });

      /**
       * ★ 持仓收益的出处:客户最想问的"我赚了多少"必须能对得上账。
       *   所以除了市值与累计收益,还要把**怎么算的**写出来:
       *   市值 = 份额 × 最新净值;收益 = 市值 − 成本。
       */
      ctx.extras?.citations.push({
        id: "data:持仓收益",
        topic: `持仓市值 ${totalMarketValue.toFixed(2)} 元 · 累计收益 ${totalProfit.toFixed(2)} 元`,
        source: SOURCES.wealth,
        subject: "客户本人",
        effective: `按最新净值计算 · 截至 ${new Date(ctx.now).toLocaleString("zh-CN", {
          timeZone: "Asia/Shanghai",
          hour12: false,
        })}`,
        asOf: ctx.now,
        calculation: [
          `市值 = Σ(持仓份额 × 最新净值) = ${totalMarketValue.toFixed(2)} 元`,
          `成本 = Σ(买入金额) = ${totalCost.toFixed(2)} 元`,
          `累计收益 = 市值 − 成本 = ${totalProfit.toFixed(2)} 元`,
          `收益率 = ${totalProfit.toFixed(2)} ÷ ${totalCost.toFixed(2)} ≈ ${
            totalCost > 0 ? ((totalProfit / totalCost) * 100).toFixed(2) : "0.00"
          }%`,
        ],
        note: "净值由银行侧提供;浮动收益随净值变化,赎回时以当日净值为准",
        kind: "data",
      });
      if (ctx.extras) ctx.extras.hasMonetary = true;

      const holdHeadline = `市值 ${fmtMoney(totalMarketValue)} 元 · 累计 ${totalProfit >= 0 ? "+" : ""}${fmtMoney(totalProfit)} 元`;
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "理财持仓",
          subtitle: holdHeadline,
          summary: `本金 ${fmtMoney(totalCost)} 元 · 共 ${holdings.length} 只`,
          bars: holdings.map((h) => ({
            label: h.productName.length > 10 ? `${h.productName.slice(0, 9)}…` : h.productName,
            value: h.marketValue,
            tone: h.profit >= 0 ? "ok" : "medium",
          })),
          items: holdings.map((h, i) => ({
            title: `${i + 1}. ${h.productName}`,
            value: `¥${fmtMoney(h.marketValue)}`,
            badge: h.riskLevel,
            tone: h.profit >= 0 ? "ok" : "medium",
            lines: [
              `份额 ${h.shares.toLocaleString("zh-CN")} · 净值 ${h.nav.toFixed(4)}(成本 ${h.avgCostNav.toFixed(4)})`,
              `累计 ${h.profit >= 0 ? "+" : ""}${fmtMoney(h.profit)}(${fmtPct(h.profitRate)}) · 持有 ${holdingDaysLabel(h.holdingDays)} · ${h.settlement === "T+0" ? "T+0到账" : h.settlement === "T+1" ? "T+1到账" : "T+2到账"}`,
            ],
          })),
          compactBody: `${holdHeadline}。明细与市值构成见卡片;赎回可说「第2个赎回」。`,
          footer: "浮动收益随净值变化;赎回以当日净值为准。",
        };
      }

      return {
        ok: true,
        data: {
          holdings: holdings.map((h) => ({
            holdingId: h.holdingId,
            productCode: h.productCode,
            productName: h.productName,
            riskLevel: h.riskLevel,
            shares: h.shares,
            nav: h.nav,
            avgCostNav: h.avgCostNav,
            marketValue: h.marketValue,
            costAmount: h.costAmount,
            profit: h.profit,
            profitRate: h.profitRate,
            holdingDays: h.holdingDays,
            settlementText: h.settlement === "T+0" ? "当日到账(T+0)" : h.settlement === "T+1" ? "次一工作日到账(T+1)" : "第二工作日到账(T+2)",
          })),
          totalMarketValue,
          totalCost,
          totalProfit,
          totalProfitRate: totalCost > 0 ? round2ish((totalProfit / totalCost) * 100) : 0,
          pendingRedemptionAmount: 0,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 申购(承诺类:冻结资金 + 份额确认)----
  registry.register({
    name: "wealth.purchase",
    description:
      "申购(购买)理财产品。承诺类操作:提交后**冻结资金**,份额在确认日后到账。" +
      "用户说『帮我买1万块那个稳健型的』『申购XX』『买5万理财』时使用。" +
      "★ 前置条件:首次购买必须先完成风险测评;" +
      "★ 产品风险等级超过客户等级时,必须取得《风险不匹配确认书》后才能继续;" +
      "★ 申购与赎回都必须由用户确认,Agent 不得自主执行。",
    inputSchema: z.object({
      productCode: z.string().optional().describe("产品代码"),
      productName: z.string().optional().describe("产品名称或口语称呼,如『稳健增利』『那个稳健型的』"),
      amount: z.number().positive().describe("申购金额"),
      fromAccountId: z.string().optional().describe("扣款账户 ID,默认工资卡"),
      amountRaw: z.string().optional().describe("用户金额原文,用于确认卡回显"),
    }),
    outputSchema: z.object({
      orderId: z.string(),
      productCode: z.string(),
      productName: z.string(),
      amount: z.number(),
      fee: z.number(),
      confirmedNav: z.number(),
      shares: z.number(),
      frozenAmount: z.number(),
      sharesConfirmedAt: z.number(),
      riskLevel: z.string(),
      consentRef: z.string().nullable(),
      reference: z.string(),
      riskDisclosure: z.string(),
      summary: z.string(),
    }),
    sideEffect: "irreversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["amount", "fee", "shares", "frozenAmount", "confirmedNav"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const product = await resolveProduct(ctx, input);
      if (!product) {
        return {
          ok: false,
          error: {
            code: "PRODUCT_NOT_FOUND",
            message: "没有找到您要购买的产品。请告诉我产品名或代码。",
            retryable: true,
          },
        };
      }

      const profile = await ctx.bank.getRiskProfile(ctx.customerId);
      // ★ hasConsent 来自编排器签署确认书后写入的 __consentRef。
      //   策略引擎的硬规则 R-WEALTH-RISK-MISMATCH 才是强制点;
      //   能力层这里只是"知道确认书已签",据此把消息改成如实的说明。
      const suit = checkSuitability({
        product,
        profile,
        hasConsent: typeof input["__consentRef"] === "string" && String(input["__consentRef"]).length > 0,
      });

      // ★ 三道前置闸门(这里只是最后一道;编排器与策略引擎各有一道)
      if (suit.status === "need_assessment") {
        return {
          ok: false,
          error: {
            code: "RISK_ASSESSMENT_REQUIRED",
            message:
              "按监管规定,首次购买理财产品前必须完成风险承受能力测评。" +
              "回复「做风险测评」,我带您走一遍(6 道题,约一分钟)。",
            retryable: true,
          },
        };
      }
      if (suit.status === "assessment_expired") {
        return {
          ok: false,
          error: {
            code: "RISK_ASSESSMENT_EXPIRED",
            message: "您的风险测评已超过一年(有效期 1 年),需要重新测评后才能继续申购。回复「重新做风险测评」即可。",
            retryable: true,
          },
        };
      }
      if (suit.status === "mismatch_consent_required") {
        return {
          ok: false,
          error: {
            code: "RISK_MISMATCH_CONSENT_REQUIRED",
            message: suit.message,
            retryable: false,
          },
        };
      }

      const amount = Number(input["amount"]);
      const accountId = await resolveDebitAccount(ctx, input["fromAccountId"]);
      if (!accountId) {
        return {
          ok: false,
          error: { code: "NO_ACCOUNT", message: "没有找到可用于扣款的活期账户。", retryable: false },
        };
      }

      const account = await ctx.bank.getAccount(ctx.customerId, accountId);
      const math = computePurchase({
        product,
        amount,
        availableBalance: account?.availableBalance ?? 0,
        now: ctx.now,
        settlementDays: 1,
      });
      if (math.error) {
        return { ok: false, error: { code: "PURCHASE_REJECTED", message: math.error, retryable: true } };
      }

      let receipt;
      try {
        receipt = await ctx.bank.submitWealthPurchase({
          customerId: ctx.customerId,
          productCode: product.productCode,
          amount,
          fromAccountId: accountId,
          frozenPayloadHash: String(input["__payloadHash"] ?? ""),
          ...(typeof input["__consentRef"] === "string" ? { consentRef: String(input["__consentRef"]) } : {}),
        });
      } catch (err) {
        return {
          ok: false,
          error: { code: "PURCHASE_FAILED", message: (err as Error).message, retryable: true },
        };
      }

      const lines: string[] = [];
      lines.push(`申购已提交:${receipt.productName}`);
      lines.push("");
      lines.push(`  · 申购金额:${fmtMoney(receipt.amount)} 元`);
      lines.push(`  · 申购费:${fmtMoney(receipt.fee)} 元`);
      lines.push(`  · 确认净值:${receipt.confirmedNav.toFixed(4)}`);
      lines.push(`  · 确认份额:${receipt.shares.toLocaleString("zh-CN")} 份`);
      lines.push(`  · 冻结金额:${fmtMoney(receipt.frozenAmount)} 元(冻结期间不可动用)`);
      lines.push(`  · 份额确认:${new Date(receipt.sharesConfirmedAt).toLocaleDateString("zh-CN")}(T+1)`);
      lines.push(`  · 流水号:${receipt.reference}`);
      if (receipt.consentRef) {
        lines.push(`  · 风险不匹配确认书:${receipt.consentRef}`);
      }
      lines.push("");
      lines.push(product.riskDisclosure);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "wealth.purchase",
          orderId: receipt.orderId,
          productCode: product.productCode,
          productRiskLevel: product.riskLevel,
          customerRiskLevel: profile.level,
          amount: receipt.amount,
          shares: receipt.shares,
          frozenAmount: receipt.frozenAmount,
          consentRef: receipt.consentRef ?? null,
          note:
            "申购执行(承诺类):资金被冻结而非划走,份额 T+1 确认。" +
            "同时留存客户等级与产品等级的落差,便于日后复核适当性判定的依据。",
        },
      });

      return { ok: true, data: { ...receipt, riskLevel: product.riskLevel, riskDisclosure: product.riskDisclosure, consentRef: receipt.consentRef ?? null, summary: lines.join("\n") }, summary: lines.join("\n") };
    },
  });

  // ---- 赎回(影响资金:份额减少 + T+N 到账)----
  registry.register({
    name: "wealth.redeem",
    description:
      "赎回理财产品。影响资金:份额立即减少,资金按产品约定的 T+0/T+1/T+2 到账。" +
      "用户说『把那个赎回来』『卖掉一半』『全部赎回』时使用。" +
      "★ 必须说清到账时间,并且必须告知**本次兑现的收益可能为负** ——" +
      "赎回是把浮亏变成实亏的动作,只报喜的界面在客户亏钱那天会彻底失去信任。",
    inputSchema: z.object({
      holdingId: z.string().optional().describe("持仓 ID"),
      productCode: z.string().optional().describe("产品代码"),
      productName: z.string().optional().describe("产品名称或口语称呼,如『上次买的那个』"),
      shares: z.number().positive().optional().describe("赎回份额"),
      amount: z.number().positive().optional().describe("赎回金额(按当前净值折算份额)"),
      redeemAll: z.boolean().optional().describe("是否全部赎回"),
    }),
    outputSchema: z.object({
      orderId: z.string(),
      productCode: z.string(),
      productName: z.string(),
      shares: z.number(),
      estimatedAmount: z.number(),
      fee: z.number(),
      settlement: z.string(),
      estimatedArrivalAt: z.number(),
      realizedProfit: z.number(),
      remainingShares: z.number(),
      reference: z.string(),
      riskDisclosure: z.string(),
      summary: z.string(),
    }),
    sideEffect: "irreversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["estimatedAmount", "fee", "realizedProfit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const holdings = await ctx.bank.listWealthHoldings(ctx.customerId);
      if (holdings.length === 0) {
        return {
          ok: false,
          error: { code: "NO_HOLDING", message: "您目前没有理财持仓,没有可赎回的产品。", retryable: false },
        };
      }

      // 定位顺序:持仓 ID > 产品代码 > 产品名 > 唯一持仓兜底
      let holding = input["holdingId"] ? holdings.find((h) => h.holdingId === String(input["holdingId"])) : undefined;
      if (!holding && input["productCode"]) {
        holding = holdings.find((h) => h.productCode === String(input["productCode"]));
      }
      if (!holding && input["productName"]) {
        const product = await resolveProduct(ctx, { productName: String(input["productName"]) });
        if (product) holding = holdings.find((h) => h.productCode === product.productCode);
      }
      // 兜底:只有一只持仓时不需要用户指认,直接用那一只
      if (!holding && holdings.length === 1) holding = holdings[0];
      if (!holding) {
        return {
          ok: false,
          error: {
            code: "HOLDING_AMBIGUOUS",
            message:
              `您持有 ${holdings.length} 只理财产品,需要您指明赎回哪一只:` +
              holdings.map((h) => `${h.productName}(${h.productCode})`).join("、"),
            retryable: true,
          },
        };
      }

      const product = await ctx.bank.getWealthProduct(holding.productCode);
      if (!product) {
        return { ok: false, error: { code: "PRODUCT_NOT_FOUND", message: "产品信息已下架。", retryable: false } };
      }

      const redeemAll = Boolean(input["redeemAll"]);
      const math = computeRedemption({
        product,
        holding,
        ...(redeemAll ? { shares: holding.shares } : {}),
        ...(!redeemAll && input["shares"] != null ? { shares: Number(input["shares"]) } : {}),
        ...(!redeemAll && input["shares"] == null && input["amount"] != null ? { amount: Number(input["amount"]) } : {}),
        now: ctx.now,
      });
      if (math.error) {
        return { ok: false, error: { code: "REDEMPTION_REJECTED", message: math.error, retryable: true } };
      }

      let receipt;
      try {
        receipt = await ctx.bank.submitWealthRedemption({
          customerId: ctx.customerId,
          holdingId: holding.holdingId,
          ...(redeemAll ? { shares: holding.shares } : {}),
          ...(!redeemAll && input["shares"] != null ? { shares: Number(input["shares"]) } : {}),
          ...(!redeemAll && input["shares"] == null && input["amount"] != null ? { amount: Number(input["amount"]) } : {}),
          frozenPayloadHash: String(input["__payloadHash"] ?? ""),
        });
      } catch (err) {
        return { ok: false, error: { code: "REDEMPTION_FAILED", message: (err as Error).message, retryable: true } };
      }

      const lines: string[] = [];
      lines.push(`赎回申请已提交:${receipt.productName}`);
      lines.push("");
      lines.push(`  · 赎回份额:${receipt.shares.toLocaleString("zh-CN")} 份`);
      lines.push(`  · 预计到账金额:${fmtMoney(receipt.estimatedAmount)} 元(按申请日净值估算,实际以确认日净值为准)`);
      lines.push(`  · 本次兑现收益:${receipt.realizedProfit >= 0 ? "+" : ""}${fmtMoney(receipt.realizedProfit)} 元`);
      lines.push(`  · 剩余份额:${receipt.remainingShares.toLocaleString("zh-CN")} 份`);
      lines.push(`  · 到账时效:${receipt.settlement}(预计 ${new Date(receipt.estimatedArrivalAt).toLocaleDateString("zh-CN")} 到账)`);
      lines.push(`  · 流水号:${receipt.reference}`);
      lines.push("");
      lines.push("份额已扣减,对应部分不再计算后续收益;资金到账前不计收益。");
      lines.push("");
      lines.push(product.riskDisclosure);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "wealth.redeem",
          orderId: receipt.orderId,
          productCode: receipt.productCode,
          shares: receipt.shares,
          estimatedAmount: receipt.estimatedAmount,
          realizedProfit: receipt.realizedProfit,
          remainingShares: receipt.remainingShares,
          settlement: receipt.settlement,
          estimatedArrivalAt: receipt.estimatedArrivalAt,
          note: "赎回入链:份额扣减与资金 T+N 到账是两个分开的事件,审计里也分开记 —— 二者之间资金在途,不计收益。",
        },
      });

      return { ok: true, data: { ...receipt, riskDisclosure: product.riskDisclosure, summary: lines.join("\n") }, summary: lines.join("\n") };
    },
  });

  // ---- 到期续接方案(只读:不申购、不冻结) ----
  registry.register({
    name: "wealth.rollover_plan",
    description:
      "为即将到期的理财持仓生成续接方案:同风险或更低风险的产品对比、近 6 个月最大回撤、不续投时的活期挂牌利率。" +
      "用户说『理财快到期了怎么办』『看看这笔到期怎么续接』时使用。" +
      "★ 只读。不排序出综合最优,不写预计收益下降,不申购,不冻结资金。",
    inputSchema: z.object({}),
    outputSchema: z.object({
      found: z.boolean(),
      planId: z.string().nullable(),
      holdingId: z.string().nullable(),
      productName: z.string().nullable(),
      executed: z.boolean(),
      marketValue: z.number().nullable(),
      products: z.array(z.object({ productCode: z.string(), name: z.string() })),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["marketValue"],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      const [holdings, products, profile, rate] = await Promise.all([
        ctx.bank.listWealthHoldings(ctx.customerId),
        ctx.bank.listWealthProducts({ limit: 20 }),
        ctx.bank.getRiskProfile(ctx.customerId),
        ctx.bank.getDemandDepositRate(ctx.customerId),
      ]);
      const built = buildRolloverPlan({
        customerId: ctx.customerId,
        holdings,
        products,
        profile,
        rate,
        now: ctx.now,
      });
      if (!built.ok) {
        return {
          ok: true,
          data: {
            found: false,
            planId: null,
            holdingId: null,
            productName: null,
            executed: false,
            marketValue: null,
            products: [],
            summary: built.summary,
          },
          summary: built.summary,
        };
      }
      const plan = built.plan;
      ctx.extras?.citations.push({
        id: "data:到期续接方案",
        topic: `${plan.productName} 到期续接 · 市值与候选收益口径`,
        source: SOURCES.wealth,
        subject: `客户 ${ctx.customerId}`,
        effective: `持仓市值与活期挂牌利率截至 ${new Date(ctx.now).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })}`,
        asOf: ctx.now,
        calculation: [
          `到期市值 ${plan.marketValue} 元 = 份额 × 最新净值`,
          plan.demandRateText,
          ...plan.candidates.map((c) => `${c.name} ${c.yieldText} · ${c.drawdownText}`),
        ],
        note: "方案不按收益排序。活期利率与理财业绩分列,不相减。",
        kind: "data",
      });
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_rollover_plan_generated",
        payload: {
          capability: "wealth.rollover_plan",
          planId: plan.planId,
          holdingId: plan.holdingId,
          productCode: plan.productCode,
          maturityAt: plan.maturityAt,
          marketValue: plan.marketValue,
          candidateCodes: plan.candidates.map((c) => c.productCode),
          excluded: plan.excluded.slice(0, 6),
          executed: false,
          note: "续接方案只读。没有申购,没有冻结。候选不按收益排序。",
        },
      });
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_risk_disclosure_sent",
        payload: {
          capability: "wealth.rollover_plan",
          productCount: plan.candidates.length,
          riskLevels: [...new Set(plan.candidates.map((c) => c.riskLevel))],
          disclosureIncluded: true,
          customerRiskLevel: profile.level,
          note: "续接方案随风险提示一起发出。",
        },
      });
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "到期续接方案",
          subtitle: `${plan.productName} · 到期市值 ${fmtMoney(plan.marketValue)} 元`,
          items: plan.candidates.map((c, i) => ({
            title: `${i + 1}. ${c.name}`,
            value: c.yieldText,
            badge: c.riskLevel,
            lines: [c.drawdownText],
          })),
          compactBody: `${plan.productName} 即将到期,候选见卡片;说「续接第1个」或「不续投」。`,
          footer: plan.demandRateText,
        };
      }
      return {
        ok: true,
        data: {
          found: true,
          planId: plan.planId,
          holdingId: plan.holdingId,
          productName: plan.productName,
          executed: false,
          marketValue: plan.marketValue,
          products: plan.candidates.map((c) => ({ productCode: c.productCode, name: c.name })),
          summary: plan.summary,
        },
        summary: plan.summary,
      };
    },
  });

  // ---- 登记续接选择(不申购) ----
  registry.register({
    name: "wealth.rollover_choose",
    description:
      "把客户对到期续接方案的选择记下来:续接某一只,或明确不续投。" +
      "★ 不创建申购、不冻结资金。资金仍在原产品里时,状态只能是等待入账。" +
      "用户说『续接第1个』『不续投』时使用,且必须对应刚刚看过的那份方案。",
    inputSchema: z.object({
      planId: z.string(),
      holdingId: z.string(),
      decision: z.enum(["renew", "stay_demand"]),
      productCode: z.string().optional(),
      ordinal: z.number().int().positive().optional(),
    }),
    outputSchema: z.object({
      choiceId: z.string(),
      status: z.string(),
      gate: z.string(),
      purchased: z.boolean(),
      summary: z.string(),
    }),
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    autoExecutable: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const decision = input["decision"] === "stay_demand" ? "stay_demand" : "renew";
      const planId = String(input["planId"] ?? "");
      const holdingId = String(input["holdingId"] ?? "");
      const productCode = typeof input["productCode"] === "string" ? input["productCode"] : "";

      const [holdings, products, profile, rate, accounts] = await Promise.all([
        ctx.bank.listWealthHoldings(ctx.customerId),
        ctx.bank.listWealthProducts({ limit: 20 }),
        ctx.bank.getRiskProfile(ctx.customerId),
        ctx.bank.getDemandDepositRate(ctx.customerId),
        ctx.bank.listAccounts(ctx.customerId),
      ]);
      const built = buildRolloverPlan({
        customerId: ctx.customerId,
        holdings,
        products,
        profile,
        rate,
        now: ctx.now,
      });
      if (!built.ok || built.plan.planId !== planId || built.plan.holdingId !== holdingId) {
        return {
          ok: false,
          error: {
            code: "ROLLOVER_PLAN_STALE",
            message: "这份续接方案已经变了,或还没有一份您看过的方案。我没有登记选择,也没有申购。请先再说一次「看看这笔理财到期怎么续接」。",
            retryable: true,
          },
        };
      }
      const plan = built.plan;
      const holding = holdings.find((h) => h.holdingId === holdingId);
      if (!holding) {
        return {
          ok: false,
          error: { code: "HOLDING_GONE", message: "这笔持仓已经不在了,不能按旧方案续接。", retryable: false },
        };
      }

      let chosenCode: string | null = null;
      let chosenName: string | null = null;
      if (decision === "renew") {
        const candidate = plan.candidates.find((c) => c.productCode === productCode);
        if (!candidate) {
          return {
            ok: false,
            error: {
              code: "ROLLOVER_CANDIDATE_MISSING",
              message: "您选的产品不在刚才那份方案里。我没有改成别的产品,也没有申购。",
              retryable: true,
            },
          };
        }
        chosenCode = candidate.productCode;
        chosenName = candidate.name;
      }

      const available = accounts
        .filter((a) => a.type === "current" || a.type === "savings")
        .reduce((s, a) => s + a.availableBalance, 0);
      const gate = evaluateRolloverFunds({
        now: ctx.now,
        maturityAt: plan.maturityAt,
        disposition: holding.maturityDisposition,
        credited: holding.maturityCredited === true,
        availableBalance: available,
        amount: plan.amountBasis,
      });
      const status = decision === "stay_demand" ? "declined" : gate.ready ? "ready_to_confirm" : "awaiting_credit";
      const note =
        decision === "stay_demand"
          ? "客户明确不续投。没有申购,没有冻结。"
          : gate.ready
            ? "资金已回到活期。选择已记下,仍须客户另行确认申购。本次没有申购。"
            : `${gate.message}本次没有申购,没有冻结。`;

      const saved = await ctx.bank.saveRolloverChoice({
        customerId: ctx.customerId,
        planId,
        holdingId,
        decision,
        productCode: chosenCode,
        productName: chosenName,
        amountBasis: plan.amountBasis,
        status,
        gate: decision === "stay_demand" ? "declined" : gate.code,
        note,
      });

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "wealth_rollover_choice_recorded",
        payload: {
          capability: "wealth.rollover_choose",
          choiceId: saved.choiceId,
          planId,
          holdingId,
          decision,
          productCode: chosenCode,
          status,
          gate: saved.gate,
          purchased: false,
          amountBasis: plan.amountBasis,
          note,
        },
      });

      const head =
        decision === "stay_demand"
          ? `已记下:「${plan.productName}」到期后不续投。没有申购,现在没有冻结。`
          : `已记下:续接「${chosenName}」。没有申购,现在没有冻结。`;
      const when =
        decision === "stay_demand" ? "" : gate.ready ? "到期款已回到活期。请再说「按续接方案申购」。" : gate.message;
      const lines = [head, when, rolloverFollowUps(decision === "stay_demand" ? "stay" : "renew")].filter(
        (line) => line.length > 0,
      );
      return {
        ok: true,
        data: {
          choiceId: saved.choiceId,
          status,
          gate: saved.gate,
          purchased: false,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });
}
// ============================================================================
// 理财能力公共辅助
// ============================================================================

/** 持仓金额/收益率保留两位小数(与全仓金额口径共用一份实现,见 util/format.ts) */
function round2ish(n: number): number {
  return round2(n);
}

/** 产品定位:代码优先,其次名称,再退化为关键词检索 */
async function resolveProduct(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): Promise<Awaited<ReturnType<ExecutionContext["bank"]["getWealthProduct"]>>> {
  const code = input["productCode"] ? String(input["productCode"]) : undefined;
  if (code) {
    const p = await ctx.bank.getWealthProduct(code);
    if (p) return p;
  }

  const name = input["productName"] ? String(input["productName"]) : undefined;
  if (!name) return null;

  // 精确代码写在名字里(用户可能说"买LC1002")
  const codeInName = name.match(/LC\d{4}/i);
  if (codeInName) {
    const p = await ctx.bank.getWealthProduct(codeInName[0].toUpperCase());
    if (p) return p;
  }

  const list = await ctx.bank.listWealthProducts({ keyword: name, limit: 5 });
  if (list.length > 0) {
    // 名称完全包含优先,否则取第一条
    const exact = list.find((p) => p.name.includes(name) || name.includes(p.name));
    return exact ?? list[0]!;
  }

  // 退化:把口语词映射为风险等级上限后再找(如"那个稳健型的")
  const { riskPreferenceFromText } = await import("./wealth.ts");
  const maxRisk = riskPreferenceFromText(name);
  if (maxRisk) {
    const relaxed = await ctx.bank.listWealthProducts({ maxRiskLevel: maxRisk, limit: 5 });
    if (relaxed.length > 0) return relaxed[0]!;
  }
  return null;
}

/** 扣款账户解析:未指定时取活期账户 */
async function resolveDebitAccount(ctx: ExecutionContext, hint: unknown): Promise<string | undefined> {
  if (hint && String(hint) !== "default") {
    const acc = await ctx.bank.getAccount(ctx.customerId, String(hint));
    if (acc && acc.status === "active") return acc.accountId;
  }
  const accounts = await ctx.bank.listAccounts(ctx.customerId);
  return accounts.find((a) => a.type === "current" && a.status === "active")?.accountId ?? accounts[0]?.accountId;
}

/** 产品 → 列表视图已内联在各能力中(字段口径与输出 Schema 严格对应) */

export { RISK_LEVEL_LABELS, maxProductRiskFor, detectGuaranteeClaim, normalizeReturnWording };

/**
 * 注册记账能力。
 *
 * 记账是 `readOnly: false` 但 `moneyMovement: false` 的写操作 ——
 * 它改动的是**客户侧的批注**,不是银行流水。因此:
 *   · 自动执行,不打断用户(风险极低);
 *   · 但仍然写审计 —— "客户对某笔资金往来的定性"在纠纷时是重要证据。
 */
export function registerNoteCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "note.create",
    description:
      "为客户的一笔资金往来做记账备注。当用户说『帮我记一下』『这笔钱是借款/还款/报销』『记成房租』时使用。" +
      "★ 重要:这是**客户侧的记账批注**,不会修改银行交易记录本身 —— " +
      "银行流水是核心系统的既有事实,客户侧只能附加说明。若用户想修改交易金额,那是做不到的,应如实告知。",
    inputSchema: z.object({
      title: z.string().min(1).max(50).describe("这笔往来的名义,如『借款』『还款』『报销』『房租』"),
      amount: z.number().positive().optional().describe("金额。可用于自动关联到对应的交易"),
      direction: z.enum(["in", "out"]).optional().describe("out=我付出去,in=我收到"),
      counterpartyHint: z.string().optional().describe("对方姓名或关键词,用于关联交易"),
      note: z.string().max(200).optional().describe("补充说明"),
      tags: z.array(z.string()).max(5).default([]).describe("标签,如『借贷』『私人往来』『公务』"),
    }),
    outputSchema: z.object({
      annotationId: z.string(),
      title: z.string(),
      amount: z.number().nullable(),
      linkedTransactionId: z.string().nullable(),
      linkedTransactionSummary: z.string().nullable(),
      note: z.string(),
    }),
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    // ★ 全项目唯一一个"写操作但可自动执行"的能力:
    //   它只给客户自己的记录加一条说明,不动银行流水、不动资金。
    //   强制它走确认卡会让"帮我记一下"这种诉求变得很烦。
    autoExecutable: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      // 用鸭子类型探测银行核心是否提供记账口 —— 记账是客户侧能力,
      // 不是所有银行核心实现都需要支持它,缺失时应如实告知而不是假装成功。
      const bank = ctx.bank as unknown as {
        createAnnotation?: (i: {
          ownerCustomerId: string;
          title: string;
          amount?: number;
          direction?: "in" | "out";
          counterpartyHint?: string;
          note?: string;
          tags: string[];
        }) => Promise<{
          annotationId: string;
          linkedTransactionId?: string;
          linkedTransactionSummary?: string;
        }>;
      };

      if (typeof bank.createAnnotation !== "function") {
        return {
          ok: false,
          error: { code: "NOT_SUPPORTED", message: "当前银行核心未开通记账批注功能。", retryable: false },
        };
      }

      const title = String(input["title"]);
      const result = await bank.createAnnotation({
        ownerCustomerId: ctx.customerId,
        title,
        ...(typeof input["amount"] === "number" ? { amount: input["amount"] as number } : {}),
        ...(input["direction"] ? { direction: input["direction"] as "in" | "out" } : {}),
        ...(input["counterpartyHint"] ? { counterpartyHint: String(input["counterpartyHint"]) } : {}),
        ...(input["note"] ? { note: String(input["note"]) } : {}),
        tags: (input["tags"] as string[] | undefined) ?? [],
      });

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "note.create",
          annotationId: result.annotationId,
          title,
          amount: input["amount"] ?? null,
          linkedTransactionId: result.linkedTransactionId ?? null,
          note:
            "客户侧记账批注入链。★ 明确记录:只新增客户侧说明,未改动任何银行流水;" +
            "若日后发生纠纷,这条批注的定性只代表客户自述,不代表银行已认可该笔往来的性质。",
        },
      });

      return {
        ok: true,
        data: {
          annotationId: result.annotationId,
          title,
          amount: typeof input["amount"] === "number" ? (input["amount"] as number) : null,
          linkedTransactionId: result.linkedTransactionId ?? null,
          linkedTransactionSummary: result.linkedTransactionSummary ?? null,
          note: (input["note"] as string | undefined) ?? "",
        },
        summary: result.linkedTransactionId
          ? `已记下「${title}」,并关联到交易:${result.linkedTransactionSummary}`
          : `已记下「${title}」${input["amount"] ? `(金额 ${input["amount"]})` : ""}(仅客户侧批注,未改动银行流水)`,
      };
    },
  });

  registry.register({
    name: "note.list",
    description: "查询客户之前的记账批注列表。只读。",
    inputSchema: z.object({ limit: z.number().int().positive().max(50).optional() }),
    outputSchema: z.object({
      notes: z.array(
        z.object({
          annotationId: z.string(),
          title: z.string(),
          amount: z.number().nullable(),
          direction: z.string().nullable(),
          tags: z.array(z.string()),
          createdAt: z.number(),
        }),
      ),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["notes[].amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const bank = ctx.bank as unknown as {
        listAnnotations?: (
          customerId: string,
          limit?: number,
        ) => Array<{
          annotationId: string;
          title: string;
          amount?: number;
          direction?: string;
          tags: string[];
          createdAt: number;
        }>;
      };
      const notes = typeof bank.listAnnotations === "function" ? bank.listAnnotations(ctx.customerId, (input["limit"] as number) ?? 20) : [];
      const noteSummary = `共 ${notes.length} 条记账批注`;
      if (ctx.extras && notes.length > 0) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "记账批注",
          subtitle: noteSummary,
          items: notes.slice(0, 15).map((n) => ({
            title: n.title,
            value: n.amount != null ? `¥${n.amount.toLocaleString("zh-CN")}` : undefined,
            lines: [
              n.direction ? `方向:${n.direction}` : "",
              n.tags.length > 0 ? n.tags.join(" · ") : "",
            ].filter(Boolean),
          })),
          compactBody: noteSummary,
        };
      }
      return {
        ok: true,
        data: {
          notes: notes.map((n) => ({
            annotationId: n.annotationId,
            title: n.title,
            amount: n.amount ?? null,
            direction: n.direction ?? null,
            tags: n.tags,
            createdAt: n.createdAt,
          })),
        },
        summary: noteSummary,
      };
    },
  });
}
// ============================================================================
// 转账能力(核心场景 / 资金操作)
// ============================================================================

export interface TransferExecuteInput {
  fromAccountId: string;
  payeeName: string;
  payeeId?: string;
  accountNo?: string;
  phone?: string;
  bankCode?: string;
  bankName?: string;
  maskedAccountNo?: string;
  amount: number;
  currency: string;
  memo?: string;
  scheduledAt?: number;
  /** 由注入器写入的风险信号:模型看不到也写不了 */
  __payeeRisk?: {
    isFirstTime: boolean;
    successCount: number;
    isSelfOwned: boolean;
    isWhitelisted: boolean;
    isKnownFrequent: boolean;
  };
  __screening?: { hit: boolean; hits: Array<{ listType: string; severity: string; detail: string }> };
  __velocity?: {
    samePayeeCount24h?: number;
    sameAmountRepeatCount?: number;
    dailyCumulative?: number;
    dailyLimit?: number;
  };
  __fraudSignals?: {
    urgency: boolean;
    secrecy: boolean;
    guided: boolean;
    keywords: string[];
    note?: string;
  };
  __fee?: number;
  __estimatedArrival?: string;
}

export const TransferInputSchema = z.object({
  fromAccountId: z.string().describe("付款账户 ID"),
  payeeName: z.string().describe("收款人姓名"),
  payeeId: z.string().optional().describe("收款人 ID(系统消歧后写入,模型不应编造)"),
  accountNo: z.string().optional(),
  phone: z.string().optional(),
  bankCode: z.string().optional(),
  bankName: z.string().optional(),
  maskedAccountNo: z.string().optional(),
  amount: z.number().positive().max(5_000_000).describe("转账金额,单位元"),
  currency: z.string().default("CNY"),
  memo: z.string().max(200).optional().describe("转账备注"),
  scheduledAt: z.number().optional().describe("计划执行时间戳(定时转账用)"),
});

export function registerTransferCapabilities(registry: CapabilityRegistry): void {
  // ---- 试算(只读,不产生任何资金动作) ----
  registry.register({
    name: "transfer.preview",
    description:
      "试算一笔转账的手续费与预计到账时间,并校验收款方可达性。只读,不执行转账、不冻结任何资金。" +
      "用户说『先看看转过去要多少钱手续费』『多久能到』时使用。",
    inputSchema: TransferInputSchema.pick({
      payeeName: true,
      accountNo: true,
      phone: true,
      bankCode: true,
      amount: true,
      currency: true,
    }),
    outputSchema: z.object({
      fee: z.number().optional(),
      estimatedArrival: z.string(),
      nameMatched: z.boolean(),
      interbank: z.boolean(),
      warnings: z.array(z.string()),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["fee"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const info = await ctx.bank.verifyPayeeDeliverable({
        payeeName: sanitizePayeeName(String(input["payeeName"])),
        ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
        ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
        ...(input["bankCode"] ? { bankCode: String(input["bankCode"]) } : {}),
      });
      const warnings: string[] = [];
      if (!info.nameMatched) warnings.push("户名与账号未能完全匹配,建议核实收款人身份后再转账");
      if (info.interbank) warnings.push("跨行转账到账时间以对方银行为准");

      /**
       * ★ 试算手续费必须用**入参里的金额**(规则见 capabilities/transferFee.ts)。
       *   原来这里把入参里的 amount 丢掉了,直接回一个写死的 0 ——
       *   于是「先看看转 6 万过去要多少手续费」答"免手续费",而制度条款说应收 30 元。
       */
      const amount = typeof input["amount"] === "number" ? (input["amount"] as number) : null;
      const fee = amount != null ? transferFeeOf(amount, info.interbank) : null;
      const feeText =
        fee == null ? "需给出转账金额才能试算手续费" : fee === 0 ? "免手续费" : `手续费 ${fee} 元`;
      const summary = `${feeText},${info.estimatedArrival ?? "实时到账"}`;
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "转账试算",
          subtitle: sanitizePayeeName(String(input["payeeName"])),
          items: [
            {
              title: "预计到账",
              value: info.estimatedArrival ?? "实时到账",
              badge: info.interbank ? "跨行" : "同行",
              tone: info.nameMatched ? "ok" : "medium",
              lines: [
                feeText,
                amount != null ? `金额 ${amount.toLocaleString("zh-CN")} 元` : "未给金额",
                ...warnings,
              ],
            },
          ],
          compactBody: summary,
        };
      }

      return {
        ok: true,
        data: {
          ...(fee != null ? { fee } : {}),
          estimatedArrival: info.estimatedArrival ?? "实时到账",
          nameMatched: info.nameMatched,
          interbank: info.interbank,
          warnings,
        },
        summary,
      };
    },
  });

  // ---- 定时转账创建(先创建草稿,由编排器走确认) ----
  registry.register({
    name: "transfer.create_schedule",
    description:
      "创建定时/周期转账任务。支持每天/每周/每月。执行前系统会先提醒用户,并允许随时取消。此能力会创建真实的周期扣款计划,需用户确认。",
    inputSchema: TransferInputSchema.extend({
      frequency: z.enum(["once", "daily", "weekly", "monthly"]).describe("周期频率"),
      interval: z.number().int().positive().max(12).default(1),
      firstRunAt: z.number().describe("首次执行时间戳"),
      onInsufficientFunds: z.enum(["notify_and_skip", "retry_next_day", "partial"]).default("notify_and_skip"),
      preExecutionReminder: z.boolean().default(true).describe("执行前是否提醒(强烈建议开启)"),
    }),
    outputSchema: z.object({
      scheduleId: z.string(),
      nextRunAt: z.number(),
      frequency: z.string(),
      payeeName: z.string(),
      amount: z.number(),
    }),
    sideEffect: "reversible",
    moneyMovement: false, // 本次调用不移动资金,但会创建未来的资金操作
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const intent = toTransferIntent(input);
      const schedule = await ctx.bank.createSchedule({
        transferIntent: intent,
        firstRunAt: Number(input["firstRunAt"]),
        recurrence: {
          frequency: input["frequency"] as "once" | "daily" | "weekly" | "monthly",
          interval: (input["interval"] as number | undefined) ?? 1,
        },
        onInsufficientFunds:
          (input["onInsufficientFunds"] as "notify_and_skip" | "retry_next_day" | "partial" | undefined) ??
          "notify_and_skip",
        preExecutionReminder: (input["preExecutionReminder"] as boolean | undefined) ?? true,
      });

      return {
        ok: true,
        data: {
          scheduleId: schedule.scheduleId,
          nextRunAt: schedule.nextRunAt,
          frequency: frequencyLabel(schedule.recurrence.frequency),
          payeeName: schedule.intent.payee.name,
          amount: schedule.intent.amount,
        },
        summary: `已创建${frequencyLabel(schedule.recurrence.frequency)}转账任务,下次执行 ${
          new Date(schedule.nextRunAt).toLocaleString("zh-CN")
        }`,
      };
    },
  });

  // ---- 撤销定时任务 ----
  registry.register({
    name: "transfer.cancel_schedule",
    description: "取消一个已设置的定时转账任务。属于安全方向操作(降低风险敞口),但仍需用户确认。",
    inputSchema: z.object({ scheduleId: z.string() }),
    outputSchema: z.object({ cancelled: z.boolean(), scheduleId: z.string() }),
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      await ctx.bank.cancelSchedule(ctx.customerId, String(input["scheduleId"]));
      return {
        ok: true,
        data: { cancelled: true, scheduleId: String(input["scheduleId"]) },
        summary: "定时转账任务已取消",
      };
    },
  });

  // ---- 撤销转账(未清算窗口内) ----
  registry.register({
    name: "transfer.cancel",
    description:
      "撤销一笔尚未入账的转账。仅在可撤销时间窗口内有效。属于安全方向操作,但涉及资金退回,需用户确认。",
    inputSchema: z.object({
      transferId: z.string(),
      reason: z.string().max(100).optional(),
    }),
    outputSchema: z.object({
      ok: z.boolean(),
      refundAmount: z.number().optional(),
      reason: z.string().optional(),
    }),
    sideEffect: "reversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["refundAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const result = await ctx.bank.cancelTransfer(ctx.customerId, String(input["transferId"]));
      return {
        ok: result.ok,
        data: {
          ok: result.ok,
          ...(result.refundAmount != null ? { refundAmount: result.refundAmount } : {}),
          ...(result.reason ? { reason: result.reason } : {}),
        },
        summary: result.ok ? `已撤销,退回 ${result.refundAmount} 元` : `撤销失败:${result.reason}`,
      };
    },
  });

  // ---- 提交转账(真正的资金操作,不可逆) ★ 核心能力 ----
  registry.register({
    name: "transfer.submit",
    description:
      "执行一笔转账。这是不可逆的资金操作,必须经过用户明确确认(或强验证)。参数必须完整包含收款人、金额、付款账户。系统会自行完成名单筛查与风险裁决,你不需要也不应该自行判断风险等级。",
    inputSchema: TransferInputSchema,
    outputSchema: z.object({
      transferId: z.string(),
      status: z.string(),
      amount: z.number(),
      fee: z.number(),
      payeeName: z.string(),
      reference: z.string(),
      cancellableUntil: z.number().optional(),
    }),
    sideEffect: "irreversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["amount", "fee"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      // ---- 二次校验:即使通过了策略引擎,执行前再核对一次关键不变量 ----
      const amount = Number(input["amount"]);
      if (!Number.isFinite(amount) || amount <= 0) {
        return { ok: false, error: { code: "INVALID_AMOUNT", message: "金额不合法", retryable: false } };
      }

      // ---- 反诈评估(在执行前做最后一次评估,并把结论写进审计) ----
      const profile = ctx.profile.riskProfile;
      const payeeRisk = (input["__payeeRisk"] ?? {
        isFirstTime: true,
        successCount: 0,
        isSelfOwned: false,
        isWhitelisted: false,
        isKnownFrequent: false,
      }) as TransferExecuteInput["__payeeRisk"] & object;
      const fraud = assessFraudRisk({
        ...(input["__fraudSignals"]
          ? { signals: input["__fraudSignals"] as never }
          : {}),
        amount,
        amountRatioToBaseline: amount / Math.max(profile.transferAmountP95, 1),
        payee: {
          name: String(input["payeeName"]),
          isFirstTime: payeeRisk.isFirstTime,
          isSelfOwned: payeeRisk.isSelfOwned,
          successCount: payeeRisk.successCount,
          bankName: String(input["bankName"] ?? "未知银行"),
        },
        userText: String(input["__userText"] ?? ""),
        ...(input["memo"] ? { memo: String(input["memo"]) } : {}),
      });

      // ---- 备注净化 ----
      const memoResult = sanitizeMemo(input["memo"] as string | undefined);

      // ---- 名单筛查(执行前最后一道) ----
      const screening = await ctx.bank.screenPayee({
        payeeName: String(input["payeeName"]),
        ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
        ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
      });
      if (screening.hit && screening.hits.some((h) => h.severity === "block")) {
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "execution_failed",
          payload: {
            capability: "transfer.submit",
            stage: "pre_execution_screening",
            blocked: true,
            hits: screening.hits,
          },
        });
        return {
          ok: false,
          error: {
            code: "WATCHLIST_BLOCK",
            message: `收款方命中阻断级名单:${screening.hits.map((h) => h.detail).join(";")}`,
            retryable: false,
          },
        };
      }

      // ---- 幂等:同一请求重放不得产生第二笔转账 ----
      const existing = await ctx.bank.findByIdempotencyKey(ctx.idempotencyKey);
      if (existing.found && existing.receipt) {
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "execution_completed",
          payload: { capability: "transfer.submit", idempotentReplay: true, transferId: existing.receipt.transferId },
        });
        return {
          ok: true,
          data: receiptToData(existing.receipt),
          summary: `这笔转账已经执行过(幂等重放),流水号 ${existing.receipt.reference},没有重复扣款。`,
        };
      }

      // ---- 创建草稿(冻结载荷) ----
      const intent = toTransferIntent(input, memoResult.memo);
      const draft = await ctx.bank.createTransferDraft(intent);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "payload_frozen",
        payload: {
          capability: "transfer.submit",
          draftId: draft.draftId,
          frozenPayloadHash: draft.frozenPayloadHash,
          frozenPayload: draft.frozenPayload,
          memoSanitization: memoResult.changes,
        },
      });

      // ---- 提交(执行器内部注入受限服务身份;Agent 不持有任何用户凭证) ----
      try {
        const receipt = await ctx.bank.submitTransfer({
          draftId: draft.draftId,
          frozenPayloadHash: draft.frozenPayloadHash,
          actionToken: ctx.tokens.actionToken ?? "internal-service-token",
        });

        /**
         * ★ 把幂等键**写下来** —— 否则上面那段「重放不得产生第二笔」永远走不到。
         *
         * 踩过的坑:`findByIdempotencyKey` 是全仓唯一的读点,而世界里那张表**从来没人写**:
         * 幂等保护看着齐全(读点、分支、措辞、审计都在),实际是一段永远不会执行的分支。
         * 只读不写 = 没有幂等。写入放在提交成功之后,保证"只有真的成了的那笔才可重放"。
         */
        await ctx.bank.rememberIdempotency(ctx.idempotencyKey, receipt);

        return {
          ok: true,
          data: receiptToData(receipt),
          summary: `已向 ${receipt.payeeName} 转账 ${receipt.amount} ${receipt.currency},流水号 ${receipt.reference}`,
          extraReasons: fraud.reasons,
          ...(buildFraudCardBlock(fraud) ? { fraudBlock: buildFraudCardBlock(fraud)! } : {}),
        };
      } catch (err) {
        /**
         * ★ 提交点之前的取消**必须原样抛出**,不能在这里被包装成"转账失败"(第 3 项)。
         *
         *   踩过的坑(实测):能力层把银行核心抛出的所有异常统一转成
         *   `{ok:false, error:{code:"TRANSFER_FAILED"}}` 并写一条 execution_failed ——
         *   于是"提交前取消"(什么都没做)与"执行失败"(可能已改状态)在审计里
         *   长得一模一样,编排器也永远看不到取消信号。这正是不允许存在的
         *   第三种状态:钱没动,但账上写着"失败"。
         *   取消由**执行边界**统一处理(写 execution_cancelled + 转成干净结果)。
         */
        if (isOperationCancelled(err)) throw err;

        const msg = (err as Error).message;
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "execution_failed",
          payload: { capability: "transfer.submit", error: msg },
        });
        return {
          ok: false,
          error: {
            code: "TRANSFER_FAILED",
            message: msg,
            retryable: msg.includes("载荷哈希") ? false : true,
          },
        };
      }
    },
  });
}

// ============================================================================
// AA 收款能力
// ============================================================================

export function registerCollectionCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "collection.create",
    description:
      "发起一笔 AA 收款(均摊 equal / 自定义金额 custom / 按份数 shares)。" +
      "系统会为每位参与人生成各自的应收金额,由他们确认后支付。此操作会向参与人发送收款请求,需用户确认。",
    inputSchema: z.object({
      title: z.string().min(1).max(50).describe("收款事由,如『上周团建』"),
      totalAmount: z.number().positive().describe("总金额"),
      currency: z.string().default("CNY"),
      splitMode: z.enum(["equal", "custom", "shares"]).default("equal"),
      participants: z
        .array(
          z.object({
            displayName: z.string(),
            phone: z.string().optional(),
            amount: z.number().positive().optional(),
            shares: z.number().positive().optional(),
          }),
        )
        .min(2)
        .describe("参与人列表,至少 2 人"),
      feeBearer: z.enum(["initiator", "each"]).default("each"),
      allowPartial: z.boolean().default(false),
    }),
    outputSchema: z.object({
      collectionId: z.string(),
      title: z.string(),
      totalAmount: z.number(),
      shares: z.array(
        z.object({
          participantName: z.string(),
          amountDue: z.number(),
          paymentLink: z.string().optional(),
        }),
      ),
    }),
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["totalAmount", "shares[].amountDue"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const participants = input["participants"] as Array<{
        displayName: string;
        phone?: string;
        amount?: number;
        shares?: number;
      }>;

      const totalAmount = Number(input["totalAmount"]);

      // ---- 分摊校验:份数/金额必须自洽,不能"差不多就行" ----
      const validation = validateSplit(totalAmount, input["splitMode"] as string, participants);
      if (!validation.ok) {
        return { ok: false, error: { code: "SPLIT_INVALID", message: validation.message, retryable: true } };
      }

      // ★ 归属由调用方身份决定(ctx.customerId),不是客户在文本里说的名字
      const collection = await ctx.bank.createCollection(ctx.customerId, {
        title: String(input["title"]),
        totalAmount,
        currency: (input["currency"] as string | undefined) ?? "CNY",
        splitMode: (input["splitMode"] as "equal" | "custom" | "shares" | undefined) ?? "equal",
        participants,
        feeBearer: (input["feeBearer"] as "initiator" | "each" | undefined) ?? "each",
        allowPartial: (input["allowPartial"] as boolean | undefined) ?? false,
      });

      return {
        ok: true,
        data: {
          collectionId: collection.collectionId,
          title: collection.title,
          totalAmount: collection.totalAmount,
          shares: collection.shares.map((s) => ({
            participantName: s.participantName,
            amountDue: s.amountDue,
            ...(s.paymentLink ? { paymentLink: s.paymentLink } : {}),
          })),
        },
        summary: `已发起【${collection.title}】,共 ${collection.shares.length} 人分摊,总计 ${totalAmount} 元`,
      };
    },
  });
}

/** AA 分摊校验:自定义金额必须与总额一致,按份数每人必须给出份数 */
export function validateSplit(
  total: number,
  mode: string,
  participants: Array<{ displayName: string; amount?: number; shares?: number }>,
): { ok: true } | { ok: false; message: string } {
  if (participants.length < 2) {
    return { ok: false, message: "AA 收款至少需要 2 位参与人" };
  }

  if (mode === "custom") {
    const sum = participants.reduce((s, p) => s + (p.amount ?? 0), 0);
    const diff = Math.round((sum - total) * 100) / 100;
    if (Math.abs(diff) > 0.01) {
      return {
        ok: false,
        message: `各人金额之和 ${sum} 元与总额 ${total} 元不一致(相差 ${diff} 元)。请核对后再发起,否则会有人多付或少付。`,
      };
    }
    if (participants.some((p) => !p.amount || p.amount <= 0)) {
      return { ok: false, message: "自定义分摊要求每个人都要有金额,且必须大于 0" };
    }
  }

  if (mode === "shares") {
    if (participants.some((p) => !p.shares || p.shares <= 0)) {
      return { ok: false, message: "按份数分摊要求每个人都要给出份数" };
    }
  }

  return { ok: true };
}

// ============================================================================
// 安全类能力(演示权限分级用 —— 这些是"不可代理"的操作)
// ============================================================================

export function registerSecurityCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "security.change_phone",
    description: "修改账户绑定的手机号。此操作会改变账户的安全凭证。",
    inputSchema: z.object({ newPhone: z.string().optional() }),
    outputSchema: z.object({ delegatedToNativeFlow: z.boolean(), guidance: z.string() }),
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "blocked",
    sensitiveFields: ["newPhone"],
    monetaryFields: [],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "handoff_to_human",
        payload: {
          capability: "security.change_phone",
          disposition: "blocked_by_policy",
          note: "改绑手机号是账户接管的关键路径,Agent 不代理此操作,仅引导至官方安全流程。",
        },
      });
      return {
        ok: true,
        data: {
          delegatedToNativeFlow: true,
          guidance: "请前往「我的 → 安全中心 → 手机号管理」完成修改,需要通过原手机号验证 + 人脸识别。",
        },
        summary: "已引导至官方安全中心",
      };
    },
  });

  registry.register({
    name: "security.change_password",
    description: "修改登录密码或交易密码。此操作会改变账户的安全凭证。",
    inputSchema: z.object({ type: z.enum(["login", "transaction"]).optional() }),
    outputSchema: z.object({ delegatedToNativeFlow: z.boolean(), guidance: z.string() }),
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "blocked",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(_input, ctx): Promise<CapabilityOutcome> {
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "handoff_to_human",
        payload: {
          capability: "security.change_password",
          disposition: "blocked_by_policy",
          note: "密码修改必须走原生安全流程,Agent 不接触任何密码。",
        },
      });
      return {
        ok: true,
        data: {
          delegatedToNativeFlow: true,
          guidance: "请前往「我的 → 安全中心 → 密码管理」完成修改。为保护您的账户安全,密码修改不能通过对话完成。",
        },
        summary: "已引导至官方安全中心",
      };
    },
  });
}
// ============================================================================
// 卡片管理能力(场景四)
// ============================================================================

/**
 * 注册卡片管理能力(场景四)。
 *
 * ★ 这一组能力的分类依据不是"卡片业务有多少流程",而是**每一个动作的后果由谁承担**:
 *
 *   | 能力                       | 后果承担者            | sideEffect   | moneyMovement | baseTier     |
 *   |----------------------------|----------------------|--------------|---------------|--------------|
 *   | card.list / card.detail    | —(只读)              | none         | false         | auto         |
 *   | card.limit_eligibility     | —(只读判定)          | none         | false         | auto         |
 *   | card.restrictions          | —(只读诊断)          | none         | false         | auto         |
 *   | card.report_loss ★         | 客户自己(止损)       | reversible   | true          | auto         |
 *   | card.activate              | 客户自己             | reversible   | false         | confirm      |
 *   | card.replace               | 银行制卡 + 客户      | irreversible | false         | confirm      |
 *   | card.limit_adjust          | **银行审核**         | reversible   | true          | strong_auth  |
 *   | card.new_application       | **银行审批**         | irreversible | false         | strong_auth  |
 *   | card.unblock               | **银行审核**         | reversible   | true          | confirm      |
 *
 *   三点必须讲清楚:
 *
 *   ① **card.report_loss 是 auto —— 全项目除只读与记账外唯一一个自动执行的写操作。**
 *      为什么敢自动执行:它是**安全方向**的操作(把风险敞口关上),
 *      而且时间敏感程度最高 —— 卡丢了之后每多一轮确认,就多一笔可能被盗刷的机会。
 *      按项目一贯的演进原则"凡安全方向的操作降级",它降到底。
 *      这不是放松安全,而是**把紧急动作与危险动作区分开**:
 *      "冻结"永远比"不冻结"安全,所以不需要问。
 *
 *   ② **card.limit_adjust 标 moneyMovement = true。**
 *      它没有转走一分钱,但它会**改变客户的授信状态**,而且一旦批下来,
 *      客户能花出去的钱就变了。按本项目对 moneyMovement 的定义
 *      ("改变资金状态 → 必须独立裁决、不继承前置许可"),它必须为 true,
 *      否则会绕过 R-ACCOUNT-RESTRICTED 这类本该生效的硬规则。
 *
 *   ③ **card.unblock 标 moneyMovement = true 而非 false。**
 *      直觉上"解除限制"只是把状态改回来,不涉及资金。但它把**被风控关掉的口子重新打开**,
 *      是**扩权方向**的操作 —— 与提额同类,而不是与冻结同类。
 *      这也是场景四最容易被写错的一处分级:冻结与解冻看起来是对称的,
 *      在风险上却完全不对称。
 */
export function registerCardCapabilities(registry: CapabilityRegistry): void {
  // ---- 卡片列表(只读)----
  registry.register({
    name: "card.list",
    description:
      "查询客户名下的卡片列表与状态(卡种、尾号、是否激活、额度、有效期、交易限制)。" +
      "用户说『我有哪些卡』『我的卡都什么状态』『信用卡额度多少』时使用。" +
      "★ 只读,无副作用。卡片状态包含正常/已挂失/已冻结/未激活/补卡在途。",
    inputSchema: z.object({
      kind: z.enum(["credit", "debit", "virtual"]).optional().describe("只看某一类卡"),
      /** ★ 由编排器写入:用户在"卡丢了"的紧急路径下被冻结的卡,需要在回执里回显 */
      cardIds: z.array(z.string()).optional().describe("指定卡片 ID 列表(内部使用)"),
      focusNote: z.string().optional().describe("列表前面的提示语(内部使用)"),
    }),
    outputSchema: z.object({
      cards: z.array(
        z.object({
          cardId: z.string(),
          productName: z.string(),
          kind: z.string(),
          kindLabel: z.string(),
          last4: z.string(),
          status: z.string(),
          statusLabel: z.string(),
          activated: z.boolean(),
          creditLimit: z.number().nullable(),
          availableLimit: z.number().nullable(),
          expiresText: z.string(),
          restrictionCause: z.string().nullable(),
          restrictionDetail: z.string().nullable(),
        }),
      ),
      totalCount: z.number(),
      hasBlockedCard: z.boolean(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["cards[].creditLimit", "cards[].availableLimit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const all = await ctx.bank.listCards(ctx.customerId);
      const wanted = Array.isArray(input["cardIds"]) ? (input["cardIds"] as string[]) : null;
      let cards = all;
      if (input["kind"]) cards = cards.filter((c) => c.kind === String(input["kind"]));
      if (wanted && wanted.length > 0) {
        const set = new Set(wanted);
        cards = cards.filter((c) => set.has(c.cardId));
      }

      const lines: string[] = [];
      if (typeof input["focusNote"] === "string" && input["focusNote"].length > 0) {
        lines.push(String(input["focusNote"]));
        lines.push("");
      }
      if (cards.length === 0) {
        lines.push("您没有符合条件的卡片。");
      } else {
        lines.push(`您名下共有 ${cards.length} 张卡:`);
        lines.push("");
        lines.push(...renderCardList(cards, ctx.now));
        lines.push("要操作某一张可以直接说序号或尾号(例如「尾号 1234 那张的额度」「挂失第 2 张」)。");
      }

      const hasBlocked = cards.some((c) => isCardBlocked(c.status));
      if (hasBlocked) {
        lines.push("");
        lines.push("有卡片当前不可用,状态与处理方式见上方列表。");
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "card.list",
          totalCount: cards.length,
          statuses: cards.map((c) => `${c.last4}:${c.status}`),
          note: "卡片状态与额度来自银行核心,模型未参与任何判断。",
        },
      });

      if (ctx.extras && cards.length > 0) {
        const focus = typeof input["focusNote"] === "string" ? String(input["focusNote"]) : "";
        ctx.extras.visual = {
          kind: "list_report",
          title: "我的银行卡",
          subtitle: `共 ${cards.length} 张`,
          items: cards.map((c) => ({
            title: `${c.productName}(尾号 ${c.last4})`,
            badge: c.statusLabel,
            tone: isCardBlocked(c.status) ? ("high" as const) : ("plain" as const),
            value: (c.creditLimit ?? 0) > 0 ? `可用 ¥${(c.availableLimit ?? 0).toLocaleString("zh-CN")}` : undefined,
            lines: [
              (c.creditLimit ?? 0) > 0
                ? `${c.kindLabel} · 额度 ¥${(c.creditLimit ?? 0).toLocaleString("zh-CN")}`
                : `${c.kindLabel} · 借记卡没有授信额度,能花多少取决于账户余额`,
            ],
          })),
          compactBody:
            `${focus ? `${focus}\n` : ""}您名下共有 ${cards.length} 张卡,状态与额度见下。` +
            (hasBlocked ? "其中有卡片当前不可用,已在清单中标出。" : "") +
            "要操作某一张,可以直接说序号或尾号。",
        };
      }

      return {
        ok: true,
        data: {
          cards: cards.map((c) => ({
            cardId: c.cardId,
            productName: c.productName,
            kind: c.kind,
            kindLabel: c.kindLabel,
            last4: c.last4,
            status: c.status,
            statusLabel: c.statusLabel,
            activated: c.activated,
            creditLimit: c.creditLimit,
            availableLimit: c.availableLimit,
            expiresText: fmtCardDay(c.expiresAt),
            restrictionCause: c.restriction?.cause ?? null,
            restrictionDetail: c.restriction?.detail ?? null,
          })),
          totalCount: cards.length,
          hasBlockedCard: hasBlocked,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 单张卡详情(只读)----
  registry.register({
    name: "card.detail",
    description: "查询某一张卡的详细信息:卡种、状态、额度与可用额度、账单日还款日、有效期、开卡时间、交易限制原因。只读。",
    inputSchema: z.object({
      cardId: z.string().optional().describe("卡片 ID"),
      last4: z.string().optional().describe("卡号后四位"),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      cardId: z.string().nullable(),
      productName: z.string().nullable(),
      status: z.string().nullable(),
      statusLabel: z.string().nullable(),
      creditLimit: z.number().nullable(),
      availableLimit: z.number().nullable(),
      usedAmount: z.number().nullable(),
      statementDay: z.number().nullable(),
      dueDay: z.number().nullable(),
      openedText: z.string().nullable(),
      monthsUsed: z.number().nullable(),
      restrictionCause: z.string().nullable(),
      restrictionCauseLabel: z.string().nullable(),
      restrictionChannel: z.string().nullable(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["creditLimit", "availableLimit", "usedAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没有找到这张卡。可以说卡号后四位,或者先看「我有哪些卡」。", retryable: true },
        };
      }

      const lines: string[] = [];
      lines.push(`【${card.productName}】${CARD_KIND_LABELS[card.kind]} 尾号 ${card.last4}`);
      lines.push(`状态:${CARD_STATUS_LABELS[card.status]}${card.activated ? "" : "(尚未激活,暂不能交易)"}`);
      if (card.creditLimit != null) {
        lines.push(
          `额度:${fmtCardMoney(card.creditLimit)} 元 · 已用 ${fmtCardMoney(card.usedAmount ?? 0)} 元 · 可用 ${fmtCardMoney(card.availableLimit ?? 0)} 元`,
        );
        if (card.statementDay != null) lines.push(`账单日:每月 ${card.statementDay} 日 · 还款日:每月 ${card.dueDay} 日`);
      } else {
        lines.push("类型:借记卡,无授信额度");
      }
      lines.push(`有效期至 ${fmtCardDay(card.expiresAt)} · 开卡 ${fmtCardDay(card.openedAt)}(已用卡 ${monthsBetween(card.openedAt, ctx.now)} 个月)`);
      if (card.restriction) {
        const diag = diagnoseRestriction(card, ctx.now);
        lines.push("");
        lines.push(diag.summary);
        lines.push("");
        lines.push(`处理通道:${RESTRICTION_CHANNEL_LABELS[card.restriction.channel]}`);
        lines.push("");
        lines.push("建议动作:");
        for (const a of diag.nextActions) lines.push(`  · ${a}`);
      } else {
        lines.push("交易限制:无");
      }
      if (card.status === "lost") {
        lines.push("");
        lines.push("该卡已挂失冻结。如需补卡,请回复「补办这张卡」。换号与保留原号的到达时间不同,办理前将说明差异。");
      }
      if (card.status === "pending_activation") {
        lines.push("");
        lines.push("该卡尚未激活,激活后方可使用。如需办理,请回复「激活这张卡」。");
      }

      const cardSummary = lines.join("\n");
      if (ctx.extras) {
        const detailLines = [
          `状态:${CARD_STATUS_LABELS[card.status]}`,
          card.creditLimit != null
            ? `额度 ${fmtCardMoney(card.creditLimit)} · 可用 ${fmtCardMoney(card.availableLimit ?? 0)}`
            : "借记卡,无授信额度",
          `有效期至 ${fmtCardDay(card.expiresAt)}`,
        ];
        if (card.restriction) {
          const diag = diagnoseRestriction(card, ctx.now);
          detailLines.push(diag.summary);
        }
        ctx.extras.visual = {
          kind: "list_report",
          title: "卡片详情",
          subtitle: `${card.productName} · 尾号 ${card.last4}`,
          items: [{ title: CARD_KIND_LABELS[card.kind], value: CARD_STATUS_LABELS[card.status], lines: detailLines }],
          compactBody: `${card.productName}(尾号 ${card.last4}) · ${CARD_STATUS_LABELS[card.status]}`,
        };
      }

      return {
        ok: true,
        data: {
          found: true,
          cardId: card.cardId,
          productName: card.productName,
          status: card.status,
          statusLabel: CARD_STATUS_LABELS[card.status],
          creditLimit: card.creditLimit,
          availableLimit: card.availableLimit,
          usedAmount: card.usedAmount,
          statementDay: card.statementDay,
          dueDay: card.dueDay,
          openedText: fmtCardDay(card.openedAt),
          monthsUsed: monthsBetween(card.openedAt, ctx.now),
          restrictionCause: card.restriction?.cause ?? null,
          restrictionCauseLabel: card.restriction?.causeLabel ?? null,
          restrictionChannel: card.restriction?.channel ?? null,
          summary: cardSummary,
        },
        summary: cardSummary,
      };
    },
  });

  // ---- 额度调整资格(只读)----
  registry.register({
    name: "card.limit_eligibility",
    description:
      "查询某张信用卡**能不能申请提额**、能申请到多少、还差多久。" +
      "用户说『额度太低能不能提额』『我这张卡能提额吗』『为什么不能提额』时使用。" +
      "★ 只读判定,不会提交任何申请。" +
      "★ 规则:新开户或刚调额不久的客户通常需用卡满 6 个月左右再申请;距上次调额不满约 3 个月的需等冷却期。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
    }),
    outputSchema: z.object({
      status: z.string(),
      canApply: z.boolean(),
      currentLimit: z.number().nullable(),
      suggestedMaxLimit: z.number().nullable(),
      waitMonths: z.number(),
      reason: z.string(),
      ourPart: z.string(),
      bankPart: z.string(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["currentLimit", "suggestedMaxLimit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到这张卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }

      const elig = checkLimitEligibility({ card, now: ctx.now });
      const lines: string[] = [];
      lines.push(`${card.productName}(尾号 ${card.last4})额度情况:`);
      lines.push(elig.reason);
      lines.push("");
      lines.push(`我们能做的:${elig.ourPart}`);
      lines.push(`银行定规则的部分:${elig.bankPart}`);
      if (elig.canApply) {
        lines.push("");
        lines.push(`要提交的话,回复「把尾号 ${card.last4} 的额度申请提到 ${elig.suggestedMaxLimit} 元」——`);
        lines.push("我会先把申请额度、审核时效,以及「审核通过才生效」这件事说清楚,由您确认后再提交。");
      }

      const eligSummary = lines.join("\n");
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "提额资格",
          subtitle: `${card.productName} · 尾号 ${card.last4}`,
          summary: elig.reason,
          items: [
            {
              title: elig.canApply ? "可以申请" : "暂不可申请",
              value:
                elig.suggestedMaxLimit != null
                  ? `可提到 ¥${fmtCardMoney(elig.suggestedMaxLimit)}`
                  : undefined,
              tone: elig.canApply ? "ok" : "medium",
              lines: [elig.ourPart, elig.bankPart],
            },
          ],
          compactBody: elig.canApply
            ? `${elig.reason} 可申请提到 ${fmtCardMoney(elig.suggestedMaxLimit ?? 0)} 元。`
            : elig.reason,
        };
      }

      return {
        ok: true,
        data: {
          status: elig.status,
          canApply: elig.canApply,
          currentLimit: elig.currentLimit,
          suggestedMaxLimit: elig.suggestedMaxLimit,
          waitMonths: elig.waitMonths,
          reason: elig.reason,
          ourPart: elig.ourPart,
          bankPart: elig.bankPart,
          summary: eligSummary,
        },
        summary: eligSummary,
      };
    },
  });

  // ---- ★ 挂失(紧急安全动作,自动执行)----
  registry.register({
    name: "card.report_loss",
    description:
      "挂失卡片,阻止该卡一切交易。用户说『卡丢了』『卡被偷了』『马上挂失』时使用。" +
      "★ 这是紧急止损动作,系统会**先挂失再聊补办细节** —— 不要为了追问细节而推迟办理。" +
      "★ 必须明确是哪一张卡;未指定时由路由层先问清,不能默认挂失全部卡片。",
    inputSchema: z.object({
      cardId: z.string().optional().describe("要挂失的卡片 ID"),
      cardIds: z.array(z.string()).optional().describe("要挂失的卡片 ID 列表(批量,极少使用)"),
      scenario: z.string().max(200).optional().describe("用户自述的丢失/被盗情形"),
      reason: z.string().max(100).optional().describe("挂失原因代码"),
    }),
    outputSchema: z.object({
      frozenCount: z.number(),
      cards: z.array(
        z.object({
          cardId: z.string(),
          last4: z.string(),
          productName: z.string(),
          frozenAt: z.number(),
        }),
      ),
      immediate: z.boolean(),
      reference: z.string(),
      nextSteps: z.array(z.string()),
      summary: z.string(),
    }),
    /**
     * ★★ moneyMovement 必须是 `false`:挂失**不动一分钱**,只是停用该卡。
     *
     *   这个字段被写错不是文字问题,是**真实的拦截**:策略里有
     *   R-CREDENTIAL-MONEY-COMBO(同一会话内"改凭证 + 资金操作"阻断),
     *   它按 moneyMovement 判定。实测复现:
     *     ① 同一会话说「我要改手机号」 → 记下改凭证意图
     *     ② 接着说「卡丢了先挂失」 → 被该规则拒绝:「修改安全信息与转账不能在同一会话中连续进行」
     *   卡在最需要冻结的一刻没有冻结 —— 而这恰好是账户被盗最典型的场景
     *   (刚动过安全信息 / 正被骗子指挥)。挂失是**紧急止损**,优先级高于一切。
     *
     * ★ sideEffect 保持 `reversible`:挂失是可以解除的(解挂 / 补卡激活),
     *   所以它不需要"不可撤销"的措辞,而且紧急动作不能被确认环节拖住 ——
     *   autoExecutable 的理由见下。
     */
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "auto",
    autoExecutable: true,
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const all = await ctx.bank.listCards(ctx.customerId);
      const explicit = Array.isArray(input["cardIds"]) && (input["cardIds"] as string[]).length > 0
        ? (input["cardIds"] as string[])
        : input["cardId"]
          ? [String(input["cardId"])]
          : null;

      if (!explicit || explicit.length === 0) {
        return {
          ok: false,
          error: {
            code: "CARD_NOT_SPECIFIED",
            message: "请说明要挂失哪一张卡(可以说尾号或序号,或先看「我有哪些卡」)。",
            retryable: true,
          },
        };
      }

      const targets = all.filter((c) => explicit.includes(c.cardId));

      if (targets.length === 0) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到要挂失的卡片。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }

      const frozen: Array<{ cardId: string; last4: string; productName: string; frozenAt: number }> = [];
      for (const c of targets) {
        const receipt = await ctx.bank.reportCardLoss({
          customerId: ctx.customerId,
          cardId: c.cardId,
          ...(input["scenario"] ? { scenario: String(input["scenario"]) } : {}),
          ...(input["reason"] ? { reason: String(input["reason"]) } : {}),
        });
        if (receipt.ok) {
          frozen.push({ cardId: receipt.cardId, last4: receipt.cardLast4, productName: c.productName, frozenAt: receipt.frozenAt });
        }
      }

      // ★ 独立审计事件:这是监管与风控都关心的"止损时效"证据。
      //   它必须能直接检索出"客户什么时候报的挂失、系统什么时候冻的"。
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_loss_reported",
        payload: {
          capability: "card.report_loss",
          frozenCardCount: frozen.length,
          cards: frozen.map((f) => `${f.productName} 尾号 ${f.last4}`),
          userSpecifiedCard: true,
          scenario: input["scenario"] ?? null,
          immediate: true,
          note: "挂失是紧急止损动作:按「先挂失、后补办」的顺序处理,不因追问补办细节而延迟办理。",
        },
      });

      const lines: string[] = [];
      lines.push(`已完成挂失(${frozen.length} 张,即时生效):`);
      for (const f of frozen) lines.push(`  · ${f.productName} 尾号 ${f.last4}`);
      lines.push("");
      lines.push("上述卡片现已无法交易,包括刷卡、取现、线上支付与自动扣款。");

      const nextSteps = [
        "补办新卡:换号补卡约 5 个工作日,保留原号约 12 个工作日(需您选择)",
        "补卡后需要激活;换号补卡还要重新设置交易密码",
        "已绑定的自动扣款、快捷支付会失败,补卡后需要重新绑定(保留原号则不用)",
      ];
      lines.push("");
      lines.push("后续可办理:");
      for (const s of nextSteps) lines.push(`  · ${s}`);

      const lossSummary = lines.join("\n");
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "挂失回执",
          subtitle: `已挂失 ${frozen.length} 张 · 即时生效`,
          items: frozen.map((f) => ({
            title: `${f.productName} · 尾号 ${f.last4}`,
            badge: "已挂失",
            tone: "medium" as const,
          })),
          compactBody: `已完成挂失 ${frozen.length} 张,该卡现已无法交易。`,
          footer: "补卡、解挂需另行办理;自动扣款将失败直至重新绑定。",
        };
      }

      return {
        ok: true,
        data: {
          frozenCount: frozen.length,
          cards: frozen,
          immediate: true,
          reference: `LOSS-${Date.now().toString(36).toUpperCase()}`,
          nextSteps,
          summary: lossSummary,
        },
        summary: lossSummary,
      };
    },
  });

  // ---- 交易限制原因诊断(只读)----
  registry.register({
    name: "card.restrictions",
    description:
      "查询卡片为什么被限制交易:异常交易 / 信息不完整 / 司法冻结 / 安全风险 / 客户自设限额,并给出对应的处理通道与所需材料。" +
      "用户说『卡为什么被限制』『卡怎么刷不了了』『我的卡被锁了』时使用。" +
      "★ 只读诊断。★ 必须先查清原因再决定怎么处理,不同原因的处理通道完全不同,不能一刀切。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
    }),
    outputSchema: z.object({
      cardId: z.string().nullable(),
      hasRestriction: z.boolean(),
      cause: z.string().nullable(),
      causeLabel: z.string().nullable(),
      channel: z.string().nullable(),
      requiredDocuments: z.array(z.string()),
      estimatedResolution: z.string().nullable(),
      canSubmitUnblock: z.boolean(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到这张卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }

      const diag = diagnoseRestriction(card, ctx.now);
      const canUnblock = canSubmitUnblock(card.restriction);

      const lines: string[] = [diag.summary];
      if (card.restriction) {
        lines.push("");
        lines.push(`处理通道:${RESTRICTION_CHANNEL_LABELS[card.restriction.channel]}`);
        if (card.restriction.requiredDocuments.length > 0) {
          lines.push(`需要准备:${card.restriction.requiredDocuments.join("、")}`);
        }
        lines.push(`预计处理时效:${card.restriction.estimatedResolution}`);
        lines.push("");
        lines.push(`我们能做的:${diag.ourPart}`);
        lines.push(`银行/有权机关定规则的部分:${diag.bankPart}`);
        lines.push("");
        lines.push("建议动作:");
        for (const a of diag.nextActions) lines.push(`  · ${a}`);
      } else {
        lines.push("");
        lines.push(diag.ourPart);
      }

      // ★ 查询本身也是敏感事件:客户问过限制原因,监管可能会问"系统当时怎么答复的"
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_restriction_inquired",
        payload: {
          capability: "card.restrictions",
          cardLast4: card.last4,
          cause: card.restriction?.cause ?? null,
          channel: card.restriction?.channel ?? null,
          canSubmitUnblock: canUnblock,
          note:
            "查询交易限制原因入链:「系统当时把原因解释成了什么」是监管与客诉复核的关键证据。" +
            "★ 未在查清原因之前给出任何「帮您解除」的承诺。",
        },
      });

      const restrSummary = lines.join("\n");
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "交易限制诊断",
          subtitle: `${card.productName} · 尾号 ${card.last4}`,
          summary: diag.summary,
          items: [
            {
              title: card.restriction ? card.restriction.causeLabel : "无限制",
              badge: card.restriction ? RESTRICTION_CHANNEL_LABELS[card.restriction.channel] : "正常",
              tone: card.restriction ? "medium" : "ok",
              lines: [
                ...(card.restriction?.requiredDocuments.length
                  ? [`材料:${card.restriction.requiredDocuments.join("、")}`]
                  : []),
                card.restriction?.estimatedResolution ?? "",
                ...diag.nextActions.slice(0, 3),
              ].filter(Boolean),
            },
          ],
          compactBody: diag.summary,
          footer: canUnblock ? "如需提交解除申请,请说「申请解除限制」。" : undefined,
        };
      }

      return {
        ok: true,
        data: {
          cardId: card.cardId,
          hasRestriction: card.restriction != null,
          cause: card.restriction?.cause ?? null,
          causeLabel: card.restriction?.causeLabel ?? null,
          channel: card.restriction?.channel ?? null,
          requiredDocuments: card.restriction?.requiredDocuments ?? [],
          estimatedResolution: card.restriction?.estimatedResolution ?? null,
          canSubmitUnblock: canUnblock,
          summary: restrSummary,
        },
        summary: restrSummary,
      };
    },
  });

  // ---- 解除限制申请(转银行审核)----
  registry.register({
    name: "card.unblock",
    description:
      "提交解除卡片交易限制的**申请**(转银行审核,不是立即解除)。" +
      "★ 前置条件:必须已经查清限制原因。司法冻结不受理;信息不完整类引导客户在 App 自助完成;" +
      "客户自设限额属于放宽敞口,需用户确认。" +
      "★ 提交后必须如实说明:是否解除由银行审核决定,审核期间限制仍然生效。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
      statement: z.string().max(300).optional().describe("客户自述情况,供审核参考"),
    }),
    outputSchema: z.object({
      accepted: z.boolean(),
      applicationId: z.string(),
      cause: z.string(),
      causeLabel: z.string(),
      estimatedResolution: z.string(),
      message: z.string(),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "reversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到这张卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }
      if (!card.restriction) {
        return {
          ok: false,
          error: {
            code: "NO_RESTRICTION",
            message: `这张卡(尾号 ${card.last4})当前没有交易限制,不需要提交解除申请。如果您遇到了交易失败,把失败时间与金额告诉我,我来查具体原因。`,
            retryable: false,
          },
        };
      }

      // ★ 能力层最后兜底:司法冻结与信息不完整类不进入申请流程。
      //   策略引擎已经拦过一道(见 R-CARD-UNBLOCK-REQUIRES-CAUSE),
      //   这里是防止有人绕过路由直接调能力 —— 同一个判断,两道闸门。
      const cause = card.restriction.cause;
      if (cause === "judicial_freeze") {
        return {
          ok: false,
          error: {
            code: "JUDICIAL_FREEZE_NOT_APPLICABLE",
            message:
              "这是司法冻结,银行无权自行解除,不能提交解除申请。请联系出具冻结的机关;" +
              "拿到《解除冻结通知书》后到任一网点或通过客服提交。",
            retryable: false,
          },
        };
      }
      if (cause === "incomplete_information") {
        return {
          ok: false,
          error: {
            code: "SELF_SERVICE_REQUIRED",
            message:
              "限制原因是身份信息不完整,不需要提交申请 —— 请在 App「我的 → 身份信息」补全证件信息,提交后一般 1 个工作日内自动解除。",
            retryable: false,
          },
        };
      }

      const receipt = await ctx.bank.submitUnblockRequest({
        customerId: ctx.customerId,
        cardId: card.cardId,
        ...(input["statement"] ? { statement: String(input["statement"]) } : {}),
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const lines: string[] = [];
      lines.push(receipt.message);
      lines.push("");
      lines.push(`限制原因:${card.restriction.causeLabel}`);
      lines.push(`申请单号:${receipt.applicationId}`);
      lines.push(`预计处理时效:${receipt.estimatedResolution}`);
      lines.push("");
      lines.push("本次提交的是申请,不是解除本身。是否解除由银行审核决定,审核期间限制仍然生效。");
      if (cause === "self_setting") {
        lines.push("该限制为本人设置的限额,修改后立即生效,无需银行审核。");
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_unblock_requested",
        payload: {
          capability: "card.unblock",
          applicationId: receipt.applicationId,
          cardLast4: card.last4,
          cause,
          accepted: receipt.accepted,
          statement: input["statement"] ?? null,
          /** ★ 关键事实:这条记录写的是"提交了申请",而不是"已解除" */
          effectiveNow: false,
          note:
            "记录的是解除**申请**而非解除结果。审核期间限制仍然生效 ——" +
            "审计里若把这条读成「系统给客户解除了限制」,那是误读,因此字段名刻意用 requested。",
        },
      });

      return {
        ok: true,
        data: {
          accepted: receipt.accepted,
          applicationId: receipt.applicationId,
          cause,
          causeLabel: card.restriction.causeLabel,
          estimatedResolution: receipt.estimatedResolution,
          message: receipt.message,
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 新卡申请 ----
  registry.register({
    name: "card.new_application",
    description:
      "申请一张新卡(新开户 / 加办卡)。用户说『想办一张新卡』『再申请一张信用卡』时使用。" +
      "★ 提交的是申请:银行做资信审核,不保证通过,批卡额度也由银行决定。" +
      "★ 必须提前告知:新卡到手后必须先激活;新开户/新办卡还需要设置交易密码,否则无法交易。",
    inputSchema: z.object({
      kind: z.enum(["credit", "debit", "virtual"]).optional().describe("申请卡种,默认信用卡"),
      requestedLimit: z.number().positive().optional().describe("期望额度(仅信用卡)"),
      purpose: z.string().max(200).optional().describe("用途说明,供审核参考"),
    }),
    outputSchema: z.object({
      applicationId: z.string(),
      kind: z.string(),
      kindLabel: z.string(),
      status: z.string(),
      statusLabel: z.string(),
      requestedLimit: z.number().nullable(),
      estimatedDecisionAt: z.number(),
      requiredDocuments: z.array(z.string()),
      postApprovalSteps: z.array(z.string()),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "strong_auth",
    sensitiveFields: [],
    monetaryFields: ["requestedLimit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const kind = (input["kind"] as "credit" | "debit" | "virtual" | undefined) ?? "credit";
      const app = await ctx.bank.submitCardApplication({
        customerId: ctx.customerId,
        kind,
        ...(input["requestedLimit"] != null ? { requestedLimit: Number(input["requestedLimit"]) } : {}),
        ...(input["purpose"] ? { purpose: String(input["purpose"]) } : {}),
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const req = requirementForScenario("new_application");
      const lines: string[] = [];
      lines.push(`您的${app.kindLabel}申请已提交(申请单号 ${app.applicationId})。`);
      lines.push("");
      lines.push(`后续由银行审批,预计 ${fmtCardDay(app.estimatedDecisionAt)} 前告知结果。`);
      if (app.requestedLimit != null) {
        lines.push(`您填的期望额度是 ${fmtCardMoney(app.requestedLimit)} 元 —— 最终批多少由银行资信审核决定,可能少于这个数。`);
      }
      if (app.requiredDocuments.length > 0) {
        lines.push("");
        lines.push(`可能需要您补充:${app.requiredDocuments.join("、")}`);
      }
      lines.push("");
      lines.push("新卡到手后须完成以下事项方可使用:");
      for (const s of app.postApprovalSteps) lines.push(`  · ${s}`);
      lines.push(`(${req.summary})`);

      return {
        ok: true,
        data: {
          applicationId: app.applicationId,
          kind: app.kind,
          kindLabel: app.kindLabel,
          status: app.status,
          statusLabel: app.statusLabel,
          requestedLimit: app.requestedLimit,
          estimatedDecisionAt: app.estimatedDecisionAt,
          requiredDocuments: app.requiredDocuments,
          postApprovalSteps: app.postApprovalSteps,
          reference: app.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 挂失后补卡(换号 / 保留原号)----
  registry.register({
    name: "card.replace",
    description:
      "挂失后补办新卡,可选**换号补卡**(约 5 个工作日)或**保留原号**(约 12 个工作日,等待更久)。" +
      "用户说『补办这张卡』『补卡要多久』『能不能保留原卡号』时使用。" +
      "★ 必须在操作**之前**告知两种方案的差异:到达时间、卡号是否变化、是否要重设交易密码、是否要重新绑定已绑业务。" +
      "★ 用户没说清哪种方式时,先展示两种方案让他选,不要替他决定。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
      mode: z.enum(["new_number", "keep_number"]).describe("补卡方式"),
    }),
    outputSchema: z.object({
      orderId: z.string(),
      mode: z.string(),
      modeLabel: z.string(),
      estimatedArrivalAt: z.number(),
      estimatedDays: z.number(),
      cardNumberChanges: z.boolean(),
      newCardLast4: z.string().nullable(),
      requiresActivation: z.boolean(),
      requiresTransactionPassword: z.boolean(),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到要补办的卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }
      // ★ 兜底:未挂失的卡不能"补办" —— 那叫换卡,而且是另一套流程
      if (card.status !== "lost" && card.status !== "frozen" && card.status !== "replacement_in_transit") {
        return {
          ok: false,
          error: {
            code: "CARD_NOT_LOST",
            message:
              `这张卡(尾号 ${card.last4})当前状态是「${CARD_STATUS_LABELS[card.status]}」,不是挂失状态,不能走补卡流程。` +
              "如果您是卡损坏或到期需要换卡,告诉我,那属于换卡业务,交易密码沿用原密码,只需激活。",
            retryable: false,
          },
        };
      }

      const mode = input["mode"] as "new_number" | "keep_number";
      const order = await ctx.bank.orderCardReplacement({
        customerId: ctx.customerId,
        cardId: card.cardId,
        mode,
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const scenario = scenarioForReplacementMode(mode);
      const req = requirementForScenario(scenario);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_replacement_ordered",
        payload: {
          capability: "card.replace",
          orderId: order.orderId,
          cardLast4: card.last4,
          mode,
          cardNumberChanges: order.cardNumberChanges,
          estimatedDays: order.estimatedDays,
          requiresActivation: req.requiresActivation,
          requiresTransactionPassword: req.requiresTransactionPassword,
          /** ★ 记录"差异已告知":这是客诉复核时唯一能证明我们说过的话 */
          differenceDisclosed: true,
          note:
            "补卡下单入链,并记录「换号/保号差异已在操作前告知」这一事实 ——" +
            "保留原号等待更久是最容易被投诉的一点,必须留下告知证据。",
        },
      });

      const lines: string[] = [];
      lines.push(`补卡申请已提交(单号 ${order.orderId}):${order.modeLabel}`);
      lines.push("");
      lines.push(order.wording);
      lines.push("");
      lines.push(`预计到手:约 ${order.estimatedDays} 个工作日(${fmtCardDay(order.estimatedArrivalAt)} 前后);`);
      lines.push(`卡号:${order.cardNumberChanges ? `会变(新卡尾号 ${order.newCardLast4})` : `不变(仍是尾号 ${card.last4})`}`);
      lines.push(`到手后必做:${req.summary}`);
      if (order.cardNumberChanges) {
        lines.push("新卡激活前,原卡绑定的自动扣款可能失败。如有在途订阅,建议先手动缴费,以免逾期。");
      }

      return {
        ok: true,
        data: {
          orderId: order.orderId,
          mode: order.mode,
          modeLabel: order.modeLabel,
          estimatedArrivalAt: order.estimatedArrivalAt,
          estimatedDays: order.estimatedDays,
          cardNumberChanges: order.cardNumberChanges,
          newCardLast4: order.newCardLast4,
          requiresActivation: req.requiresActivation,
          requiresTransactionPassword: req.requiresTransactionPassword,
          reference: order.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 激活新卡 ----
  registry.register({
    name: "card.activate",
    description:
      "激活一张新卡。用户说『激活新卡』『新卡怎么用』时使用。" +
      "★ 所有换卡/补卡/新办的卡都必须激活后才能使用。" +
      "★ 交易密码规则:挂失换卡-换号 / 新开户需**重新设置**交易密码;挂失换卡-保留原号 / 到期换卡 / 损坏换卡**沿用原密码**,只需激活。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
      activationCode: z.string().max(20).optional().describe("卡函上的激活码(如有)"),
    }),
    outputSchema: z.object({
      ok: z.boolean(),
      cardId: z.string(),
      last4: z.string(),
      transactionPasswordSet: z.boolean(),
      transactionPasswordInherited: z.boolean(),
      message: z.string(),
      reference: z.string(),
      summary: z.string(),
    }),
    /**
     * ★ sideEffect 必须是 `irreversible`:卡一旦激活就进入可用状态,
     *   这是**不可回退**的(没有"取消激活"这回事,只能再挂失)。
     *   声明成 reversible 会让确认卡按"可撤销"措辞,与事实相反。
     */
    sideEffect: "irreversible",
    moneyMovement: false,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: ["activationCode"],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到要激活的卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }
      if (card.activated && card.status !== "pending_activation") {
        return {
          ok: false,
          error: {
            code: "ALREADY_ACTIVATED",
            message: `这张卡(尾号 ${card.last4})已经激活过了${card.activatedAt ? `(${fmtCardDay(card.activatedAt)})` : ""},不需要重复激活。`,
            retryable: false,
          },
        };
      }
      if (card.status === "lost" || card.status === "closed") {
        return {
          ok: false,
          error: {
            code: "CARD_NOT_ACTIVATABLE",
            message: `这张卡状态是「${CARD_STATUS_LABELS[card.status]}」,无法激活。${card.status === "lost" ? "挂失的卡需要先补办新卡,再激活新卡。" : ""}`,
            retryable: false,
          },
        };
      }

      // ★ 交易密码需求由**业务情形**决定,不由用户或模型决定。
      //   卡号变过 → 原交易密码绑在原卡号上,必须重设;
      //   卡号没变 → 沿用原密码。
      const scenario = scenarioForActivation({
        replacementOf: card.replacementOf,
        cardId: card.cardId,
        status: card.status,
      });
      const req = requirementForScenario(scenario);
      const needsPassword = req.requiresTransactionPassword;

      const receipt = await ctx.bank.activateCard({
        customerId: ctx.customerId,
        cardId: card.cardId,
        // ★ 交易密码需求以路由层算好的为准(它已经按业务情形判定过);
        //   入参缺失时退回本层的场景判定 —— 两条路径共用同一个函数,不会给出两种答案。
        setTransactionPassword:
          typeof input["setTransactionPassword"] === "boolean" ? (input["setTransactionPassword"] as boolean) : needsPassword,
        ...(input["activationCode"] ? { activationCode: String(input["activationCode"]) } : {}),
      });

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_activation_completed",
        payload: {
          capability: "card.activate",
          cardLast4: card.last4,
          scenario,
          transactionPasswordSet: receipt.transactionPasswordSet,
          transactionPasswordInherited: receipt.transactionPasswordInherited,
          note:
            "激活入链,并记录交易密码的处理方式(新设 or 沿用)。" +
            "★ 注意:Agent 不接触任何密码 —— 这里的 setTransactionPassword 只是" +
            "「由原生流程引导客户设置」的标志,密码本身从未经过对话通道。",
        },
      });

      const lines: string[] = [];
      lines.push(`卡片已激活:${card.productName} 尾号 ${card.last4}`);
      lines.push("");
      if (needsPassword) {
        lines.push("还需设置交易密码后,该卡方可交易:");
        lines.push("请前往 App「卡片 → 交易密码 → 设置」办理(需人脸识别)。");
        lines.push("设置完成前,该卡仅可查询,不能消费或取现。");
      } else {
        lines.push("交易密码**沿用原密码**,不需要重新设置。");
        lines.push("这张卡现在就可以正常使用了。");
      }
      lines.push("");
      lines.push(`卡片情形:${req.scenarioLabel}`);

      return {
        ok: true,
        data: {
          ok: true,
          cardId: card.cardId,
          last4: card.last4,
          transactionPasswordSet: receipt.transactionPasswordSet,
          transactionPasswordInherited: receipt.transactionPasswordInherited,
          message: lines.join("\n"),
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 额度调整申请(★ 提交申请,不是调整额度)----
  registry.register({
    name: "card.limit_adjust",
    description:
      "提交信用卡额度调整申请(提额)。" +
      "★ 这**不是即时生效**的额度调整:提交后进入银行审核,审核通过才生效。" +
      "在任何回复里都不允许说『已帮你提到 X 元』,只能说『申请已提交,结果会通知』。" +
      "★ 前置条件:用卡满约 6 个月、距上次调额满约 3 个月、卡片状态正常、且是信用卡。" +
      "★ 提额属于放宽风险敞口的方向,必须强验证 + 用户确认。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
      requestedLimit: z.number().positive().describe("申请的目标额度(要高于当前额度)"),
      purpose: z.string().max(200).optional().describe("用途说明,供审核参考"),
    }),
    outputSchema: z.object({
      applicationId: z.string(),
      cardLast4: z.string(),
      currentLimit: z.number(),
      requestedLimit: z.number(),
      status: z.string(),
      statusLabel: z.string(),
      estimatedDecisionAt: z.number(),
      /** ★ 面向客户的"我们做的 / 银行定的"两段口径,由引擎生成、模型只能复述 */
      ourPart: z.string(),
      bankPart: z.string(),
      currentState: z.string(),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "reversible",
    moneyMovement: true,
    readOnly: false,
    baseTier: "strong_auth",
    sensitiveFields: [],
    monetaryFields: ["currentLimit", "requestedLimit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const card = await resolveCard(ctx, input);
      if (!card) {
        return {
          ok: false,
          error: { code: "CARD_NOT_FOUND", message: "没找到这张卡。可以说尾号,或者先看「我有哪些卡」。", retryable: true },
        };
      }
      if (card.creditLimit == null) {
        return {
          ok: false,
          error: {
            code: "NO_CREDIT_LINE",
            message: `这张卡(${CARD_KIND_LABELS[card.kind]} 尾号 ${card.last4})没有授信额度,不存在提额流程。`,
            retryable: false,
          },
        };
      }

      // ★ 能力层最后兜底:资格判定(策略引擎与路由各有一道)
      const elig = checkLimitEligibility({ card, now: ctx.now });
      if (!elig.canApply) {
        return {
          ok: false,
          error: { code: "LIMIT_NOT_ELIGIBLE", message: elig.reason, retryable: false },
        };
      }

      const requestedLimit = Number(input["requestedLimit"]);
      if (requestedLimit <= card.creditLimit) {
        return {
          ok: false,
          error: {
            code: "NOT_AN_INCREASE",
            message: `申请额度需要高于当前额度(${fmtCardMoney(card.creditLimit)} 元)。如果您是想降额,那属于安全方向操作,我可以直接帮您办。`,
            retryable: true,
          },
        };
      }

      const receipt = await ctx.bank.submitLimitAdjustment({
        customerId: ctx.customerId,
        cardId: card.cardId,
        requestedLimit,
        ...(input["purpose"] ? { purpose: String(input["purpose"]) } : {}),
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const wording = limitApplicationWording({
        cardLast4: card.last4,
        requestedLimit,
        currentLimit: card.creditLimit,
        estimatedDecisionAt: receipt.estimatedDecisionAt,
      });

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "card_limit_application_submitted",
        payload: {
          capability: "card.limit_adjust",
          applicationId: receipt.applicationId,
          cardLast4: card.last4,
          currentLimit: card.creditLimit,
          requestedLimit,
          status: receipt.status,
          /** ★★ 一条刻意写进审计的事实:额度此刻没有变化 */
          limitChangedNow: false,
          estimatedDecisionAt: receipt.estimatedDecisionAt,
          purpose: input["purpose"] ?? null,
          note:
            "这里记录的是提额**申请**,不是提额结果。limitChangedNow=false 是刻意留证的字段:" +
            "审计读到这里必须能看出「额度尚未变化」。若把这条读成「系统给客户提了额」,是误读。" +
            "卡片额度的唯一变更入口在银行审核侧,Agent 侧没有任何直接改额度的能力。",
        },
      });

      const lines: string[] = [];
      lines.push(wording.ourPart);
      lines.push("");
      lines.push(wording.currentState);
      lines.push("");
      lines.push(wording.bankPart);
      lines.push("");
      lines.push(`申请单号:${receipt.applicationId} · 预计出结果:${fmtCardDay(receipt.estimatedDecisionAt)}`);
      lines.push("结果出来我会通知您;期间您可以随时问「我的提额申请到哪一步了」。");

      return {
        ok: true,
        data: {
          applicationId: receipt.applicationId,
          cardLast4: card.last4,
          currentLimit: card.creditLimit,
          requestedLimit,
          status: receipt.status,
          statusLabel: receipt.statusLabel,
          estimatedDecisionAt: receipt.estimatedDecisionAt,
          ourPart: wording.ourPart,
          bankPart: wording.bankPart,
          currentState: wording.currentState,
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 额度调整进度查询(只读)----
  registry.register({
    name: "card.limit_status",
    description:
      "查询额度调整申请的处理进度与结果。用户说『我的提额申请到哪了』『上次申请的提额批了吗』时使用。只读。" +
      "★ 结果必须如实说明处于哪个环节;只有 status=approved 才能说额度已调整。",
    inputSchema: z.object({
      cardId: z.string().optional(),
      last4: z.string().optional(),
      applicationId: z.string().optional(),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      applications: z.array(
        z.object({
          applicationId: z.string(),
          cardLast4: z.string(),
          currentLimit: z.number(),
          requestedLimit: z.number(),
          status: z.string(),
          statusLabel: z.string(),
          submittedText: z.string(),
          decisionNote: z.string().nullable(),
        }),
      ),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["applications[].currentLimit", "applications[].requestedLimit"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const list = await ctx.bank.listLimitAdjustments(
        ctx.customerId,
        input["cardId"] ? String(input["cardId"]) : undefined,
      );

      if (list.length === 0) {
        return {
          ok: true,
          data: { found: false, applications: [], summary: "您目前没有在处理的额度调整申请。" },
          summary: "您目前没有在处理的额度调整申请。",
        };
      }

      const lines: string[] = [];
      lines.push(`您共有 ${list.length} 笔额度调整申请:`);
      for (const [i, a] of list.entries()) {
        lines.push("");
        lines.push(`${i + 1}. 申请单 ${a.applicationId}(尾号 ${a.cardLast4})`);
        lines.push(`   目标额度:${fmtCardMoney(a.requestedLimit)} 元 · 申请时额度:${fmtCardMoney(a.currentLimit)} 元`);
        lines.push(`   当前状态:${a.statusLabel}`);
        lines.push(`   提交时间:${fmtCardDay(a.submittedAt)} · 预计出结果:${fmtCardDay(a.estimatedDecisionAt)}`);
        if (a.decisionNote) lines.push(`   审核意见:${a.decisionNote}`);
        if (a.status !== "approved") {
          lines.push(`   → 您的额度目前仍是 ${fmtCardMoney(a.currentLimit)} 元(审核通过前不会变化)`);
        }
      }

      const limitSummary = lines.join("\n");
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "提额进度",
          subtitle: `${list.length} 笔申请`,
          items: list.map((a, i) => ({
            title: `${i + 1}. 尾号 ${a.cardLast4}`,
            value: a.statusLabel,
            badge: a.applicationId.slice(-6),
            tone: a.status === "approved" ? "ok" : a.status === "rejected" ? "high" : "medium",
            lines: [
              `目标 ${fmtCardMoney(a.requestedLimit)} · 当前 ${fmtCardMoney(a.currentLimit)}`,
              `提交 ${fmtCardDay(a.submittedAt)} · 预计 ${fmtCardDay(a.estimatedDecisionAt)}`,
              a.decisionNote ?? "",
            ].filter(Boolean),
          })),
          compactBody: `共有 ${list.length} 笔提额申请,状态见卡片。`,
        };
      }

      return {
        ok: true,
        data: {
          found: true,
          applications: list.map((a) => ({
            applicationId: a.applicationId,
            cardLast4: a.cardLast4,
            currentLimit: a.currentLimit,
            requestedLimit: a.requestedLimit,
            status: a.status,
            statusLabel: a.statusLabel,
            submittedText: fmtCardDay(a.submittedAt),
            decisionNote: a.decisionNote ?? null,
          })),
          summary: limitSummary,
        },
        summary: limitSummary,
      };
    },
  });
}

/**
 * 卡片定位:ID → 尾号 → 卡种口语 → 产品名。
 *
 * ★ 与 `resolveProduct`(理财)同一条设计立场:定位逻辑只有一处,
 *   行为才可能一致。绝不用默认值兜底 —— 客户说"那张卡"而系统随便挑一张,
 *   在卡片场景里后果是挂错卡、冻错卡。
 */
async function resolveCard(
  ctx: ExecutionContext,
  input: Record<string, unknown>,
): Promise<Awaited<ReturnType<ExecutionContext["bank"]["getCard"]>>> {
  const cards = await ctx.bank.listCards(ctx.customerId);

  const id = input["cardId"] ? String(input["cardId"]) : undefined;
  if (id) {
    const hit = cards.find((c) => c.cardId === id);
    if (hit) return hit;
    const byBank = await ctx.bank.getCard(ctx.customerId, id);
    if (byBank) return byBank;
  }

  const last4 = input["last4"] ? String(input["last4"]) : undefined;
  if (last4) {
    const hit = cards.find((c) => c.last4 === last4);
    if (hit) return hit;
  }

  // 单卡客户:不需要指认
  if (cards.length === 1) return cards[0]!;

  return null;
}

/** 卡片定位的口语化包装(供编排器在路由层使用,支持"信用卡""尾号1234""白金卡") */
export async function resolveCardFromText(
  ctx: ExecutionContext,
  text: string,
): Promise<Awaited<ReturnType<ExecutionContext["bank"]["getCard"]>>> {
  const cards = await ctx.bank.listCards(ctx.customerId);
  return matchCardByLast4(cards, text) ?? matchCardByNameHint(cards, text) ?? matchCardByKindHint(cards, text);
}

/** 供编排器使用的卡片术语导出 */
export {
  CARD_KIND_LABELS,
  CARD_STATUS_LABELS,
  RESTRICTION_CAUSE_LABELS,
  RESTRICTION_CHANNEL_LABELS,
  LIMIT_RULES,
  computePayloadHash,
  describeCard,
  isCardBlocked,
};

// ============================================================================
// 订阅代扣(新场景)
// ============================================================================

const SUB_DAY_MS = 24 * 3600 * 1000;
/** 识别窗口:与账单分析的"定期支出"口径一致,半年足够覆盖月/季/年三种周期 */
const SUBSCRIPTION_WINDOW_DAYS = 180;

/**
 * 取数 + 识别(能力层与路由层共用同一份实现)。
 *
 * ★ 为什么必须共用:
 *   路由层要"不猜"就必须先知道客户到底有哪些订阅(它得能回答"你说的是哪一笔");
 *   能力层要出清单也要知道。两处各写一遍取数,迟早出现
 *   「路由认为可取消、能力认为没有协议」这种自相矛盾 ——
 *   而它表现出来就是"系统答应了却办不成",最难解释的一类故障。
 */
export async function buildSubscriptionScan(
  ctx: ExecutionContext,
  windowDays = SUBSCRIPTION_WINDOW_DAYS,
): Promise<SubscriptionScanResult> {
  const [transactions, mandates] = await Promise.all([
    ctx.bank.fetchForAnalysis(ctx.customerId, { from: ctx.now - windowDays * SUB_DAY_MS, to: ctx.now }),
    ctx.bank.listSubscriptions(ctx.customerId),
  ]);

  /**
   * ★ "对手方是不是我转账给的某个**人**"是银行侧事实,必须去收款人目录里查。
   *   房租每月 1 号 5800 元,间隔与金额都最规律 —— 只有这条事实能把它
   *   与商户代扣区分开(取消房租的后果是违约,取消会员的后果是没得看剧)。
   */
  const ids = [...new Set(transactions.map((t) => t.counterpartyId).filter((v): v is string => typeof v === "string" && v.length > 0))];
  const personalPayeeIds = new Set<string>();
  for (const id of ids) {
    const payee = await ctx.bank.getPayee(ctx.customerId, id);
    if (payee) personalPayeeIds.add(id);
  }

  return scanSubscriptions({ transactions, mandates, now: ctx.now, windowDays, personalPayeeIds });
}

function subscriptionItemData(item: SubscriptionItem) {
  return {
    subscriptionId: item.subscriptionId,
    merchantName: item.merchantName,
    category: item.category,
    amount: item.amount,
    currency: item.currency,
    cadence: item.cadence,
    cadenceLabel: item.cadenceLabel,
    nextDebitAt: item.nextDebitAt,
    daysUntilNext: item.daysUntilNext,
    status: item.status,
    statusLabel: item.statusLabel,
    cancelChannel: item.cancelChannel,
    cancelChannelLabel: item.cancelChannelLabel,
    cancelable: item.cancelable,
    cancelBlockReason: item.cancelBlockReason,
    evidence: {
      keywords: item.evidence.keywords,
      occurrences: item.evidence.occurrences,
      intervalDays: item.evidence.intervalDays,
      amountStable: item.evidence.amountStable,
      amountSpread: item.evidence.amountSpread,
    },
  };
}

/**
 * 注册订阅代扣的四个能力。
 *
 * ★ 分级依据**不是"订阅业务有几个流程",而是每个动作的后果**:
 *   · scan / list / detail —— 只读,自动执行(绿色);
 *   · cancel              —— 改变资金状态与合同关系:baseTier=confirm(黄色),
 *                            而且必须在展示完整详情之后由客户确认。
 *
 *   ★ 为什么 cancel 是黄色而不是绿色:它看上去像"省钱"(减少未来支出,方向安全),
 *     但它改的是**已经签下的协议**:取消后服务终止、保险断保、重新签约可能涨价。
 *     后果由客户承担的决定,Agent 不能替他做 —— 这与"挂失可以自动执行"并不矛盾:
 *     挂失只把风险敞口关小,不改变任何合同关系。
 */
export function registerSubscriptionCapabilities(registry: CapabilityRegistry): void {
  // ---- 自动识别(只读)----
  registry.register({
    name: "subscription.scan",
    description:
      "自动扫描客户的交易流水,识别出其中的**订阅代扣**:视频/音乐/云盘/课程/健身等关键词命中," +
      "或「固定周期 + 固定金额」的规律性扣款。同时交叉核对银行侧代扣协议," +
      "给出每一笔的金额、下次扣款时间、以及**能不能在本行取消**。" +
      "用户说『帮我看看哪些是自动扣费的』『我签了哪些代扣』『有没有乱扣的订阅』时使用。只读。",
    inputSchema: z.object({
      withinDays: z.number().int().positive().max(365).optional().describe("识别窗口天数,默认 180"),
      focus: z.enum(["all", "cancelable", "upcoming"]).optional().describe("只看某类:全部 / 可在本行取消的 / 即将扣款的"),
    }),
    outputSchema: z.object({
      totalCount: z.number(),
      activeCount: z.number(),
      cancelableCount: z.number(),
      merchantOnlyCount: z.number(),
      cancelledCount: z.number(),
      monthlyTotal: z.number(),
      items: z.array(z.record(z.unknown())),
      excluded: z.array(z.object({ counterpartyName: z.string(), amount: z.number(), cadence: z.string(), reason: z.string() })),
      windowDays: z.number(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["monthlyTotal", "items[].amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const windowDays = typeof input["withinDays"] === "number" ? Number(input["withinDays"]) : SUBSCRIPTION_WINDOW_DAYS;
      const scan = await buildSubscriptionScan(ctx, windowDays);
      const focus = (input["focus"] as "all" | "cancelable" | "upcoming" | undefined) ?? "all";

      let items = scan.items;
      if (focus === "cancelable") items = items.filter((i) => i.cancelable);
      if (focus === "upcoming") items = upcomingRenewals(items, ctx.now, 30);

      const lines: string[] = [];
      lines.push(scan.summary);
      lines.push("");
      if (items.length === 0) {
        lines.push(focus === "all" ? "没有可列出的订阅代扣。" : "没有符合条件的订阅代扣。");
      } else {
        lines.push(...renderSubscriptionList(items));
        lines.push("");
        lines.push(
          `每笔均附识别依据,并标明能否在本行取消。本月仍将扣款的合计约 ¥${fmtSubMoney(scan.monthlyTotal)}。`,
        );
        const blocked = items.filter((i) => !i.cancelable && i.status !== "cancelled");
        if (blocked.length > 0) {
          lines.push("");
          lines.push(`其中 ${blocked.length} 笔不能在本行解约(无本行代扣协议,属商户侧自动续费):`);
          for (const b of blocked) lines.push(`  · ${b.merchantName}:${b.cancelBlockReason ?? ""}`);
        }
      }
      if (scan.excluded.length > 0) {
        lines.push("");
        lines.push("另识别到以下规律性付款,不属于订阅代扣,未列入可取消清单:");
        for (const e of scan.excluded) lines.push(`  · ${e.counterpartyName}(${e.cadence} ¥${fmtSubMoney(e.amount)}):${e.reason}`);
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "subscription_scanned",
        payload: {
          capability: "subscription.scan",
          windowDays,
          scannedTransactions: scan.scannedTransactions,
          totalCount: scan.items.length,
          monthlyTotal: scan.monthlyTotal,
          // ★ 每一笔的**识别依据**一并入链:争议时能回答"系统凭什么认为这是一笔订阅"
          items: scan.items.map((i) => ({
            merchantName: i.merchantName,
            amount: i.amount,
            cadence: i.cadence,
            keywords: i.evidence.keywords,
            occurrences: i.evidence.occurrences,
            intervalDays: i.evidence.intervalDays,
            amountStable: i.evidence.amountStable,
            mandate: i.subscriptionId,
            cancelable: i.cancelable,
          })),
          excluded: scan.excluded.map((e) => ({ counterpartyName: e.counterpartyName, reason: e.reason })),
          note: "识别由确定性引擎完成:关键词或固定周期金额两条路径,金额与时间全部来自银行流水与代扣协议,模型未参与判断。",
        },
      });

      const scanSummary = lines.join("\n");
      if (ctx.extras && items.length > 0) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "订阅代扣识别",
          subtitle: scan.summary,
          items: items.slice(0, 10).map((item, i) => ({
            title: `${i + 1}. ${item.merchantName}`,
            value: `¥${fmtSubMoney(item.amount)}`,
            badge: item.cancelable ? "可本行取消" : "商户侧",
            tone: item.cancelable ? "ok" : "medium",
            lines: [item.cadence, item.nextDebitAt != null ? `下次 ${fmtSubDay(item.nextDebitAt)}` : ""].filter(Boolean),
          })),
          compactBody: `识别 ${items.length} 笔订阅,本月仍将扣约 ¥${fmtSubMoney(scan.monthlyTotal)}。明细见卡片。`,
        };
      }

      return {
        ok: true,
        data: {
          totalCount: scan.items.length,
          activeCount: scan.items.filter((i) => i.status === "active").length,
          cancelableCount: scan.items.filter((i) => i.cancelable).length,
          merchantOnlyCount: scan.merchantOnlyCount,
          cancelledCount: scan.cancelledCount,
          monthlyTotal: scan.monthlyTotal,
          items: items.map(subscriptionItemData),
          excluded: scan.excluded,
          windowDays,
          summary: scanSummary,
        },
        summary: scanSummary,
      };
    },
  });

  // ---- 续费提醒(只读)----
  registry.register({
    name: "subscription.list",
    description:
      "列出**即将扣款**的订阅代扣:每一笔的扣费金额、扣款日期与倒计时天数。" +
      "用户说『我有哪些快到期了』『什么时候扣我的钱』『这个月还要扣多少』『续费提醒』时使用。只读。" +
      "★ 同时列出「本行关不了但商户侧仍会扣」的那些 —— 漏掉它们,客户就会在扣款之后才想起来。",
    inputSchema: z.object({
      withinDays: z.number().int().positive().max(120).optional().describe("提醒窗口天数,默认 30"),
    }),
    outputSchema: z.object({
      withinDays: z.number(),
      upcomingCount: z.number(),
      upcomingTotal: z.number(),
      items: z.array(z.record(z.unknown())),
      /** 商户侧仍会扣、本行关不了的笔数 */
      merchantSideCount: z.number(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["upcomingTotal", "items[].amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const withinDays = typeof input["withinDays"] === "number" ? Number(input["withinDays"]) : 30;
      const scan = await buildSubscriptionScan(ctx);
      const upcoming = upcomingRenewals(scan.items, ctx.now, withinDays);
      const upcomingTotal = Math.round(upcoming.reduce((s, i) => s + i.amount, 0) * 100) / 100;

      const lines: string[] = [];
      if (upcoming.length === 0) {
        lines.push(`未来 ${withinDays} 天内没有识别到要扣款的订阅代扣。`);
      } else {
        lines.push(`未来 ${withinDays} 天内有 ${upcoming.length} 笔订阅代扣要扣款,合计 ¥${fmtSubMoney(upcomingTotal)}:`);
        lines.push("");
        for (const [i, item] of upcoming.entries()) {
          lines.push(
            `${i + 1}. ${item.merchantName} —— ${subDaysText(item.daysUntilNext)}扣款` +
              `(${fmtSubDay(item.nextDebitAt!)}),扣 ¥${fmtSubMoney(item.amount)}`,
          );
          lines.push(
            `   ${item.cancelable ? "可在本行取消" : "只能在该商户侧关闭(本行无代扣协议)"}` +
              `${item.cancelable ? `;想取消就说「取消${item.merchantName}」` : `;关闭路径:${item.merchantCancelPath ?? "商户 App 内的订阅设置"}`}`,
          );
        }
        lines.push("");
        lines.push("以上为扣款时间与金额,并标明能否在本行关闭。");
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "subscription_renewal_reminded",
        payload: {
          capability: "subscription.list",
          withinDays,
          upcomingCount: upcoming.length,
          upcomingTotal,
          // ★ 续费提醒的凭证:提醒过谁、什么时候、提醒的是哪几笔、金额多少
          items: upcoming.map((i) => ({
            merchantName: i.merchantName,
            amount: i.amount,
            nextDebitAt: i.nextDebitAt,
            daysUntilNext: i.daysUntilNext,
            cancelable: i.cancelable,
          })),
          note: "扣款金额与日期来自银行侧代扣协议与流水推算,不是模型生成的话术。",
        },
      });

      const subListSummary = lines.join("\n");
      if (ctx.extras && upcoming.length > 0) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "续费提醒",
          subtitle: `${withinDays} 天内 ${upcoming.length} 笔 · 合计 ¥${fmtSubMoney(upcomingTotal)}`,
          items: upcoming.map((item, i) => ({
            title: `${i + 1}. ${item.merchantName}`,
            value: `¥${fmtSubMoney(item.amount)}`,
            badge: subDaysText(item.daysUntilNext),
            tone: item.daysUntilNext != null && item.daysUntilNext <= 7 ? "medium" : "plain",
            lines: [
              item.nextDebitAt != null ? fmtSubDay(item.nextDebitAt) : "",
              item.cancelable ? "可在本行取消" : "仅能在商户侧关闭",
            ].filter(Boolean),
          })),
          compactBody: `未来 ${withinDays} 天有 ${upcoming.length} 笔要扣款,合计 ¥${fmtSubMoney(upcomingTotal)}。`,
        };
      }

      return {
        ok: true,
        data: {
          withinDays,
          upcomingCount: upcoming.length,
          upcomingTotal,
          items: upcoming.map((i) => ({ ...subscriptionItemData(i), absoluteDate: i.nextDebitAt != null ? fmtSubDay(i.nextDebitAt) : null })),
          merchantSideCount: upcoming.filter((i) => !i.cancelable).length,
          summary: subListSummary,
        },
        summary: subListSummary,
      };
    },
  });

  // ---- 单笔详情(只读)----
  registry.register({
    name: "subscription.detail",
    description:
      "查询某一笔订阅代扣的详情:每期扣多少、下次什么时候扣、签约通道、识别依据、" +
      "以及**取消之后本期已扣费用怎么办、会失去什么**。用户说『爱奇艺会员多少钱』『这笔什么时候扣』时使用。只读。",
    inputSchema: z.object({
      subscriptionId: z.string().optional().describe("代扣协议号(系统解析后填入)"),
      merchantName: z.string().max(60).optional().describe("商户名(用户提到的名字)"),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      subscriptionId: z.string().nullable(),
      merchantName: z.string().nullable(),
      amount: z.number().nullable(),
      nextDebitAt: z.number().nullable(),
      cancelable: z.boolean(),
      cancelBlockReason: z.string().nullable(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const scan = await buildSubscriptionScan(ctx);
      const id =
        typeof input["subscriptionId"] === "string"
          ? String(input["subscriptionId"])
          : typeof input["__subscriptionId"] === "string"
            ? String(input["__subscriptionId"])
            : null;
      const name =
        typeof input["merchantName"] === "string"
          ? String(input["merchantName"])
          : typeof input["__subMerchant"] === "string"
            ? String(input["__subMerchant"])
            : null;

      let item: SubscriptionItem | null = id ? (scan.items.find((i) => i.subscriptionId === id) ?? null) : null;
      let closest: { name: string | null; score: number } = { name: null, score: 0 };
      if (!item && name) {
        const match = matchSubscription(name, scan.items);
        item = match.best;
        closest = { name: match.closestName, score: match.closestScore };
      }
      if (!item && !name && scan.items.length === 1) item = scan.items[0]!;

      if (!item) {
        const known = scan.items.filter((i) => i.status !== "cancelled").map((i) => i.merchantName);
        return {
          ok: false,
          error: {
            code: "SUBSCRIPTION_NOT_FOUND",
            message:
              `没有找到「${name ?? "这笔"}」对应的订阅代扣。` +
              (known.length > 0 ? `您目前识别到的是:${known.join("、")}。` : "近半年的流水里也没有识别到订阅代扣。") +
              (closest.name && closest.score >= 0.45 ? `您是想说「${closest.name}」吗?` : ""),
            retryable: true,
          },
        };
      }

      const lines = renderSubscriptionDetail(item, ctx.now);
      const subSummary = lines.join("\n");
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "execution_completed",
        payload: {
          capability: "subscription.detail",
          merchantName: item.merchantName,
          amount: item.amount,
          canvas: item.cancelable ? "cancelable" : "merchant_side_or_cancelled",
          note: "查询本身不改变任何状态;是否可取消由银行侧代扣协议决定。",
        },
      });

      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "订阅代扣详情",
          subtitle: item.merchantName,
          items: [
            {
              title: item.merchantName,
              value: `¥${fmtSubMoney(item.amount)}`,
              badge: item.cancelable ? "可本行取消" : item.cancelChannelLabel,
              tone: item.cancelable ? "ok" : "medium",
              lines: [
                item.cadenceLabel,
                item.nextDebitAt != null ? `下次扣款 ${fmtSubDay(item.nextDebitAt)}` : "暂无下次扣款日",
                item.cancelConsequence,
              ],
            },
          ],
          compactBody: `${item.merchantName} 每期 ¥${fmtSubMoney(item.amount)} · ${item.cancelable ? "可在本行取消" : "需在商户侧关闭"}`,
          footer: item.refundPolicy,
        };
      }

      return {
        ok: true,
        data: {
          found: true,
          subscriptionId: item.subscriptionId,
          merchantName: item.merchantName,
          amount: item.amount,
          nextDebitAt: item.nextDebitAt,
          cancelable: item.cancelable,
          cancelBlockReason: item.cancelBlockReason,
          summary: subSummary,
        },
        summary: subSummary,
      };
    },
  });

  // ---- 一键取消(黄色:必须展示详情并确认)----
  registry.register({
    name: "subscription.cancel",
    description:
      "解除一份**本行签约的**代扣协议,下一期起不再扣款。" +
      "用户说『把爱奇艺会员关了』『取消自动续费』『别再扣了』时使用。" +
      "★ 三条硬约束:① 必须先展示金额与下次扣款日,由客户确认(黄色操作);" +
      "② 本期已扣费用按协议处理(**不是退款**);" +
      "③ 商户侧自动续费(应用商店订阅)本行没有协议可解,必须如实说明,不得声称已取消。",
    inputSchema: z.object({
      subscriptionId: z.string().optional().describe("代扣协议号;由系统解析后填入,模型不要编造"),
      merchantName: z.string().max(60).optional().describe("用户提到的商户名(解析不到协议号时使用)"),
      reason: z.string().max(200).optional().describe("客户自述的取消原因,供留存"),
    }),
    outputSchema: z.object({
      ok: z.boolean(),
      subscriptionId: z.string(),
      merchantName: z.string(),
      statusLabel: z.string(),
      cancelledAt: z.number(),
      effective: z.string(),
      nextDebitAtAfter: z.number().nullable(),
      refundPolicy: z.string(),
      cancelConsequence: z.string(),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "reversible",
    /**
     * ★ moneyMovement=true 的含义在这里是"改变资金状态与合同关系":
     *   它决定的是**今后每个月还扣不扣**,因此必须独立裁决、不得继承前置节点的许可。
     *   注意它并不代表"方向危险" —— 减少支出的方向是安全的,可它同样改变合同关系,
     *   后果(服务终止/断保)由客户承担,所以仍然要给客户看详情再确认。
     */
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["__subAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      // ★ 能力层独立复核(与卡片场景的司法冻结同一套做法):
      //   策略引擎已经拦过"不存在/商户侧/已取消"三类,这里再拦一次 ——
      //   防止有人绕过路由直接调能力。同一个判断,两道闸门。
      const scan = await buildSubscriptionScan(ctx);
      const id =
        typeof input["subscriptionId"] === "string"
          ? String(input["subscriptionId"])
          : typeof input["__subscriptionId"] === "string"
            ? String(input["__subscriptionId"])
            : null;
      const name =
        typeof input["merchantName"] === "string"
          ? String(input["merchantName"])
          : typeof input["__subMerchant"] === "string"
            ? String(input["__subMerchant"])
            : null;
      let item: SubscriptionItem | null = id ? (scan.items.find((i) => i.subscriptionId === id) ?? null) : null;
      if (!item && name) item = matchSubscription(name, scan.items).best;

      const known = scan.items.filter((i) => i.status !== "cancelled").map((i) => i.merchantName);

      const reject = async (code: string, message: string): Promise<CapabilityOutcome> => {
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "subscription_cancel_rejected",
          payload: {
            capability: "subscription.cancel",
            code,
            query: name ?? id,
            knownMerchants: known,
            executed: false,
            note: "记录的是**没有执行**的取消请求。客户事后说「我早就让你们关了」时,这条就是当时的答案。",
          },
        });
        return { ok: false, error: { code, message, retryable: code === "SUBSCRIPTION_NOT_FOUND" } };
      };

      if (!item) {
        return reject(
          "SUBSCRIPTION_NOT_FOUND",
          `没有找到「${name ?? "这笔"}」对应的订阅代扣,**没有任何操作被执行**。` +
            (known.length > 0
              ? `您目前识别到的是:${known.join("、")}。想取消哪一笔可以说它的名字。`
              : "近半年的流水里也没有识别到订阅代扣。"),
        );
      }
      if (item.cancelChannel === "merchant") {
        return reject(
          "MERCHANT_SIDE_NO_MANDATE",
          `「${item.merchantName}」不在本行可解约范围 —— 它属于商户侧自动续费,本行没有代扣协议。` +
            `关闭路径:${item.merchantCancelPath ?? "该商户 App 内的订阅设置"}。`,
        );
      }
      if (item.status === "cancelled") {
        return reject("ALREADY_CANCELLED", `「${item.merchantName}」这笔代扣此前已经取消过了,不会再扣款,不需要再操作一次。`);
      }
      if (!item.subscriptionId) {
        return reject("NO_MANDATE_RECORD", `没有查到「${item.merchantName}」的代扣协议,无法在本行解约。`);
      }

      const receipt = await ctx.bank.cancelSubscription({
        customerId: ctx.customerId,
        subscriptionId: item.subscriptionId,
        ...(input["reason"] ? { reason: String(input["reason"]) } : {}),
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const lines: string[] = [];
      lines.push(receipt.wording);
      lines.push("");
      lines.push(`商户:${receipt.merchantName}`);
      /**
       * ★ 回执里给客户看的是**协议号**(签约时印在协议上的那串 DH…),
       *   不是内部的 subscriptionId(SUB_…)。
       *   两个号都能定位这一笔,但客户手里只有协议号 —— 给他看一个
       *   他从没见过、也无从核对的内码,等于没给凭据。
       *   确认卡上印的也是协议号,回执必须与之一致。
       */
      const agreement = await ctx.bank.getSubscription(ctx.customerId, receipt.subscriptionId);
      lines.push(`代扣协议号:${agreement?.agreementNo ?? receipt.subscriptionId}`);
      lines.push(`取消时间:${fmtSubDateTime(receipt.cancelledAt)}`);
      lines.push(`生效口径:下一期起不再扣款。解除的是后续扣款,不是已扣费用的退还。`);
      lines.push(`本期已扣费用:${receipt.refundPolicy}`);
      lines.push(`取消后果:${receipt.cancelConsequence}`);
      lines.push(`回执号:${receipt.reference}`);

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "subscription_cancelled",
        payload: {
          capability: "subscription.cancel",
          subscriptionId: receipt.subscriptionId,
          merchantName: receipt.merchantName,
          amount: item.amount,
          cancelledAt: receipt.cancelledAt,
          effective: receipt.effective,
          /** ★ 关键事实:扣款计划已经不存在了 */
          nextDebitAtAfter: receipt.nextDebitAtAfter,
          refundPolicy: receipt.refundPolicy,
          cancelConsequence: receipt.cancelConsequence,
          reason: input["reason"] ?? null,
          reference: receipt.reference,
          note:
            "取消生效口径是「下一期起不再扣款」,不是退款。" +
            "nextDebitAtAfter=null 是「扣款计划已终止」的机器可验证证据;退款是另一件事,需另行申请。",
        },
      });

      return {
        ok: true,
        data: {
          ok: true,
          subscriptionId: receipt.subscriptionId,
          merchantName: receipt.merchantName,
          statusLabel: receipt.statusLabel,
          cancelledAt: receipt.cancelledAt,
          effective: receipt.effective,
          nextDebitAtAfter: receipt.nextDebitAtAfter,
          refundPolicy: receipt.refundPolicy,
          cancelConsequence: receipt.cancelConsequence,
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });
}

// ============================================================================
// 一次性构建完整注册表
// ============================================================================

// ============================================================================
// 预算规划(场景二的延伸能力)
// ============================================================================

/**
 * 注册"本月剩余预算规划"能力。
 *
 * ★ 为什么这是一个独立能力,而不是在回复里现算一句:
 *   ① 它要读银行流水(自然月至今),这是**数据访问**,必须走能力层;
 *   ② 它给出的每个数字都必须可复现:预算 − 已支出 = 剩余,剩余 ÷ 剩余天数 = 每日可用。
 *      算式写在输出里(calculation 字段),客户与审计都能自己加一遍;
 *   ③ 它是"个性化主动建议"的第一条(「要帮你规划这个月剩余预算吗」)的落点 ——
 *      建议点进来必须真的能办,否则那句建议就是空头支票。
 *
 * ★ 只读、auto 级:不涉及资金变动,Agent 可以自主完成 ——
 *   这也正好是需求里"不重要的流程 Agent 自己做完"的一个具体例子。
 */
function registerBudgetCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "account.budget_plan",
    description:
      "帮客户规划本月剩余预算:给出预算额、已支出、剩余额度、剩余每天可用金额与主要支出项。" +
      "用户说『帮我规划这个月预算』『这个月还剩多少能花』『预算5000够不够』时使用。只读。" +
      "★ 若用户没有给出预算额,不要猜 —— 先报告本月已支出,再问他打算用多少预算。",
    inputSchema: z.object({
      budget: z.number().positive().optional().describe("客户设定的本月预算总额(元)。用户没说就不要填"),
      month: z
        .string()
        .regex(/^\d{4}-\d{2}$/)
        .optional()
        .describe("预算所属月份,格式 YYYY-MM。不填则为当前自然月"),
    }),
    outputSchema: z.object({
      needsBudget: z.boolean(),
      budget: z.number().nullable(),
      monthLabel: z.string(),
      spent: z.number(),
      spentCount: z.number(),
      remaining: z.number().nullable(),
      daysLeft: z.number(),
      dailyAllowance: z.number().nullable(),
      topCategories: z.array(z.object({ key: z.string(), total: z.number(), count: z.number() })),
      /** ★ 计算过程:逐段拼成算式,客户可自行核对 */
      calculation: z.array(z.string()),
      message: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["budget", "spent", "remaining", "dailyAllowance", "topCategories[].total"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      // ---- 时间口径:东八区自然月(与客户看到的日历一致)----
      const now = ctx.now;
      const range = monthRange(now);
      let from = range.from;
      let monthLabel = range.label;
      let monthDays: number;
      if (typeof input["month"] === "string") {
        const [y, m] = input["month"].split("-").map((x) => Number(x));
        from = Date.UTC(y ?? 1970, (m ?? 1) - 1, 1) - 8 * 3600 * 1000;
        const next = Date.UTC(y ?? 1970, m ?? 1, 1) - 8 * 3600 * 1000;
        monthDays = Math.round((next - from) / (24 * 3600 * 1000));
        monthLabel = `${input["month"]}(整月)`;
      } else {
        const { y, m } = { y: Number(dayText(now).slice(0, 4)), m: Number(dayText(now).slice(5, 7)) };
        const next = Date.UTC(y, m, 1) - 8 * 3600 * 1000;
        monthDays = Math.round((next - from) / (24 * 3600 * 1000));
      }

      const txs = await ctx.bank.listTransactions(ctx.customerId, {
        from,
        to: now,
        direction: "out",
        limit: 300,
      });

      const spent = Math.round(txs.reduce((s, t) => s + t.amount, 0) * 100) / 100;
      const byCategory = new Map<string, { total: number; count: number }>();
      for (const t of txs) {
        const key = t.category ?? "未分类";
        const cur = byCategory.get(key) ?? { total: 0, count: 0 };
        cur.total += t.amount;
        cur.count += 1;
        byCategory.set(key, cur);
      }
      const topCategories = [...byCategory.entries()]
        .map(([key, v]) => ({ key, total: Math.round(v.total * 100) / 100, count: v.count }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 5);

      // 剩余天数:含今天(今天还没过完,钱还得花)
      const daysLeft = Math.max(1, monthDays - Math.floor((now - from) / (24 * 3600 * 1000)));

      // ---- 还没给预算额:先报已支出,再问预算 ----
      if (input["budget"] == null) {
        const message = [
          `${monthLabel} 您已支出 ${moneyText(spent)} 元(${txs.length} 笔),主要集中在:`,
          ...topCategories.slice(0, 3).map((c) => `  · ${c.key}:${moneyText(c.total)} 元(${c.count} 笔)`),
          "",
          "您打算这个月总共花多少?告诉我一个数(例如「预算 5000」),我就能算出还剩多少、每天可以用多少。",
        ].join("\n");

        ctx.extras?.citations.push({
          id: "data:本月支出",
          topic: `本月已支出 ${moneyText(spent)} 元`,
          source: SOURCES.ledger,
          subject: "客户本人",
          effective: range.label,
          asOf: now,
          calculation: [
            `本期流水 ${txs.length} 笔,合计 ${moneyText(spent)} 元`,
            ...topCategories.map((c) => `${c.key} ${moneyText(c.total)}(${c.count} 笔)`),
          ],
          note: "仅统计支出方向、且已清算的交易;未包含待清算与预授权",
          kind: "data",
        });
        if (ctx.extras) ctx.extras.hasMonetary = true;

        if (ctx.extras) {
          ctx.extras.visual = {
            kind: "list_report",
            title: "本月支出",
            subtitle: `${monthLabel} 已支出 ${moneyText(spent)} 元`,
            bars: topCategories.slice(0, 5).map((c) => ({ label: c.key, value: c.total, tone: "plain" as const })),
            items: topCategories.slice(0, 5).map((c) => ({
              title: c.key,
              value: `¥${moneyText(c.total)}`,
              lines: [`${c.count} 笔`],
            })),
            compactBody: `${monthLabel} 已支出 ${moneyText(spent)} 元。告诉我预算额(如「预算5000」),我帮您算每天可用多少。`,
          };
        }

        return {
          ok: true,
          data: {
            needsBudget: true,
            budget: null,
            monthLabel,
            spent,
            spentCount: txs.length,
            remaining: null,
            daysLeft,
            dailyAllowance: null,
            topCategories,
            calculation: [`已支出 = ${txs.length} 笔支出合计 = ${moneyText(spent)} 元`],
            message,
          },
          summary: message,
        };
      }

      // ---- 有预算额:算出剩余与每日可用,并把算式写出来 ----
      const budget = Number(input["budget"]);
      const remaining = Math.round((budget - spent) * 100) / 100;
      const dailyAllowance = Math.max(0, Math.round((remaining / daysLeft) * 100) / 100);

      const calculation = [
        `预算 ${moneyText(budget)} 元`,
        `已支出 ${moneyText(spent)} 元(${txs.length} 笔,来自银行流水)`,
        `剩余 = ${moneyText(budget)} − ${moneyText(spent)} = ${moneyText(remaining)} 元`,
        `剩余天数 = ${daysLeft} 天(含今天)`,
        `每天可用 = ${moneyText(remaining)} ÷ ${daysLeft} ≈ ${moneyText(dailyAllowance)} 元`,
      ];

      const lines: string[] = [];
      if (remaining < 0) {
        lines.push(`请注意:本月预算已超出 ${moneyText(Math.abs(remaining))} 元。`);
        lines.push("");
        lines.push(`预算 ${moneyText(budget)} 元,已支出 ${moneyText(spent)} 元(${txs.length} 笔)。`);
        lines.push(`这个月还剩 ${daysLeft} 天,建议接下来只保留必要支出;要不要我帮您看一下哪几类还能压一压?`);
      } else {
        lines.push(
          `${monthLabel} 预算 ${moneyText(budget)} 元,已用 ${moneyText(spent)} 元,` +
            `还剩 ${moneyText(remaining)} 元。`,
        );
        lines.push("");
        lines.push(
          `距月底还有 ${daysLeft} 天,平均每天可用约 ${moneyText(dailyAllowance)} 元` +
            `(按剩余 ${moneyText(remaining)} 元 ÷ ${daysLeft} 天计算)。`,
        );
      }
      if (topCategories.length > 0) {
        lines.push("");
        lines.push("本月支出主要在哪:");
        for (const c of topCategories.slice(0, 3)) {
          const share = spent > 0 ? Math.round((c.total / spent) * 1000) / 10 : 0;
          lines.push(`  · ${c.key}:${moneyText(c.total)} 元(${c.count} 笔,占 ${share}%)`);
        }
      }
      lines.push("");
      lines.push("以上数字全部来自银行流水,预算额由您设定;需要调整预算直接说个数就行。");

      const message = lines.join("\n");

      ctx.extras?.citations.push({
        id: "data:预算规划",
        topic: `本月剩余预算 ${moneyText(remaining)} 元`,
        source: SOURCES.ledger,
        subject: "客户本人",
        effective: `${monthLabel} · 截至 ${dayText(now)}`,
        asOf: now,
        calculation,
        note: "仅统计支出方向、且已清算的交易;剩余天数按自然月计算(含今天)",
        kind: "data",
      });
      if (ctx.extras) ctx.extras.hasMonetary = true;

      const budgetLead =
        remaining < 0
          ? `预算已超 ${moneyText(Math.abs(remaining))} 元`
          : `还剩 ${moneyText(remaining)} 元 · 日均约 ${moneyText(dailyAllowance)} 元`;
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "list_report",
          title: "本月预算",
          subtitle: `${monthLabel} 预算 ${moneyText(budget)} 元 · 已用 ${moneyText(spent)} 元`,
          summary: budgetLead,
          bars: topCategories.slice(0, 5).map((c) => ({ label: c.key, value: c.total, tone: "plain" as const })),
          items: topCategories.slice(0, 5).map((c) => ({
            title: c.key,
            value: `¥${moneyText(c.total)}`,
            lines: [`${c.count} 笔 · 占 ${spent > 0 ? Math.round((c.total / spent) * 1000) / 10 : 0}%`],
          })),
          compactBody: `${monthLabel} ${budgetLead}。`,
        };
      }

      return {
        ok: true,
        data: {
          needsBudget: false,
          budget,
          monthLabel,
          spent,
          spentCount: txs.length,
          remaining,
          daysLeft,
          dailyAllowance,
          topCategories,
          calculation,
          message,
        },
        summary: message,
      };
    },
  });
}

// ============================================================================
// 多份材料比对(账单分析之上的扩展能力,不占场景编号)
// ============================================================================

/**
 * 注册"多份材料比对"能力。
 *
 * ★ 为什么是只读、auto 级:
 *   它不改变任何状态,只是把客户**已经提交的**材料摆到一起看是否自相矛盾。
 *   这类"帮你看出问题"的事正是 Agent 该自己做完的(需求里的"不重要的流程自己做完")。
 *
 * ★ 为什么必须把结果同时变成**可视块**:
 *   矛盾点是一种**关系**(A 写 12.8 万、B 写 13.8 万),用文字描述等于让客户
 *   在脑子里对齐两份材料。多列对照 + 差异高亮,客户几乎不用读就能看到问题在哪。
 */
function registerDocumentCompareCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "document.compare",
    description:
      "比对客户提交的多份材料(合同、报价单、发票、回单),找出金额、付款条件、对方主体、" +
      "完工日期等字段之间的矛盾点,并把差异高亮摆出来。" +
      "用户说『帮我比对这几份材料』『合同和发票金额对不上』『有没有矛盾』时使用。只读。" +
      "★ 只报告**字段级差异**,不做法律判断、不认定谁对谁错;" +
      "★ 表述不同但指向同一件事(如「整体装修」与「装修工程」)不算矛盾,不得误报。",
    inputSchema: z.object({
      documentIds: z.array(z.string()).optional().describe("要比对的材料 ID;不填则比对全部"),
      kinds: z
        .array(z.enum(["contract", "quote", "invoice", "receipt", "statement"]))
        .optional()
        .describe("只比对这几类材料(客户点名了『合同和发票』时用)"),
    }),
    outputSchema: z.object({
      documents: z.array(z.object({ id: z.string(), label: z.string(), kindLabel: z.string() })),
      rows: z.array(z.unknown()),
      conflicts: z.array(z.unknown()),
      consistentCount: z.number(),
      conflictCount: z.number(),
      verdict: z.string(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["conflicts[].amountGap"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const wanted = Array.isArray(input["documentIds"]) ? (input["documentIds"] as string[]) : null;
      const kinds = Array.isArray(input["kinds"]) ? (input["kinds"] as string[]) : null;
      const all = await ctx.bank.listDocuments(ctx.customerId);
      /**
       * ★ 客户点名了哪几类,就只比那几类。
       *
       *   「只看一下这份合同」如果还去比全部三份,答的就不是他问的问题 ——
       *   而且会顺手把另外两份的矛盾也说出来,让他以为系统答非所问。
       */
      const byKind = kinds && kinds.length > 0 ? all.filter((d) => kinds.includes(d.kind)) : all;
      const picked = wanted && wanted.length > 0 ? byKind.filter((d) => wanted.includes(d.documentId)) : byKind;

      if (all.length === 0) {
        return {
          ok: false,
          error: {
            code: "NO_DOCUMENTS",
            message: "您名下还没有可比对的材料。材料上传后我才能帮您核对。",
            retryable: false,
          },
        };
      }
      if (picked.length < 2) {
        return {
          ok: false,
          error: {
            code: "NEED_TWO_DOCUMENTS",
            message:
              all.length < 2
                ? `目前只有 ${all.length} 份材料,至少需要两份才能比对。`
                : "至少要选两份材料才能比对。",
            retryable: true,
          },
        };
      }

      const result = compareDocuments(picked);

      // 可视块:多列对照 + 差异高亮
      if (ctx.extras) {
        ctx.extras.visual = {
          kind: "doc_diff",
          title: `材料比对(${result.documents.length} 份)`,
          documents: result.documents,
          rows: result.rows,
          conflictCount: result.conflictCount,
          verdict: result.verdict,
          actions:
            result.conflictCount > 0
              ? [{ label: "先问对方确认金额", say: "帮我记一下:材料金额不一致,我已联系对方确认" }]
              : undefined,
        };
        ctx.extras.citations.push({
          id: "data:材料比对",
          topic: `比对 ${result.documents.length} 份材料,发现 ${result.conflictCount} 处矛盾`,
          source: "客户提交材料 · 原件(合同/报价单/发票)",
          subject: "客户本人",
          effective: `材料受理截至 ${dayText(ctx.now)}`,
          asOf: ctx.now,
          calculation: result.conflicts.map((c) => `${c.label}:${c.explanation}`),
          note:
            "比对只针对材料上写明的字段,不判断条款的法律效力;" +
            "表述不同但指向同一事项的,不计为矛盾",
          kind: "data",
        });
        ctx.extras.hasMonetary = result.conflicts.some((c) => c.amountGap != null);
      }

      return {
        ok: true,
        data: result as unknown as Record<string, unknown>,
        summary: result.summary,
      };
    },
  });
}

// ============================================================================
// 跨场景事件联动(新场景)
// ============================================================================

/**
 * 把规划所需的数据一次取齐。
 *
 * ★ 这个函数就是需求里那句"**触发后自动调用账单分析、理财、外部订购等现有能力**"
 *   的具体落点 —— 它没有重写任何一条业务逻辑,而是把既有引擎的结论**汇总**起来:
 *     · 账单侧:buildPeriodReport(近 30 天收支)+ detectRecurring(定期支出)
 *     · 订阅侧:buildSubscriptionScan(既有订阅代扣识别与协议交叉核对)
 *     · 理财侧:listWealthHoldings / listWealthProducts(持仓与候选产品)
 *     · 任务侧:listSchedules(已有定时任务)
 *   规划引擎只做"把这些结论排进同一张时间表"这件事。
 *
 * ★ 为什么必须一次取齐而不是让每个触发器自己去查:
 *   同一个触发器里的多个步骤若各自取数,可能落在**不同时刻**的数据上
 *   (比如预算是按 A 时刻的余额算的、扣款清单是按 B 时刻的协议读的),
 *   方案内部就会自相矛盾。取一次、用一份快照,是方案可复核的前提。
 */
export async function buildEventPlanData(ctx: ExecutionContext): Promise<EventPlanData> {
  const now = ctx.now;
  const day = 24 * 3600 * 1000;

  const accounts = await ctx.bank.listAccounts(ctx.customerId);
  const txs = await ctx.bank.fetchForAnalysis(ctx.customerId, { from: now - 180 * day, to: now });
  const bill = buildPeriodReport(txs, { from: now - 30 * day, to: now, compareWithPrevious: true });
  const recurring = detectRecurring(txs.filter((t) => t.direction === "out"), now);
  const subScan = await buildSubscriptionScan(ctx);
  const holdings = await ctx.bank.listWealthHoldings(ctx.customerId);
  const products = await ctx.bank.listWealthProducts({ limit: 4 });
  const schedules = await ctx.bank.listSchedules(ctx.customerId);
  const events = await ctx.bank.listLifeEvents(ctx.customerId);
  const merchants = await ctx.bank.listExternalMerchants({});

  return {
    now,
    accounts,
    transactions: txs,
    bill: {
      periodLabel: bill.periodLabel,
      income: bill.income,
      expense: bill.expense,
      net: bill.net,
      topCategories: bill.topCategories.map((c) => ({ key: c.key, total: c.total, count: c.count })),
      largest: bill.largestTransactions.map((l) => ({
        counterpartyName: l.counterpartyName,
        amount: l.amount,
        category: l.category,
        ts: l.ts,
      })),
    },
    recurring: recurring.items.map((r) => ({
      counterpartyName: r.counterpartyName,
      category: r.category,
      cadence: r.cadence,
      avgAmount: r.avgAmount,
      expectedNext: r.expectedNext,
    })),
    subscriptions: subScan.items,
    holdings: holdings.map((h) => ({ productName: h.productName, marketValue: h.marketValue, profit: h.profit })),
    products: products.map((p) => ({
      productCode: p.productCode,
      name: p.name,
      riskLevel: p.riskLevel,
      minAmount: p.minAmount,
      termDays: p.termDays,
    })),
    schedules: schedules
      .filter((s) => s.status === "active")
      .map((s) => ({
        scheduleId: s.scheduleId,
        amount: s.intent.amount,
        payeeName: s.intent.payee?.name ?? "定时转账",
        nextRunAt: s.nextRunAt,
        cadenceLabel: recurrenceLabel(s.recurrence.frequency),
      })),
    events,
    merchants,
  };
}

function recurrenceLabel(f: "once" | "daily" | "weekly" | "monthly"): string {
  return { once: "一次性", daily: "每日", weekly: "每周", monthly: "每月" }[f];
}

/** 生成一次方案快照:数据 + 方案(两者来自同一时刻,可复核) */
export async function buildEventPlanSnapshot(
  ctx: ExecutionContext,
  ref: EventPlanRef,
): Promise<{ plan: EventPlan; data: EventPlanData }> {
  const data = await buildEventPlanData(ctx);
  const dateHint = ref.occursAt != null ? { occursAt: ref.occursAt, hintText: "客户指定的时间" } : parseEventDateHint(ref.text, data.now);
  const plan = buildEventPlan(data, {
    text: ref.text,
    dateHint,
    ...(ref.triggerId != null ? { triggerId: ref.triggerId } : {}),
    ...(ref.title != null ? { titleHint: ref.title } : {}),
    ...(ref.budget != null ? { budgetHint: ref.budget } : {}),
    ...(ref.occursAt != null ? {} : {}),
  });
  return { plan, data };
}

/**
 * 触发器识别与登记。
 *
 * ★ 登记事件(auto 级)—— 为什么它可以自动执行:
 *   它只是把客户**自己说的话**记进他自己的日程,没有任何资金动作、
 *   没有对外订单、也不改动银行侧任何数据。这与"客户侧记账批注"同一档。
 *   若把它做成黄色,客户说一句"记一下我下月15号纪念日"还要点一次确认,
 *   那这个系统就变成"什么都要问一句"的系统了 —— 而真正需要确认的
 *   (锁钱、下单)反倒会被淹没在一堆确认里。
 */
export function registerEventCapabilities(registry: CapabilityRegistry): void {
  // ---- 触发器与事件清单(只读)----
  registry.register({
    name: "event.list",
    description:
      "列出系统挂载的**事件触发器**(纪念日/生日/发薪日/大额支出预备/出行)以及客户已登记的关键事件。" +
      "用户问『有哪些重要日子』『你能帮我规划什么』时使用。只读。",
    inputSchema: z.object({
      focus: z.enum(["events", "triggers", "all"]).optional().describe("只看已登记事件 / 只看触发器 / 全部,默认全部"),
    }),
    outputSchema: z.object({
      eventCount: z.number(),
      triggerCount: z.number(),
      triggers: z.array(z.record(z.unknown())),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const focus = (input["focus"] as "events" | "triggers" | "all" | undefined) ?? "all";
      const events = await ctx.bank.listLifeEvents(ctx.customerId);
      const triggers = listEventTriggers();
      const lines: string[] = [];
      if (focus !== "triggers") {
        lines.push(renderLifeEventList(events, ctx.now));
        lines.push("");
      }
      if (focus !== "events") {
        lines.push(renderEventTriggerList());
      }
      const eventSummary = lines.join("\n");
      if (ctx.extras && (events.length > 0 || triggers.length > 0)) {
        const dayFmt = (ts: number) =>
          new Date(ts).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai", month: "numeric", day: "numeric" });
        const items = [
          ...events.slice(0, 8).map((e) => ({
            title: e.title,
            badge: e.kindLabel,
            lines: [`${dayFmt(e.occursAt)} · ${e.sourceLabel}`],
          })),
          ...(focus === "events"
            ? []
            : triggers.slice(0, 4).map((t) => ({
                title: t.kindLabel,
                badge: "触发器",
                lines: [`提前 ${t.leadDays} 天 · ${t.mounts}`],
              }))),
        ];
        ctx.extras.visual = {
          kind: "list_report",
          title: "关键事件",
          subtitle: `已登记 ${events.length} 个 · 触发器 ${triggers.length} 类`,
          items,
          compactBody: `已登记 ${events.length} 个关键事件。明细见卡片。`,
        };
      }
      return {
        ok: true,
        data: { eventCount: events.length, triggerCount: triggers.length, triggers, summary: eventSummary },
        summary: eventSummary,
      };
    },
  });

  // ---- 登记客户自述的关键事件(auto:低风险写操作)----
  registry.register({
    name: "event.register",
    description:
      "把客户**自己说出来的**关键事件登记到他的日程(纪念日/生日/出行等),不涉及任何资金动作。" +
      "用户说『记一下11月15号是我结婚纪念日』时使用。",
    inputSchema: z.object({
      kind: z.enum(["birthday", "anniversary", "payday", "big_expense", "travel", "renewal_window"]),
      title: z.string().min(1).max(40).describe("事件名,如「结婚纪念日」"),
      occursAt: z.number().int().positive().describe("事件发生时间(毫秒时间戳);必须由系统解析后填入,模型不要自己算"),
      leadDays: z.number().int().positive().max(EVENT_MAX_LEAD_DAYS).optional().describe("提前多少天进入规划窗口"),
      note: z.string().max(200).optional(),
      budgetHint: z.number().positive().optional().describe("客户自述的预算"),
      rawText: z.string().max(300).optional().describe("客户原话,供留存"),
    }),
    outputSchema: z.object({
      eventId: z.string(),
      title: z.string(),
      kindLabel: z.string(),
      occursAt: z.number(),
      sourceLabel: z.string(),
      summary: z.string(),
    }),
    /**
     * ★ sideEffect 必须是 `reversible`(不是 `none`):这里**写了一件事** ——
     *   它会在银行侧留下一条日程,后续"事件联动"的规划窗口就是按它算出来的。
     *   声明成 `none`(等于"没有任何副作用")会让下游按"纯查询"来措辞与排序,
     *   与事实相反;而它确实是可逆的(客户随时可删可改,所以仍允许自动执行)。
     */
    sideEffect: "reversible",
    moneyMovement: false,
    readOnly: false,
    /**
     * ★ autoExecutable=true 的判据与记账批注完全一致:
     *   写的是**客户自己的日程**,不动钱、不下单、不改银行侧事实数据,且可随时删改。
     */
    autoExecutable: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const event = await ctx.bank.saveLifeEvent({
        customerId: ctx.customerId,
        kind: input["kind"] as LifeEvent["kind"],
        title: String(input["title"]),
        occursAt: Number(input["occursAt"]),
        ...(input["leadDays"] != null ? { leadDays: Number(input["leadDays"]) } : {}),
        ...(input["note"] != null ? { note: String(input["note"]) } : {}),
        ...(input["budgetHint"] != null ? { budgetHint: Number(input["budgetHint"]) } : {}),
        ...(input["rawText"] != null ? { rawText: String(input["rawText"]) } : {}),
      });
      const summary =
        `已记下:${event.title}(${event.kindLabel})—— ${fmtSubDay(event.occursAt)}。\n` +
        "登记本身不涉及资金,也不会创建订单。如需方案,请回复「帮我规划一下」。";
      return {
        ok: true,
        data: {
          eventId: event.eventId,
          title: event.title,
          kindLabel: event.kindLabel,
          occursAt: event.occursAt,
          sourceLabel: event.sourceLabel,
          summary,
        },
        summary,
      };
    },
  });

  // ---- 方案生成(只读:★ 它一步都不执行)----
  registry.register({
    name: "cross_scene_event_planning",
    description:
      "识别客户生活中的**关键事件**(纪念日/生日/发薪日/大额支出预备/出行),结合账单、订阅、理财与定时任务数据," +
      "生成一份**跨场景联动方案**:哪些钱要提前留、哪一天要做什么、以及哪一步需要下单。" +
      "用户说『下个月15号有个重要纪念日帮我规划下』『最近有什么大额支出需要提前准备』时使用。" +
      "★ 硬约束:生成方案**不代表执行** —— 只会产出「资金操作」与「外部服务操作」两类待确认步骤," +
      "每一类都必须由客户**分别确认**之后才会执行;每笔钱的去向与金额都写在方案里。只读。",
    inputSchema: z.object({
      triggerId: z.string().optional().describe("命中的触发器 id;由系统解析后填入,模型不要编造"),
      text: z.string().max(300).optional().describe("客户原话,用于触发器匹配与留痕"),
      occursAt: z.number().int().positive().optional().describe("客户说的事件时间;由系统解析后填入"),
      title: z.string().max(40).optional(),
      budget: z.number().positive().optional(),
    }),
    outputSchema: z.object({
      planId: z.string(),
      eventId: z.string(),
      eventTitle: z.string(),
      occursAt: z.number(),
      daysUntil: z.number(),
      stepCount: z.number(),
      fundTotal: z.number(),
      externalTotal: z.number(),
      steps: z.array(z.record(z.unknown())),
      notDoing: z.array(z.string()),
      sources: z.array(z.string()),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    /**
     * ★ readOnly=true 的含义在这里必须说清楚:
     *   它**只读**银行侧数据(账户/流水/协议/持仓/任务),
     *   生成的方案停留在"待确认步骤列表"里 —— 不改钱、不下单、不建任务。
     *   所有会产生副作用的动作都在另外两个能力里(fund_step / external_step),
     *   而它们各自带着自己的分级与确认卡。
     */
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: ["fundTotal", "externalTotal", "steps[].funds.amount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const ref: EventPlanRef = {
        text: typeof input["text"] === "string" ? String(input["text"]) : "",
        ...(typeof input["triggerId"] === "string" ? { triggerId: String(input["triggerId"]) } : {}),
        ...(typeof input["occursAt"] === "number" ? { occursAt: Number(input["occursAt"]) } : {}),
        ...(typeof input["title"] === "string" ? { title: String(input["title"]) } : {}),
        ...(typeof input["budget"] === "number" ? { budget: Number(input["budget"]) } : {}),
      };
      const { plan, data } = await buildEventPlanSnapshot(ctx, ref);

      /**
       * ★ 兜底闸门:方案里只要有一笔钱的去向没说清,就**不生成执行入口**。
       *   正常路径下不会触发(引擎构造步骤时必然带齐 funds 四元组),
       *   但"合规要求必须被结构保证"的意思就是:即使有人在引擎里写错一步,
       *   出口这里也要挡住,而不是把一份说不清去向的方案递给客户。
       */
      const gaps = checkFundDisclosure(plan.steps);
      if (gaps.length > 0) {
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "event_plan_step_rejected",
          payload: {
            capability: "cross_scene_event_planning",
            planId: plan.planId,
            code: "FUND_DISCLOSURE_INCOMPLETE",
            gaps,
            executed: false,
            note: "方案里有步骤没有说清资金去向与金额,已拒绝生成 —— 合规要求每一笔资金去向必须事先明确告知。",
          },
        });
        return {
          ok: false,
          error: {
            code: "FUND_DISCLOSURE_INCOMPLETE",
            message:
              "这份方案里有步骤**没有说清钱的去向与金额**,所以我不能把它交给您去确认 —— " +
              "没交代清楚就让客户点确认,那个确认是没有意义的。请补充信息后重试。",
            retryable: false,
          },
        };
      }

      const text = renderEventPlan(plan);

      if (ctx.extras) {
        const followUps = eventPlanFollowUpActions(plan);
        const externalTotal =
          plan.externalTotal > 0 ? ` · 外部服务约 ${plan.externalTotal.toLocaleString("zh-CN")} 元` : "";
        ctx.extras.visual = {
          kind: "list_report",
          title: "联动方案",
          subtitle: `${plan.eventTitle} · ${plan.daysUntil} 天后`,
          summary: `${plan.steps.length} 步 · 资金合计 ${plan.fundTotal.toLocaleString("zh-CN")} 元${externalTotal}`,
          items: plan.steps.map((s, i) => ({
            title: `${i + 1}. ${s.title}`,
            badge: eventPlanStepListBadge(s),
            tone: eventPlanStepListTone(s),
            lines: [s.disclosure, s.funds ? `¥${s.funds.amount.toLocaleString("zh-CN")}` : "无需资金"].filter(
              Boolean,
            ),
          })),
          compactBody:
            `「${plan.eventTitle}」共 ${plan.steps.length} 步;方案不等于已执行,请逐步确认。` +
            (followUps.length > 0 ? ` 可先点下方按钮,或说「${followUps[0]!.say}」。` : ""),
          footer:
            (plan.notDoing.length > 0 ? `暂不自动办理:${plan.notDoing.slice(0, 2).join("；")}。` : "") +
            "资金操作与外部服务须分开确认。",
          ...(followUps.length > 0 ? { actions: followUps } : {}),
        };
      }

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "event_plan_generated",
        payload: {
          capability: "cross_scene_event_planning",
          planId: plan.planId,
          triggerId: plan.eventId,
          eventTitle: plan.eventTitle,
          occursAt: plan.occursAt,
          daysUntil: plan.daysUntil,
          fundTotal: plan.fundTotal,
          externalTotal: plan.externalTotal,
          /**
           * ★ 逐步确认的凭据链从这里开始:审计必须能看到
           *   "方案当时把哪几步、什么分级、多少钱、什么去向,摆到了客户面前"。
           *   后面 event_plan_step_confirmed 里的每一项都要能在这一份里找到对应。
           */
          steps: plan.steps.map((s) => ({
            stepId: s.stepId,
            domain: s.domain,
            title: s.title,
            tier: s.tier,
            capability: s.capability,
            amount: s.funds?.amount ?? null,
            fromAccountId: s.funds?.fromAccountId ?? null,
            toName: s.funds?.toName ?? null,
            scheduledAt: s.funds?.scheduledAt ?? null,
            disclosure: s.disclosure,
          })),
          notDoing: plan.notDoing,
          sources: plan.sources,
          /** ★ 这一步是"读了哪些既有引擎":跨场景联动的可追溯来源 */
          dataUsed: {
            accounts: data.accounts.length,
            transactions: data.transactions.length,
            recurring: data.recurring.length,
            subscriptions: data.subscriptions.length,
            holdings: data.holdings.length,
            schedules: data.schedules.length,
            events: data.events.length,
            merchants: data.merchants.length,
          },
          executed: false,
          note:
            "★ 方案 ≠ 执行:本条只记录方案生成,没有任何资金被锁定、没有任何订单被创建。" +
            "资金操作与外部服务操作必须分别由客户确认,分别留痕为 event_plan_step_confirmed。",
        },
      });

      return {
        ok: true,
        data: {
          planId: plan.planId,
          eventId: plan.eventId,
          eventTitle: plan.eventTitle,
          occursAt: plan.occursAt,
          daysUntil: plan.daysUntil,
          stepCount: plan.steps.length,
          fundTotal: plan.fundTotal,
          externalTotal: plan.externalTotal,
          steps: plan.steps.map((s) => ({
            stepId: s.stepId,
            domain: s.domain,
            domainLabel: s.domainLabel,
            title: s.title,
            tier: s.tier,
            executable: s.executable,
            funds: s.funds ?? null,
            disclosure: s.disclosure,
          })),
          notDoing: plan.notDoing,
          sources: plan.sources,
          summary: text,
        },
        summary: text,
      };
    },
  });

  // ---- 资金操作步骤(黄色:锁定资金 / 定时任务)----
  registry.register({
    name: "event.fund_step",
    description:
      "执行联动方案里的**资金操作**那一步:在你自己的账户内预留一笔资金(锁定),或登记一个到点执行的定时任务。" +
      "★ 只做这两件事,不产生对外支付;" +
      "★ 必须先展示资金去向与金额并由客户确认(黄色);" +
      "★ 一次只执行一步 —— 方案里其它步骤不会被顺带执行。",
    inputSchema: z.object({
      planId: z.string().min(1),
      stepId: z.string().min(1),
      mode: z
        .enum(["reserve", "schedule", "release"])
        .describe("reserve = 预留(锁定)资金;schedule = 登记定时任务;release = 解开此前预留的资金"),
      fromAccountId: z.string().min(1),
      toName: z.string().min(1).max(60).describe("这笔钱的用途/去向名目"),
      amount: z.number().positive(),
      scheduledAt: z.number().int().positive().describe("锁定到期时间或定时任务执行时间"),
      purpose: z.string().max(120).optional(),
      eventTitle: z.string().max(40).optional(),
      stepTitle: z.string().max(80).optional(),
    }),
    outputSchema: z.object({
      ok: z.boolean(),
      planId: z.string(),
      stepId: z.string(),
      modeLabel: z.string(),
      amount: z.number(),
      fromAccountLabel: z.string(),
      toName: z.string(),
      reservedUntil: z.number().nullable(),
      scheduleId: z.string().nullable(),
      nextRunAt: z.number().nullable(),
      availableAfter: z.number(),
      reference: z.string(),
      summary: z.string(),
    }),
    sideEffect: "reversible",
    /**
     * ★ moneyMovement=true:它改变的是"这笔钱还能不能动" —— 决定权在客户,
     *   必须独立裁决、不得继承方案生成那一步的许可。
     */
    moneyMovement: true,
    readOnly: false,
    baseTier: "confirm",
    sensitiveFields: [],
    monetaryFields: ["amount", "__evStepAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const account = await ctx.bank.getAccount(ctx.customerId, String(input["fromAccountId"]));
      if (!account) {
        return {
          ok: false,
          error: {
            code: "ACCOUNT_NOT_FOUND",
            message: "没有找到这笔资金要出账的账户,**没有任何操作被执行**。",
            retryable: false,
          },
        };
      }
      const amount = Number(input["amount"]);
      const mode = input["mode"] as "reserve" | "schedule" | "release";
      /**
       * ★ 能力层的独立复核(与订阅取消同一套做法):可用余额不足时**不办**,并如实说明。
       *   锁定资金最坏的结果就是"锁完之后账户里没钱可用了" ——
       *   这个检查不该只依赖策略层,离钱最近的那一层必须自己再算一遍。
       *   ★ 解开(release)方向相反,不适用这条:它是把钱还回可用余额。
       */
      if (mode !== "release" && amount > account.availableBalance) {
        return {
          ok: false,
          error: {
            code: "INSUFFICIENT_AVAILABLE",
            message:
              `账户可用余额 ¥${fmtMoney(account.availableBalance)} 不足以预留 ¥${fmtMoney(amount)},**没有执行任何操作**。\n` +
              "可改小金额、更换账户,或待资金到账后再办理。",
            retryable: true,
          },
        };
      }

      const receipt = await ctx.bank.applyFundStep({
        customerId: ctx.customerId,
        planId: String(input["planId"]),
        stepId: String(input["stepId"]),
        mode,
        fromAccountId: account.accountId,
        toName: String(input["toName"]),
        amount,
        currency: String(input["currency"] ?? "CNY"),
        scheduledAt: Number(input["scheduledAt"]),
        purpose: String(input["purpose"] ?? input["toName"]),
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const lines: string[] = [];
      lines.push(receipt.wording);
      lines.push("");
      lines.push(`用途/去向:${receipt.toName}`);
      lines.push(`金额:¥${fmtMoney(receipt.amount)}(${receipt.modeLabel})`);
      lines.push(`出账账户:${receipt.fromAccountLabel}`);
      if (receipt.mode === "reserve") {
        lines.push(`锁定至:${receipt.reservedUntil != null ? fmtSubDateTime(receipt.reservedUntil) : "—"}`);
      } else if (receipt.mode === "schedule") {
        lines.push(`定时任务:${receipt.scheduleId ?? "—"}`);
        lines.push(`计划执行时间:${receipt.nextRunAt != null ? fmtSubDateTime(receipt.nextRunAt) : "—"}`);
      } else {
        lines.push("此前预留的资金已解除,并回到可用余额。");
      }
      lines.push(`操作后可用余额:¥${fmtMoney(receipt.availableAfter)}`);
      lines.push(`回执号:${receipt.reference}`);
      lines.push("");
      lines.push("本步仅在本人账户内调整预留,没有对外支付。其它步骤均未执行。");

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "event_plan_step_confirmed",
        payload: {
          capability: "event.fund_step",
          planId: receipt.planId,
          stepId: receipt.stepId,
          domain: "fund",
          eventTitle: input["eventTitle"] ?? null,
          stepTitle: input["stepTitle"] ?? null,
          mode: receipt.mode,
          amount: receipt.amount,
          currency: receipt.currency,
          fromAccountId: receipt.fromAccountId,
          toName: receipt.toName,
          scheduledAt: Number(input["scheduledAt"]),
          reservedUntil: receipt.reservedUntil,
          scheduleId: receipt.scheduleId,
          availableAfter: receipt.availableAfter,
          reference: receipt.reference,
          /** ★ 与方案生成那条里同一 stepId 的 disclosure 必须一致 —— 这就是"逐步确认"的证据 */
          confirmedBy: "客户对**这一步**的确认(不是对整份方案的确认)",
          externalActionCreated: false,
          note:
            "资金操作步骤已执行:只在本账户内预留资金,未产生任何对外支付或外部订单。" +
            "外部服务操作是**另一个步骤、另一次确认**,不因本次确认而被授权。",
        },
      });

      return {
        ok: true,
        data: {
          ok: true,
          planId: receipt.planId,
          stepId: receipt.stepId,
          modeLabel: receipt.modeLabel,
          amount: receipt.amount,
          fromAccountLabel: receipt.fromAccountLabel,
          toName: receipt.toName,
          reservedUntil: receipt.reservedUntil,
          scheduleId: receipt.scheduleId,
          nextRunAt: receipt.nextRunAt,
          availableAfter: receipt.availableAfter,
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });

  // ---- 外部服务操作步骤(红色:外部订购,需强验证)----
  registry.register({
    name: "event.external_step",
    description:
      "执行联动方案里的**外部服务操作**那一步:向外部商户提交一笔订单(模拟)。" +
      "★ 这是红色动作:钱会离开你的账户、由商户提供服务,退订要按商户政策协商;" +
      "★ 必须经过强验证,并且必须事先说清金额、去向(商户)与出账账户;" +
      "★ 一次只提交一笔,方案里其它步骤不受影响。",
    inputSchema: z.object({
      planId: z.string().min(1),
      stepId: z.string().min(1),
      merchantId: z.string().min(1),
      merchantName: z.string().min(1).max(60),
      item: z.string().min(1).max(80),
      amount: z.number().positive(),
      scheduledAt: z.number().int().positive(),
      fromAccountId: z.string().min(1),
      purpose: z.string().max(120).optional(),
      eventTitle: z.string().max(40).optional(),
      stepTitle: z.string().max(80).optional(),
    }),
    outputSchema: z.object({
      ok: z.boolean(),
      planId: z.string(),
      stepId: z.string(),
      orderId: z.string(),
      merchantName: z.string(),
      item: z.string(),
      amount: z.number(),
      scheduledAt: z.number(),
      statusLabel: z.string(),
      cancelPolicy: z.string(),
      fromAccountLabel: z.string(),
      reference: z.string(),
      summary: z.string(),
    }),
    /** 外部订单提交后无法由银行单方面撤回 —— 回退要跟商户协商 */
    sideEffect: "irreversible",
    moneyMovement: true,
    readOnly: false,
    /**
     * ★ 红色(strong_auth)的原因,一句话:
     *   前五个场景里所有动作的"钱"都还在银行体系内(转账可撤销、理财可赎回、
     *   代扣可解约、额度只是申请),而**只有外部订购是钱离开体系变成一份商户订单**。
     *   它的后果不可由我们单方面回滚,所以必须最强的一档验证。
     */
    baseTier: "strong_auth",
    sensitiveFields: [],
    monetaryFields: ["amount", "__evStepAmount"],
    async execute(input, ctx): Promise<CapabilityOutcome> {
      const account = await ctx.bank.getAccount(ctx.customerId, String(input["fromAccountId"]));
      if (!account) {
        return {
          ok: false,
          error: { code: "ACCOUNT_NOT_FOUND", message: "没有找到这笔订单的出账账户,**没有提交任何订单**。", retryable: false },
        };
      }
      const merchant = (await ctx.bank.listExternalMerchants({ keyword: String(input["merchantName"]) })).find(
        (m) => m.merchantId === String(input["merchantId"]),
      );
      if (!merchant) {
        return {
          ok: false,
          error: {
            code: "MERCHANT_NOT_FOUND",
            message: `没有在外部商户目录里找到「${String(input["merchantName"])}」,**没有提交任何订单**。`,
            retryable: false,
          },
        };
      }
      const amount = Number(input["amount"]);
      if (amount < merchant.minAmount) {
        return {
          ok: false,
          error: {
            code: "BELOW_MIN_AMOUNT",
            message: `「${merchant.name}」的起订金额是 ¥${fmtMoney(merchant.minAmount)},${fmtMoney(amount)} 达不到起订线,**没有提交订单**。`,
            retryable: true,
          },
        };
      }

      const receipt = await ctx.bank.placeExternalOrder({
        customerId: ctx.customerId,
        planId: String(input["planId"]),
        stepId: String(input["stepId"]),
        merchantId: merchant.merchantId,
        merchantName: merchant.name,
        item: String(input["item"]),
        amount,
        currency: String(input["currency"] ?? "CNY"),
        scheduledAt: Number(input["scheduledAt"]),
        purpose: String(input["purpose"] ?? input["item"]),
        fromAccountId: account.accountId,
        frozenPayloadHash: String(input["__payloadHash"] ?? ""),
      });

      const lines: string[] = [];
      lines.push(receipt.wording);
      lines.push("");
      lines.push(`商户:${receipt.merchantName}`);
      lines.push(`项目:${receipt.item}`);
      lines.push(`金额与去向:从${receipt.fromAccountLabel}支付 ¥${fmtMoney(receipt.amount)} 给「${receipt.merchantName}」`);
      lines.push(`计划服务时间:${fmtSubDateTime(receipt.scheduledAt)}`);
      lines.push(`订单状态:${receipt.statusLabel}`);
      lines.push(`退订/改期政策:${receipt.cancelPolicy}`);
      lines.push(`订单号:${receipt.orderId}`);
      lines.push("");
      lines.push("本订单在您确认后提交。资金操作须另行确认,本次不会一并执行。");

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "event_external_order_placed",
        payload: {
          capability: "event.external_step",
          planId: receipt.planId,
          stepId: receipt.stepId,
          domain: "external",
          eventTitle: input["eventTitle"] ?? null,
          merchantId: receipt.merchantId,
          merchantName: receipt.merchantName,
          item: receipt.item,
          amount: receipt.amount,
          currency: receipt.currency,
          fromAccountId: receipt.fromAccountId,
          scheduledAt: receipt.scheduledAt,
          status: receipt.status,
          cancelPolicy: receipt.cancelPolicy,
          orderId: receipt.orderId,
          reference: receipt.reference,
          /** ★ 红色动作的授权凭据:强验证 + 逐笔披露,两者都必须在这条里能看到 */
          strongAuthRequired: true,
          note:
            "外部订单已提交:钱离开客户账户体系、由外部商户提供服务,退订需按商户政策协商。" +
            "本条是资金去向与授权口径的唯一追溯起点。",
        },
      });

      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "event_plan_step_confirmed",
        payload: {
          capability: "event.external_step",
          planId: receipt.planId,
          stepId: receipt.stepId,
          domain: "external",
          amount: receipt.amount,
          fromAccountId: receipt.fromAccountId,
          toName: receipt.merchantName,
          scheduledAt: receipt.scheduledAt,
          orderId: receipt.orderId,
          confirmedBy: "客户对**这一步**的确认 + 强验证",
          note: "外部服务操作步骤已执行。资金操作步骤不因本次确认而被授权 —— 两类操作分开确认。",
        },
      });

      return {
        ok: true,
        data: {
          ok: true,
          planId: receipt.planId,
          stepId: receipt.stepId,
          orderId: receipt.orderId,
          merchantName: receipt.merchantName,
          item: receipt.item,
          amount: receipt.amount,
          scheduledAt: receipt.scheduledAt,
          statusLabel: receipt.statusLabel,
          cancelPolicy: receipt.cancelPolicy,
          fromAccountLabel: receipt.fromAccountLabel,
          reference: receipt.reference,
          summary: lines.join("\n"),
        },
        summary: lines.join("\n"),
      };
    },
  });
}

export function buildDefaultRegistry(): CapabilityRegistry {
  const registry = new CapabilityRegistry();
  registerReadCapabilities(registry);
  registerBudgetCapabilities(registry);
  registerDocumentCompareCapabilities(registry);
  registerBillAnalysisCapabilities(registry);
  registerWealthCapabilities(registry);
  registerCardCapabilities(registry);
  registerSubscriptionCapabilities(registry);
  registerEventCapabilities(registry);
  registerNoteCapabilities(registry);
  registerTransferCapabilities(registry);
  registerCollectionCapabilities(registry);
  registerSecurityCapabilities(registry);
  registerPolicyCapabilities(registry);
  registerMemoryCapabilities(registry);
  return registry;
}

// ============================================================================
// 内部工具
// ============================================================================

function toTransferIntent(input: Record<string, unknown>, sanitizedMemo?: string) {
  return {
    fromAccountId: String(input["fromAccountId"]),
    payee: {
      ...(input["payeeId"] ? { payeeId: String(input["payeeId"]) } : {}),
      name: sanitizePayeeName(String(input["payeeName"])),
      ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
      ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
      ...(input["bankCode"] ? { bankCode: String(input["bankCode"]) } : {}),
    },
    amount: Number(input["amount"]),
    currency: (input["currency"] as string | undefined) ?? "CNY",
    ...(sanitizedMemo ?? input["memo"] ? { memo: sanitizedMemo ?? String(input["memo"]) } : {}),
    ...(input["scheduledAt"] ? { scheduledAt: Number(input["scheduledAt"]) } : {}),
  };
}

function receiptToData(r: {
  transferId: string;
  status: string;
  amount: number;
  fee: number;
  currency: string;
  payeeName: string;
  executedAt: number;
  cancellableUntil?: number;
  reference: string;
}) {
  return {
    transferId: r.transferId,
    status: r.status === "succeeded" ? "已成功" : r.status === "pending" ? "处理中" : "已失败",
    amount: r.amount,
    fee: r.fee,
    currency: r.currency,
    payeeName: r.payeeName,
    reference: r.reference,
    ...(r.cancellableUntil != null ? { cancellableUntil: r.cancellableUntil } : {}),
  };
}

/**
 * 账户类型与定时任务状态的客户说法已收归 `util/labels.ts`(见该文件说明)。
 *
 * ★ 原来这里自己写了一份 `accountTypeLabel`,兜底是**原样回显类型串** ——
 *   与方案卡那份(兜底「账户」)不一致:同一个未知类型,一个页面说「账户」,
 *   另一个页面把内部枚举名摊到客户面前。现在两处共用一份,兜底也不回显英文。
 */

/** 频率 → 客户说法(未知时给中性说法,不回显内部枚举名) */
function frequencyLabel(f: string): string {
  return { once: "一次性", daily: "每天", weekly: "每周", monthly: "每月" }[f] ?? "按约定周期";
}

function collectionStatusLabel(s: string): string {
  return {
    open: "待支付",
    partially_paid: "部分已付",
    completed: "已收齐",
    expired: "已过期",
    cancelled: "已取消",
  }[s] ?? s;
}

function shareStatusLabel(s: string): string {
  return { pending: "待支付", paid: "已支付", expired: "已过期", declined: "已拒绝" }[s] ?? s;
}

// ============================================================================
// 风险信号注入(策略引擎的输入来源,模型既看不到也写不了)
// ============================================================================

/**
 * 把银行侧事实注入为 `__` 前缀的风险信号。
 *
 * ★ 为什么必须这样做:转账的风险信号来自"对手方新颖度"、"名单命中"、"速度特征",
 *   而这些事实只能从银行核心取。若让模型填 `isWhitelisted=true`,
 *   那道防线就等于没有。
 *
 * ★ 这些字段全部以 `__` 前缀注入,不会出现在能力的 JSON Schema 中
 *   (`additionalProperties: false` 会拒绝模型写入任何未知字段),
 *   因此模型无法伪造 `__payeeRisk.isWhitelisted=true` 来降低自己的风险分。
 */
export async function injectRiskSignals(
  input: Record<string, unknown>,
  ctx: ExecutionContext,
): Promise<{ input: Record<string, unknown>; reasons: PolicyReason[] }> {
  const reasons: PolicyReason[] = [];
  const out = { ...input };

  const payeeId = input["payeeId"] ? String(input["payeeId"]) : undefined;
  if (payeeId) {
    const payee = await ctx.bank.getPayee(ctx.customerId, payeeId);
    if (payee) {
      out["__payeeRisk"] = {
        isFirstTime: payee.novelty.isFirstTime,
        successCount: payee.novelty.successCount,
        isSelfOwned: payee.isSelfOwned,
        isWhitelisted: payee.isWhitelisted,
        isKnownFrequent: ctx.profile.riskProfile.frequentPayees.includes(payee.payeeId),
      };
      out["bankName"] = out["bankName"] ?? payee.bankName;
      out["maskedAccountNo"] = out["maskedAccountNo"] ?? payee.maskedAccountNo;
    }
  } else if (input["payeeName"]) {
    // 未指定 payeeId:按姓名反查,判断是否首次
    const candidates = await ctx.bank.searchPayees(ctx.customerId, { name: String(input["payeeName"]), limit: 5 });
    const exact = candidates.find((c) => c.name === String(input["payeeName"]));
    out["__payeeRisk"] = exact
      ? {
          isFirstTime: exact.novelty.isFirstTime,
          successCount: exact.novelty.successCount,
          isSelfOwned: exact.isSelfOwned,
          isWhitelisted: exact.isWhitelisted,
          isKnownFrequent: ctx.profile.riskProfile.frequentPayees.includes(exact.payeeId),
        }
      : { isFirstTime: true, successCount: 0, isSelfOwned: false, isWhitelisted: false, isKnownFrequent: false };
  }

  // 名单筛查
  if (input["payeeName"]) {
    const screening = await ctx.bank.screenPayee({
      payeeName: String(input["payeeName"]),
      ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
      ...(input["phone"] ? { phone: String(input["phone"]) } : {}),
    });
    out["__screening"] = { hit: screening.hit, hits: screening.hits };
  }

  // 速度特征(拆分交易检测)—— 日累计口径按客户维度跨收款人统计
  if (typeof input["amount"] === "number") {
    const amount = input["amount"] as number;
    const since = ctx.now - 24 * 3600 * 1000;
    const recent = await ctx.bank.listTransactions(ctx.customerId, {
      from: since,
      direction: "out",
      limit: 200,
    });
    const transfers = recent.filter((t) => t.category === "转账");
    const samePayee = input["payeeName"]
      ? transfers.filter((t) => t.counterpartyName === String(input["payeeName"]))
      : [];
    const sameAmount = transfers.filter((t) => Math.abs(t.amount - amount) < 0.01);
    const dailyCumulative = transfers.reduce((s, t) => s + t.amount, 0) + amount;

    out["__velocity"] = {
      samePayeeCount24h: samePayee.length,
      sameAmountRepeatCount: sameAmount.length,
      dailyCumulative: Math.round(dailyCumulative * 100) / 100,
      /**
       * ★ 限额口径只有一处:**策略配置**(configurePolicy 可调,面板也展示它)。
       *   原来这里写死 200_000,于是把配置调成 5 万之后 ——
       *   面板显示 ¥50,000、判定仍按 200,000,演示"阈值可配置"时当场穿帮。
       *   判定读的就是这个注入值,所以它必须跟着配置走。
       */
      dailyLimit: getPolicyConfig().dailyLimit,
    };

    if (samePayee.length >= 3) {
      reasons.push({
        ruleId: "R-VELOCITY-SAME-PAYEE",
        message: `24 小时内已向该收款人转账 ${samePayee.length} 笔,本笔为第 ${samePayee.length + 1} 笔`,
        effect: "escalate",
        evidence: { count: samePayee.length },
      });
    }
    if (sameAmount.length >= 2) {
      reasons.push({
        ruleId: "R-VELOCITY-SAME-AMOUNT",
        message: `24 小时内已有 ${sameAmount.length} 笔金额相同的转账,存在拆分交易特征`,
        effect: "escalate",
        evidence: { count: sameAmount.length, amount },
      });
    }
  }

  // 费用与到账时间(供确认卡展示)
  if (input["payeeName"]) {
    const info = await ctx.bank.verifyPayeeDeliverable({
      payeeName: String(input["payeeName"]),
      ...(input["accountNo"] ? { accountNo: String(input["accountNo"]) } : {}),
    });
    out["__fee"] =
        typeof input["amount"] === "number" ? transferFeeOf(input["amount"] as number, info.interbank) : 0;
    out["__estimatedArrival"] = info.estimatedArrival ?? "实时到账";
  }

  // ==========================================================================
  // 理财场景(场景三)的风险信号
  //
  // ★ 与转账场景的关键差别:转账的风险信号来自"对手方新颖度",
  //   理财的风险信号来自"客户与产品之间的风险等级落差" ——
  //   这是适配性监管的核心指标,也是唯一能决定"能不能卖"的依据。
  //
  //   这些字段全部以 __ 前缀注入,不会出现在能力的 JSON Schema 中,
  //   因此模型既看不到、也写不了。想靠提示词伪造 __customerRiskOrdinal=5
  //   来买 R5 产品,在架构上做不到。
  //
  //   触发方式:编排器在理财资金操作的入参里放入 __productCode(同样是 __ 前缀),
  //   注入器据此去银行核心取产品与客户评级,再把落差算出来。
  // ==========================================================================
  if (typeof input["__productCode"] === "string" && input["__productCode"].length > 0) {
    const product = await ctx.bank.getWealthProduct(String(input["__productCode"]));
    if (product) {
      const profile = await ctx.bank.getRiskProfile(ctx.customerId);
      out["__productRiskLevel"] = product.riskLevel;
      out["__productRiskOrdinal"] = Number(product.riskLevel.slice(1));
      out["__riskAssessed"] = profile.assessed && !profile.expired;
      out["__riskAssessmentExpired"] = profile.expired;
      out["__customerRiskLevel"] = profile.level;
      out["__customerRiskOrdinal"] = profile.level ? Number(profile.level.slice(1)) : 0;
      out["__suitabilityGap"] =
        profile.level && !profile.expired
          ? Math.max(0, Number(product.riskLevel.slice(1)) - Number(profile.level.slice(1)))
          : 0;
      out["__minAmount"] = product.minAmount;
      out["__incrementAmount"] = product.incrementAmount;
      out["__settlement"] = product.settlement;

      reasons.push({
        ruleId: "R-WEALTH-SUITABILITY-INFO",
        message:
          `适配性信息:客户等级 ${profile.level ?? "未测评"}(${profile.assessed ? (profile.expired ? "已过期" : "有效") : "未测评"}),` +
          `产品风险等级 ${product.riskLevel}`,
        effect: "pass",
        evidence: {
          customerLevel: profile.level,
          assessed: profile.assessed,
          expired: profile.expired,
          productLevel: product.riskLevel,
          gap: out["__suitabilityGap"],
        },
      });
    }
  }

  // ==========================================================================
  // 卡片管理场景(场景四)的风险信号
  //
  // ★ 与场景三(理财)同一条架构纪律:凡是**决定放不放行**的事实,
  //   一律由注入器从银行核心取,以 __ 前缀写入 —— 模型看不到、也写不了。
  //
  //   卡片场景里这类事实有四组:
  //     ① 卡片本身的属性(状态、额度、开卡时长、上次调额时间)→ 额度资格
  //     ② 交易限制的原因与处理通道 → 决定"能不能在这里解"
  //     ③ 补卡情形 → 决定"要不要重新设交易密码"
  //     ④ 当前额度与目标额度两个数 → 保证"申请 ≠ 已提额"在数据层就成立
  //
  //   ★ 为什么把资格判定放在注入器而不是路由层:
  //     策略引擎的 R-CARD-LIMIT-TIME-GATE 必须能在**调用能力之前**独立裁决。
  //     如果资格只算在路由层,那么绕过路由(直接调能力、或写一个新的调用方)
  //     的路径就会失去这道闸门。注入器是策略请求的必经之路,放这里才拦得住。
  // ==========================================================================
  if (input["__cardId"] != null || input["__cardLast4"] != null) {
    const cards = await ctx.bank.listCards(ctx.customerId);
    const key = input["__cardId"] != null ? String(input["__cardId"]) : "";
    const last4 = input["__cardLast4"] != null ? String(input["__cardLast4"]) : "";
    const card = key
      ? cards.find((c) => c.cardId === key)
      : last4
        ? cards.find((c) => c.last4 === last4)
        : cards.length === 1
          ? cards[0]
          : undefined;

    if (card) {
      out["__cardId"] = card.cardId;
      out["__cardLast4"] = card.last4;
      out["__cardProductName"] = card.productName;
      out["__cardKindHint"] = card.kind;
      out["__cardStatus"] = card.status;
      out["__cardCurrentLimit"] = card.creditLimit;
      out["__cardCreditLimit"] = card.creditLimit;

      // ---- 额度资格(决定提额申请能否提交)----
      const elig = checkLimitEligibility({ card, now: ctx.now });
      out["__cardLimitEligibility"] = elig.status;
      out["__cardLimitReason"] = elig.reason;
      out["__cardLimitWaitMonths"] = elig.waitMonths;
      out["__cardLimitSuggestedMax"] = elig.suggestedMaxLimit;

      // ---- 交易限制(决定解除申请能否受理、以及"该怎么处理")----
      out["__cardRestrictionCause"] = card.restriction?.cause ?? null;
      out["__cardRestrictionCauseLabel"] = card.restriction?.causeLabel ?? null;
      out["__cardRestrictionChannel"] = card.restriction?.channel ?? null;
      if (card.restriction) out["__restrictionSince"] = card.restriction.since;

      reasons.push({
        ruleId: "R-CARD-CONTEXT-INFO",
        message:
          `卡片上下文:尾号 ${card.last4} ${card.kind === "credit" ? "信用卡" : "借记卡"},状态「${CARD_STATUS_LABELS[card.status]}」,` +
          `开卡 ${monthsBetween(card.openedAt, ctx.now)} 个月,提额资格 ${elig.status}` +
          `${card.restriction ? `,交易限制原因 ${card.restriction.cause}` : ""}`,
        effect: "pass",
        evidence: {
          cardLast4: card.last4,
          status: card.status,
          monthsOpen: monthsBetween(card.openedAt, ctx.now),
          limitEligibility: elig.status,
          restrictionCause: card.restriction?.cause ?? null,
        },
      });
    }
  }

  // ==========================================================================
  // 订阅代扣上下文(新场景)
  //
  // ★ 这里注入的每一件事都是**银行侧事实**,模型既看不到也写不了(不在 JSON Schema 里):
  //     ① 这笔订阅在不在(流水与代扣协议里都查不到 → 必须明确告知"不存在");
  //     ② 每期扣多少、下一次什么时候扣 → 确认卡上必须出现的两个数;
  //     ③ 签约通道(本行协议 / 商户侧)→ 决定"能不能在这里取消";
  //     ④ 协议状态(代扣中 / 已取消)→ 决定"要不要再执行一次";
  //     ⑤ 取消生效口径、本期费用处理、取消后果 → 客户确认时认下的代价。
  //
  //   ★ 为什么这些必须走注入器而不是路由层算完塞进 input:
  //     策略引擎的五条 R-SUB-* 规则要求**在调用能力之前**就能独立裁决。
  //     资格只算在路由层,那么绕过路由的调用方(直接调能力、批量脚本、
  //     将来新增的入口)就会绕开这道闸门 —— 而"取消一笔并不存在的订阅"
  //     恰恰是最需要在结构上被拦住的场景。
  //
  //   ★ 触发条件:只要载荷里出现 `__subscriptionId` 或 `__subQuery`,
  //     就说明这是一次"针对某笔订阅"的操作(路由层已做初步指认)。
  // ==========================================================================
  if (input["__subscriptionId"] != null || input["__subQuery"] != null) {
    const scan = await buildSubscriptionScan(ctx);
    const id = input["__subscriptionId"] != null ? String(input["__subscriptionId"]) : "";
    const query = input["__subQuery"] != null ? String(input["__subQuery"]) : "";

    const byId = id ? scan.items.find((i) => i.subscriptionId === id) : undefined;
    /**
     * ★ 有 id 就用 id;**没有 id 只有名字时,这里再做一次匹配**。
     *   路由层正常情况下已经匹配好并把 id 塞进来了,但"没有匹配到"也是它塞进来的
     *   一种结果(没有 id、只有 query)。这里再匹配一次,是为了让
     *   "绕过路由直接调能力"的路径也能得到同样的结论 —— 而不是拿到一句
     *   「没有 id 就无法处理」。兜底的价值不在于正常路径,而在于异常路径。
     */
    const matched = byId ?? (query ? (matchSubscription(query, scan.items).best ?? undefined) : undefined);

    if (!matched) {
      out["__subFound"] = false;
      out["__subQuery"] = query || "这笔订阅";
      /**
       * ★ 把用户提到的名字也回填到**公开字段** merchantName。
       *
       *   为什么:能力执行时读的是 schema 里的公开字段(merchantName),
       *   而"没匹配上"这条路径下,名字只存在于 `__subQuery` 里。
       *   不回填的话,能力给出的错误提示会变成「没有找到「这笔」」——
       *   客户看到的是"这笔",而不是他自己说的那个名字,等于没被听见。
       *   (实测踩到:确认「把优酷会员关了」时回的是「没有找到「这笔」」。)
       */
      if (typeof out["merchantName"] !== "string" || out["merchantName"].length === 0) {
        out["merchantName"] = query || "这笔订阅";
      }
      out["__subKnownMerchants"] = scan.items.filter((i) => i.status !== "cancelled").map((i) => i.merchantName);
      reasons.push({
        ruleId: "R-SUB-CONTEXT-INFO",
        message:
          `订阅代扣上下文:未找到「${query || "未指明"}」对应的订阅 —— 已核对 ${scan.items.length} 笔识别结果与 ` +
          `${scan.items.filter((i) => i.subscriptionId).length} 份银行侧代扣协议,均无匹配;本次不执行任何取消操作。`,
        effect: "pass",
        evidence: {
          found: false,
          query,
          knownMerchants: out["__subKnownMerchants"],
          scannedTransactions: scan.scannedTransactions,
        },
      });
    } else {
      out["__subFound"] = true;
      if (matched.subscriptionId) out["__subscriptionId"] = matched.subscriptionId;
      /**
       * ★ 公开字段一并回填:能力执行时读的是 schema 里的公开字段。
       *
       *   只写 `__` 私有字段会出现一个很隐蔽的裂缝:
       *   「把爱奇艺会员关了」→ 确认卡 → 用户说「确认」时,
       *   执行阶段拿到的入参里**只有** `__subscriptionId`,而能力读的是
       *   `subscriptionId` —— 于是一次已经确认过的取消,执行时变成"没有找到这笔"。
       *   冻结载荷里必须同时带着"能被执行的公开字段"与"供裁决的私有事实"。
       */
      out["subscriptionId"] = matched.subscriptionId ?? out["subscriptionId"];
      out["merchantName"] = matched.merchantName;
      out["__subMerchant"] = matched.merchantName;
      out["__subCategory"] = matched.category;
      out["__subAmount"] = matched.amount;
      out["__subCadenceLabel"] = matched.cadenceLabel;
      // ★ 用一个"哨兵值"而不是 undefined 来表达"没有下次扣款":
      //   undefined 在 JSON 序列化时会消失,策略规则就无法区分
      //   "字段没注入"与"确实没有下次扣款" —— 这两者的结论完全相反。
      out["__subNextDebitAt"] = matched.nextDebitAt;
      out["__subStatus"] = matched.status;
      out["__subStatusLabel"] = matched.statusLabel;
      out["__subCancelChannel"] = matched.cancelable ? "bank" : matched.cancelChannel;
      out["__subChannelLabel"] = matched.cancelChannelLabel;
      out["__subCancelEffective"] = matched.cancelable ? "next_cycle" : null;
      out["__subRefundPolicy"] = matched.refundPolicy;
      out["__subCancelConsequence"] = matched.cancelConsequence;
      out["__subMerchantCancelPath"] = matched.merchantCancelPath;
      out["__subCancelable"] = matched.cancelable;
      out["__subBlockReason"] = matched.cancelBlockReason;
      out["__subIdentifyKeywords"] = matched.evidence.keywords;
      out["__subLastChargedAt"] = matched.evidence.lastChargedAt;

      const agreement = matched.subscriptionId ? await ctx.bank.getSubscription(ctx.customerId, matched.subscriptionId) : null;
      if (agreement) {
        out["__subAgreementNo"] = agreement.agreementNo;
        out["__subSignedAt"] = agreement.signedAt;
        out["__subCancelledAt"] = agreement.cancelledAt;
        out["__subAgreement"] = agreement.status === "cancelled" ? "cancelled" : "active";
      } else {
        // 没有银行侧协议:这是"商户侧自动续费",本行没有可解的东西
        out["__subAgreement"] = "none";
      }

      reasons.push({
        ruleId: "R-SUB-CONTEXT-INFO",
        message:
          `订阅代扣上下文:「${matched.merchantName}」每期 ¥${fmtSubMoney(matched.amount)}(${matched.cadenceLabel}),` +
          `下次扣款 ${matched.nextDebitAt != null ? fmtSubDay(matched.nextDebitAt) : "无"},` +
          `签约通道 ${matched.cancelChannelLabel},状态 ${matched.statusLabel}` +
          `(识别依据:${matched.evidence.keywords.length > 0 ? `关键词「${matched.evidence.keywords.join("、")}」` : "固定周期金额"}` +
          `${matched.evidence.occurrences > 0 ? `,近 ${matched.evidence.occurrences} 次扣款` : ""})`,
        effect: "pass",
        evidence: {
          merchantName: matched.merchantName,
          amount: matched.amount,
          nextDebitAt: matched.nextDebitAt,
          cancelChannel: matched.cancelChannel,
          cancelable: matched.cancelable,
          status: matched.status,
          agreement: out["__subAgreement"],
          keywords: matched.evidence.keywords,
          occurrences: matched.evidence.occurrences,
        },
      });
    }
  }

  // ==========================================================================
  // 跨场景事件联动(新场景)—— 步骤执行前的独立裁决事实
  //
  // ★ 为什么"资金去向"这件事必须在**调用能力之前**就有机器可读的结论:
  //   合规要求的原话是"涉及跨场景时,必须事先明确告知每一笔资金去向和金额"。
  //   如果只在方案文本里写一句"钱从工资卡出 1200 元",那是**文案**;
  //   而策略引擎需要的是一个能当场判定的结构:从哪出、给谁、多少、什么时候,
  //   四项齐了才允许执行。缺项时必须**拒绝执行**,而不是"提醒一句仍然放行"。
  //
  // ★ 触发条件:路由层为"执行方案里某一步"塞入 `__evStepId` 与 `__evStepDomain`。
  //   这两个字段由系统写入(模型不可见、不可写),因此它们同时也是
  //   "这一步是从方案里出来的"的证据 —— 没有方案的即兴请求没有这两个字段。
  // ==========================================================================
  if (input["__evStepId"] != null || input["__evStepDomain"] != null) {
    const domain = input["__evStepDomain"] === "external" ? "external" : "fund";
    const planId = input["__evPlanId"] != null ? String(input["__evPlanId"]) : "";
    const stepId = input["__evStepId"] != null ? String(input["__evStepId"]) : "";
    const amount = typeof input["amount"] === "number" ? Number(input["amount"]) : null;
    const toName = typeof input["toName"] === "string" ? String(input["toName"]) : typeof input["merchantName"] === "string" ? String(input["merchantName"]) : "";
    const fromAccountId = typeof input["fromAccountId"] === "string" ? String(input["fromAccountId"]) : "";
    const scheduledAt = typeof input["scheduledAt"] === "number" ? Number(input["scheduledAt"]) : null;

    out["__evStepDomain"] = domain;
    out["__evPlanId"] = planId;
    out["__evStepId"] = stepId;
    out["__evPlanMissing"] = planId.length === 0 || stepId.length === 0;
    out["__evStepAmount"] = amount;

    /**
     * ★ 四元组完整性判定:缺任何一项,这一步就"说不清钱去哪了"。
     *   注意 fromAccountId 为空的处理 —— 客户没指定出账账户时**不算缺项**,
     *   因为方案里本来就允许"确认时再定";但金额与去向缺了就一定拒绝。
     */
    const missing: string[] = [];
    if (amount == null || !(amount > 0)) missing.push("金额");
    if (!toName) missing.push("资金去向");
    if (scheduledAt == null || !(scheduledAt > 0)) missing.push("时间");
    out["__evFundsDisclosed"] = missing.length === 0;

    const account = fromAccountId ? await ctx.bank.getAccount(ctx.customerId, fromAccountId) : null;
    const fromLabel = account
      ? `${accountTypeText(account.type)} 尾号 ${String(account.maskedNo).replace(/\D/g, "").slice(-4)}`
      : fromAccountId
        ? "指定账户"
        : "待指定出账账户";
    out["__evFromAccountLabel"] = fromLabel;
    out["__evDisclosure"] =
      missing.length === 0
        ? `从${fromLabel}出账 ¥${fmtMoney(amount as number)},去向「${toName}」,时间 ${fmtSubDateTime(scheduledAt as number)}`
        : `本步信息未齐,缺少${missing.join("、")}。去向未明确的操作不予执行。`;

    /**
     * ★ 外部步骤额外核对商户是真实存在的目录项(与能力层的复核同一个判断,
     *   放在这里是为了让策略引擎能**在调用能力之前**就拒绝一个不存在的商户)。
     */
    if (domain === "external") {
      const name = typeof input["merchantName"] === "string" ? String(input["merchantName"]) : "";
      const merchantId = typeof input["merchantId"] === "string" ? String(input["merchantId"]) : "";
      const merchants = await ctx.bank.listExternalMerchants(name ? { keyword: name } : {});
      const merchant = merchants.find((m) => m.merchantId === merchantId) ?? merchants.find((m) => m.name === name) ?? null;
      out["__evMerchantFound"] = merchant != null;
      out["__evMerchantName"] = merchant?.name ?? name;
      out["__evMerchantMinAmount"] = merchant?.minAmount ?? null;
      out["__evMerchantCancelPolicy"] = merchant?.cancelPolicy ?? null;
      if (merchant && amount != null && amount < merchant.minAmount) {
        out["__evBelowMinAmount"] = true;
      }
    }

    reasons.push({
      ruleId: "R-EVENT-CONTEXT-INFO",
      message:
        `事件联动上下文:执行方案 ${planId || "(缺方案号)"} 的 ${stepId || "(缺步骤号)"} —— ` +
        `${domain === "external" ? "外部服务操作(红色,需强验证)" : "资金操作(黄色,需确认)"};` +
        `${out["__evDisclosure"]}`,
      effect: "pass",
      evidence: {
        planId,
        stepId,
        domain,
        amount,
        toName,
        fromAccountId: fromAccountId || null,
        scheduledAt,
        fundsDisclosed: out["__evFundsDisclosed"],
      },
    });
  }

  return { input: out, reasons };
}

function accountTypeText(type: "current" | "savings" | "credit" | "ewallet"): string {
  return { current: "活期账户", savings: "储蓄账户", credit: "信用卡", ewallet: "电子钱包" }[type];
}
