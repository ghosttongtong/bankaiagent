/**
 * `policy.search` —— 制度条款问答(只读)。
 *
 * ★ 这个能力只做三件事:把话交给检索、把命中条款原样引用、把"为什么是这条"讲清楚。
 *   它**不做**业务判断,也**不生成**任何金额:
 *     · 制度里没有客户的余额,所以数字类问题一律不查检索;
 *     · 回答文本由确定性代码拼装(不用模型改写),引用原文。
 *
 * ★ 拒答是**一等公民**,不是失败分支:
 *   答不上来时给一句固定话术 + 引导人工,比"猜一条看起来像的条款"安全得多。
 *   客户会照着条款去办事 —— 猜错的代价由客户承担,这不可接受。
 */

import { z } from "zod";

import type { ExecutionContext } from "../types.ts";
import { detectInjection } from "../security/injection.ts";
import { NUMERIC_REDIRECT_TEXT, POLICY_REFUSAL_TEXT, looksNumericQuestion } from "../retrieval/guard.ts";
import type { CapabilityOutcome, CapabilityRegistry } from "./registry.ts";

/** 检索不可用时的如实回答(不编条款) */
const RETRIEVAL_UNAVAILABLE = "制度检索暂时不可用,我没法给您可靠的条款依据。建议转人工核实。";

export function registerPolicyCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "policy.search",
    description:
      "查询银行制度条款(年费/手续费/到账时效/挂失补卡/风险测评/转账风控/争议处理等规则)。" +
      "只读。命中条款会返回文档版本与生效日期;答不上来会明确拒答并建议转人工。" +
      "★ 金额、余额、额度、收益、持仓这类**客户自己的数字**不要用这个能力,交给对应的查询能力。",
    inputSchema: z.object({
      query: z.string().min(1).describe("用户关于制度/规则的原话"),
      topK: z.number().int().positive().max(5).optional(),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      hits: z.array(
        z.object({
          docId: z.string(),
          title: z.string(),
          version: z.string(),
          clauseId: z.string(),
          clauseTitle: z.string(),
          text: z.string(),
          effectiveFrom: z.string(),
          issuer: z.string(),
          score: z.number(),
        }),
      ),
      confidence: z.number(),
      refusalReason: z.string().nullable(),
      summary: z.string(),
    }),
    sideEffect: "none",
    moneyMovement: false,
    readOnly: true,
    baseTier: "auto",
    sensitiveFields: [],
    monetaryFields: [],
    async execute(input, ctx: ExecutionContext): Promise<CapabilityOutcome> {
      const query = String(input["query"] ?? "").trim();
      const topK = typeof input["topK"] === "number" ? (input["topK"] as number) : 3;

      /**
       * ① 数字类问题:双重生效的第二层(第一层在路由)。
       *    即使被误路由到这里,也绝不拿检索结果去凑金额。
       */
      if (looksNumericQuestion(query)) {
        await auditSearch(ctx, {
          query,
          topK,
          hitDocIds: [],
          clauseIds: [],
          confidence: 0,
          refused: true,
          refusalCode: "numeric",
        });
        return {
          ok: true,
          data: { found: false, hits: [], confidence: 0, refusalReason: NUMERIC_REDIRECT_TEXT, summary: NUMERIC_REDIRECT_TEXT },
          summary: NUMERIC_REDIRECT_TEXT,
        };
      }

      // ② 检索端口未注入:如实说明,不编条款
      if (!ctx.retrieval) {
        return {
          ok: true,
          data: {
            found: false,
            hits: [],
            confidence: 0,
            refusalReason: RETRIEVAL_UNAVAILABLE,
            summary: RETRIEVAL_UNAVAILABLE,
          },
          summary: RETRIEVAL_UNAVAILABLE,
        };
      }

      const result = await ctx.retrieval.searchPolicy(query, topK);

      await auditSearch(ctx, {
        query,
        topK,
        hitDocIds: result.hits.map((h) => h.docId),
        clauseIds: result.hits.map((h) => `${h.docId}#${h.clauseId}`),
        confidence: result.confidence,
        refused: result.refused,
        ...(result.refusalCode ? { refusalCode: result.refusalCode } : {}),
      });

      // ③ 拒答
      if (result.refused || result.hits.length === 0) {
        const text = result.refusalReason ?? POLICY_REFUSAL_TEXT;
        return {
          ok: true,
          data: { found: false, hits: [], confidence: result.confidence, refusalReason: text, summary: text },
          summary: text,
        };
      }

      const best = result.hits[0]!;

      /**
       * ★ 检索文本是**不可信输入**(32 文档 §6)。
       *   语料理论上可能被污染(或将来接入了任意来源),命中内容一律按数据处理:
       *   只作为引用展示,不参与任何指令解释;命中注入特征时如实记录。
       */
      const injection = detectInjection(best.text);
      if (injection.length > 0) {
        await ctx.audit.append({
          ts: ctx.now,
          traceId: ctx.traceId,
          sessionId: ctx.sessionId,
          customerId: ctx.customerId,
          channel: ctx.channel,
          type: "injection_detected",
          payload: {
            source: "retrieval",
            docId: best.docId,
            clauseId: best.clauseId,
            findings: injection.map((f) => ({ id: f.id, severity: f.severity })),
            note: "检索命中的条款文本里出现了注入特征。该片段只作为引用展示,不参与任何指令解释。",
          },
        });
      }

      /**
       * ④ 回答文本:确定性拼装,引用原文。
       *    版本 + 生效日期 + 出据方三样必须同时出现 —— 这是"可追溯"的载体。
       */
      const lines: string[] = [];
      lines.push(`按《${best.title}(${best.version})》第 ${best.clauseId} 条「${best.clauseTitle}」:`);
      lines.push(`「${best.text}」`);
      lines.push("");
      lines.push(
        `生效日期:${best.effectiveFrom} · 出据方:${best.issuer} · 检索置信度 ${result.confidence.toFixed(2)}`,
      );
      if (result.hits.length > 1) {
        const others = result.hits.slice(1).map((h) => `《${h.title}》第 ${h.clauseId} 条`);
        lines.push(`另可参考:${others.join("、")}`);
      }
      const summary = lines.join("\n");

      // ⑤ 登记出处(复用现有出处组件,不在文本里重复)
      ctx.extras?.citations.push({
        id: `rule:${best.docId}#${best.clauseId}`,
        topic: `《${best.title}》第 ${best.clauseId} 条 · ${best.clauseTitle}`,
        source: `《${best.title}》(${best.version})`,
        subject: "制度条款 · 对全部客户生效",
        effective: `生效 ${best.effectiveFrom}`,
        asOf: ctx.now,
        calculation: [`检索置信度 ${result.confidence.toFixed(2)}`, `查询:「${query}」`],
        note: `出据方:${best.issuer};条款原文由系统原样引用,未经模型改写`,
        kind: "rule",
      });

      return {
        ok: true,
        data: {
          found: true,
          hits: result.hits.map((h) => ({
            docId: h.docId,
            title: h.title,
            version: h.version,
            clauseId: h.clauseId,
            clauseTitle: h.clauseTitle,
            text: h.text,
            effectiveFrom: h.effectiveFrom,
            issuer: h.issuer,
            score: h.score,
          })),
          confidence: result.confidence,
          refusalReason: null,
          summary,
        },
        summary,
      };
    },
  });
}

/** 检索审计:一次检索一条,带命中条款与是否拒答(否则事后无法复核"当时凭哪条回答") */
async function auditSearch(
  ctx: ExecutionContext,
  payload: {
    query: string;
    topK: number;
    hitDocIds: string[];
    clauseIds: string[];
    confidence: number;
    refused: boolean;
    refusalCode?: string;
  },
): Promise<void> {
  await ctx.audit.append({
    ts: ctx.now,
    traceId: ctx.traceId,
    sessionId: ctx.sessionId,
    customerId: ctx.customerId,
    channel: ctx.channel,
    type: "policy_searched",
    payload: {
      ...payload,
      note:
        "制度检索入链:客户拿到的依据必须可复核 —— " +
        "查了什么、命中哪几条、置信度多少、是不是拒答,四件事都要留下来。",
    },
  });
}
