/**
 * `memory.search` —— 客户记忆检索(只读)。
 *
 * ★ 它回答的是"**我**之前办过什么、那次对话说了什么",不是"银行怎么规定":
 *   「刚才那笔转账成功了吗」—— 制度里没有这一笔,台账里有。
 *   「我上个月转账为什么失败」—— 同上。
 *
 * ★ 三条纪律:
 *   ① 严格按 ctx.customerId 检索 —— 跨客户命中必须为零(硬断言);
 *   ② 回答由确定性代码拼装:时间 + 记录原文 + 流水号/入口,**不让模型改写数字**;
 *   ③ 检索只给"依据与位置",不给裁决 —— 它不会说"这笔能退",只会说"这笔记的是已转账成功"。
 */

import { z } from "zod";

import type { ExecutionContext } from "../types.ts";
import type { CapabilityOutcome, CapabilityRegistry } from "./registry.ts";

const MEMORY_UNAVAILABLE = "记忆检索暂时不可用,我没法核对您的历史记录。建议在「最近操作」里查看。";
const MEMORY_EMPTY = "我在您的记录里没有找到相关的内容。可以说清楚大概是哪一天、多少钱,或者换个说法。";

const KIND_LABEL: Record<string, string> = {
  ledger: "操作",
  session: "对话",
  note: "记账",
  document: "材料",
};

/** 把时间戳说成人话:今天/昨天/M月D日 + 时分 */
function whenLabel(ts: number, now: number): string {
  const d = new Date(ts);
  const n = new Date(now);
  const hhmm = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  const sameDay = d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate();
  if (sameDay) return `今天 ${hhmm}`;
  const yesterday = new Date(now - 24 * 3600 * 1000);
  const isYesterday =
    d.getFullYear() === yesterday.getFullYear() && d.getMonth() === yesterday.getMonth() && d.getDate() === yesterday.getDate();
  if (isYesterday) return `昨天 ${hhmm}`;
  return `${d.getMonth() + 1}月${d.getDate()}日 ${hhmm}`;
}

export function registerMemoryCapabilities(registry: CapabilityRegistry): void {
  registry.register({
    name: "memory.search",
    description:
      "检索客户**自己的**历史记录:办过的操作(含结果与流水号)、之前的对话、记账批注、提交的材料。" +
      "只读。用于回答「刚才那笔转账成功了吗」「我上个月那笔为什么失败」「我们上次聊了什么」这类问题。" +
      "★ 它不查银行制度(那是 policy.search),也不产出裁决;跨客户严格隔离。",
    inputSchema: z.object({
      query: z.string().min(1),
      topK: z.number().int().positive().max(10).optional(),
    }),
    outputSchema: z.object({
      found: z.boolean(),
      hits: z.array(
        z.object({
          kind: z.enum(["ledger", "session", "note", "document"]),
          ts: z.number(),
          text: z.string(),
          score: z.number(),
          opId: z.string().optional(),
          sessionId: z.string().optional(),
          traceId: z.string().optional(),
        }),
      ),
      confidence: z.number(),
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
      const topK = typeof input["topK"] === "number" ? (input["topK"] as number) : 5;

      if (!ctx.retrieval?.searchMemory) {
        return {
          ok: true,
          data: { found: false, hits: [], confidence: 0, summary: MEMORY_UNAVAILABLE },
          summary: MEMORY_UNAVAILABLE,
        };
      }

      // ★ customerId 只从 ctx 取 —— 不允许从入参传,避免"帮别人查"的入口
      const result = await ctx.retrieval.searchMemory({ customerId: ctx.customerId, query, topK });

      /**
       * ★ 审计:检索过什么、命中哪几类、是否跨会话。
       *   "客户问起往事"本身是敏感事件 —— 谁在什么时候翻过他的记录,要能查。
       */
      await ctx.audit.append({
        ts: ctx.now,
        traceId: ctx.traceId,
        sessionId: ctx.sessionId,
        customerId: ctx.customerId,
        channel: ctx.channel,
        type: "memory_searched",
        payload: {
          query,
          hitKinds: result.hits.map((h) => h.kind),
          opIds: result.hits.map((h) => h.opId).filter((id): id is string => Boolean(id)),
          confidence: result.confidence,
          crossSession: result.hits.some((h) => h.sessionId != null && h.sessionId !== ctx.sessionId),
          note: "客户记忆检索入链:检索范围严格限定为本客户(crossCustomer 命中应为零)。",
        },
      });

      if (result.hits.length === 0) {
        return {
          ok: true,
          data: { found: false, hits: [], confidence: 0, summary: MEMORY_EMPTY },
          summary: MEMORY_EMPTY,
        };
      }

      const lines: string[] = [];
      lines.push(`我在您的记录里找到 ${result.hits.length} 条相关内容:`);
      for (const hit of result.hits) {
        lines.push(`· ${whenLabel(hit.ts, ctx.now)} · ${KIND_LABEL[hit.kind] ?? hit.kind} · ${hit.text}`);
      }
      lines.push("");
      lines.push(
        `检索置信度 ${result.confidence.toFixed(2)}。这些是您自己的记录;要办新业务,我仍需您重新确认。`,
      );
      const summary = lines.join("\n");

      // 挂一条数据出处:回复里出现的流水号/金额都能追到台账
      const top = result.hits[0]!;
      ctx.extras?.citations.push({
        id: `data:memory:${top.opId ?? top.sessionId ?? String(top.ts)}`,
        topic: `客户记录:${top.text.slice(0, 40)}`,
        source: top.kind === "ledger" ? "客户操作台账" : top.kind === "session" ? "会话记录" : top.kind === "note" ? "记账批注" : "客户材料",
        subject: "客户本人",
        effective: `截至 ${whenLabel(top.ts, ctx.now)}`,
        asOf: ctx.now,
        calculation: [`查询:「${query}」`, `命中 ${result.hits.length} 条`],
        note: "记忆检索严格限定本客户;此处引用的数字与流水号来自台账/会话记录原文,未经模型改写",
        kind: "data",
      });

      return {
        ok: true,
        data: {
          found: true,
          hits: result.hits,
          confidence: result.confidence,
          summary,
        },
        summary,
      };
    },
  });
}
