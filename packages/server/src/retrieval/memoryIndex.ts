/**
 * 客户记忆索引:把"这台机器记得的关于你的事"统一成可检索的条目。
 *
 * ★ 四类数据源(32 文档 §5.2):
 *   · ledger    操作台账(办过什么、成没成、流水号)
 *   · session   会话记录(那次对话聊了什么)
 *   · note      记账批注(客户自己对某笔往来的定性)
 *   · document  客户提交的材料(合同/发票/回单)
 *   把它们映射成同一种形状之后,「刚才那笔转账成功了吗」才有地方可查 ——
 *   否则这句话既不是制度问题,也不该被当成一笔新的转账去问"转给谁"。
 *
 * ★ 跨客户隔离是**硬约束**:每一条都带 customerId,查询只在本客户条目里检索。
 *   这不是"注意一下",而是必须能被断言证明的事(见 P6.4)。
 *
 * ★ 时间衰减(最近 7 天加权):客户问"刚才那笔"时,
 *   上周的转账不该和十分钟前那笔抢同一个位置。
 */

import {
  buildBm25Index,
  queryTokens,
  type CustomerDocument,
  type MemorySearchResponse,
} from "../../../core/src/index.ts";
import { fmtMoney } from "../../../core/src/util/format.ts";
import type { HistoryRecord } from "../personalization.ts";
import type { SessionRecord } from "../sessions.ts";

/** 一条统一后的记忆条目 */
export interface MemoryEntry {
  customerId: string;
  kind: "ledger" | "session" | "note" | "document";
  ts: number;
  text: string;
  opId?: string;
  sessionId?: string;
  traceId?: string;
}

/** 记忆索引依赖的数据源(全部由宿主提供,便于测试替换) */
export interface MemorySources {
  ledger: (customerId: string) => Promise<HistoryRecord[]>;
  sessions: (customerId: string) => Promise<SessionRecord[]>;
  /** 记账批注(银行核心的可选能力;没有就返回空数组) */
  annotations?: (customerId: string) => Array<{
    annotationId: string;
    title: string;
    amount?: number;
    note?: string;
    tags?: string[];
    createdAt: number;
  }>;
  documents?: (customerId: string) => Promise<CustomerDocument[]>;
  now: () => number;
}

export interface MemoryIndex {
  /** 供核心调用的检索入口(跨客户隔离在这里,不在能力里) */
  searchMemory(input: { customerId: string; query: string; topK?: number }): Promise<MemorySearchResponse>;
  /** 某客户的全部条目(调试与断言用) */
  entries(customerId: string): Promise<MemoryEntry[]>;
}

const MAX_ENTRIES_PER_KIND = 200;

/**
 * ★ 条目类型权重:台账 > 批注 > 材料 > 会话。
 *
 *   客户问「刚才那笔转账成功了吗」,他要的是**那一笔**的事实(成没成、流水号)。
 *   会话记录里也常出现"转账""成功"这些词(因为它就是对话的回复),
 *   如果一视同仁,一段聊天记录会把真正的台账条目挤下去 ——
 *   实测踩到:回答的第一条竟是"历史记录查询"自己上一次的回答(自引用)。
 */
const KIND_WEIGHT: Record<MemoryEntry["kind"], number> = {
  ledger: 1.5,
  note: 1.2,
  document: 1.0,
  session: 0.7,
};

/** 两位小数金额(口径见 core/util/format.ts,单一实现) */
const fmtAmount = (amount: number): string => fmtMoney(amount);

/** 台账 → 记忆条目:客户问"那笔成了吗"时,答的就是这条 */
function ledgerEntry(customerId: string, row: HistoryRecord): MemoryEntry {
  const parts: string[] = [row.family];
  if (row.subject) parts.push(row.subject);
  if (typeof row.amount === "number") parts.push(`${fmtAmount(row.amount)} 元`);
  if (row.statusLabel) parts.push(row.statusLabel);
  if (row.reference) parts.push(`流水号 ${row.reference}`);
  // ★ detail 常常就是"流水号 REF…"的重复 —— 已经写过就不再抄一遍
  if (row.detail && (!row.reference || !row.detail.includes(row.reference))) parts.push(row.detail);
  return {
    customerId,
    kind: "ledger",
    ts: row.createdAt ?? row.ts,
    text: parts.join(" · "),
    ...(row.opId ? { opId: row.opId } : {}),
    ...(row.sessionId ? { sessionId: row.sessionId } : {}),
    ...(row.traceId ? { traceId: row.traceId } : {}),
  };
}

/** 会话 → 记忆条目:标题 + 最后一轮助手原话(截断),够回答"我们聊过什么" */
function sessionEntry(customerId: string, session: SessionRecord): MemoryEntry {
  const lastAgent = [...session.turns].reverse().find((t) => t.role === "agent");
  const tail = (lastAgent?.text ?? "").replace(/\s+/g, " ").slice(0, 120);
  return {
    customerId,
    kind: "session",
    ts: session.lastAt,
    text: [session.title, session.statusLabel, tail].filter(Boolean).join(" · "),
    sessionId: session.sessionId,
  };
}

/** 记账批注 → 记忆条目 */
function noteEntry(
  customerId: string,
  note: { title: string; amount?: number; note?: string; tags?: string[]; createdAt: number },
): MemoryEntry {
  return {
    customerId,
    kind: "note",
    ts: note.createdAt,
    text: ["记账", note.title, typeof note.amount === "number" ? `${fmtAmount(note.amount)} 元` : "", note.note ?? "", (note.tags ?? []).join(" ")]
      .filter(Boolean)
      .join(" · "),
  };
}

/** 材料 → 记忆条目(标题 + 出据方 + 前三个字段) */
function documentEntry(customerId: string, doc: CustomerDocument): MemoryEntry {
  const fields = doc.fields
    .slice(0, 3)
    .map((f) => `${f.label} ${f.value}${f.unit ?? ""}`)
    .join(" · ");
  return {
    customerId,
    kind: "document",
    ts: doc.issuedAt,
    text: [`${doc.kindLabel}「${doc.title}」`, doc.counterparty, fields].filter(Boolean).join(" · "),
  };
}

/**
 * 时间衰减系数:最近 7 天线性加权,7 天以外不加权。
 *
 * 具体是 `1 + 0.3 × recency`(32 文档 §5.2),即最近一周的条目最多被放大 30% ——
 * 足以让"刚办的那笔"排到"上个月那笔"前面,又不会让旧记录完全消失:
 * 客户问"上个月的转账"时,旧记录仍然能被检索到。
 */
function recencyBoost(ts: number, now: number, weight = 0.3): number {
  const ageDays = Math.max(0, (now - ts) / (24 * 3600 * 1000));
  if (ageDays >= 7) return 1;
  return 1 + weight * (1 - ageDays / 7);
}

/**
 * 查询里有没有"刚才/最近"这类**近期指向**。
 *
 * ★ 有的话,时间权重必须放大:客户说"刚才那笔"时,他要的就是**最新那一笔**。
 *   默认 0.3 的衰减(32 文档 §5.2)只够把"上周"排到"今天"后面,
 *   对"一分钟前"与"两分钟前"几乎没区分 —— 而这两笔在文本上往往一模一样
 *   (同一个人、同样 500 元),BM25 分不出高下,只能靠时间。
 */
const RECENT_CUE = /(刚才|刚刚|刚那笔|最近|最新|这才)/;

function recencyWeightFor(query: string): number {
  return RECENT_CUE.test(query) ? 1.5 : 0.3;
}

/** 建记忆索引 */
export function createMemoryIndex(sources: MemorySources): MemoryIndex {
  const index = {
    async entries(customerId: string): Promise<MemoryEntry[]> {
      // ★ 所有数据源都按 customerId 取 —— 隔离在数据入口处完成,不靠过滤补救
      const [ledger, sessions, documents] = await Promise.all([
        sources.ledger(customerId).catch(() => [] as HistoryRecord[]),
        sources.sessions(customerId).catch(() => [] as SessionRecord[]),
        sources.documents ? sources.documents(customerId).catch(() => [] as CustomerDocument[]) : Promise.resolve([]),
      ]);

      const entries: MemoryEntry[] = [];
      for (const row of ledger.slice(0, MAX_ENTRIES_PER_KIND)) entries.push(ledgerEntry(customerId, row));
      for (const session of sessions.slice(0, MAX_ENTRIES_PER_KIND)) entries.push(sessionEntry(customerId, session));
      for (const note of (sources.annotations?.(customerId) ?? []).slice(0, MAX_ENTRIES_PER_KIND)) {
        entries.push(noteEntry(customerId, note));
      }
      for (const doc of documents.slice(0, MAX_ENTRIES_PER_KIND)) entries.push(documentEntry(customerId, doc));
      return entries;
    },

    async searchMemory(input: { customerId: string; query: string; topK?: number }): Promise<MemorySearchResponse> {
      const { customerId, query } = input;
      const topK = Math.max(1, Math.min(input.topK ?? 5, 10));
      const now = sources.now();
      const tokens = queryTokens(query);
      const all = await index.entries(customerId);
      if (tokens.length === 0 || all.length === 0) return { hits: [], confidence: 0 };

      /**
       * ★ 说「刚才」的时候,就把范围收窄到最近 6 小时。
       *
       *   只靠时间加权不够:客户说"刚才那笔"时,文本上往往有**好几笔一模一样的**
       *   (同一个人、同样 500 元),BM25 分不出高下,7 天线性衰减在"8 分钟前"
       *   与"20 分钟前"之间也几乎没有差别 —— 结果最新那笔可能排第四。
       *   语义上"刚才"本来就该先看最近的记录,所以直接收窄候选集;
       *   收窄后一条都没有(比如客户昨天来过、今天才说"刚才"),再退回全量。
       */
      const candidates = RECENT_CUE.test(query)
        ? all.filter((entry) => now - entry.ts <= 6 * 3600 * 1000)
        : all;
      const pool = candidates.length > 0 ? candidates : all;

      // BM25 只用来给"词面相关"打分;时间衰减在此之上叠加
      const bm25 = buildBm25Index(
        pool.map((entry, i) => ({
          id: String(i),
          docTitle: "",
          clauseTitle: "",
          text: entry.text,
        })),
      );
      const scored = bm25.search(tokens);
      const recencyWeight = recencyWeightFor(query);
      const sorted = scored
        .map((hit) => {
          const entry = pool[Number(hit.id)]!;
          const score =
            Math.round(hit.score * recencyBoost(entry.ts, now, recencyWeight) * KIND_WEIGHT[entry.kind] * 10000) /
            10000;
          return {
            kind: entry.kind,
            ts: entry.ts,
            text: entry.text,
            score,
            ...(entry.opId ? { opId: entry.opId } : {}),
            ...(entry.sessionId ? { sessionId: entry.sessionId } : {}),
            ...(entry.traceId ? { traceId: entry.traceId } : {}),
          };
        })
        .sort((a, b) => b.score - a.score);

      /**
       * ★ 说「刚才」时:**相关**决定候选,**时间**决定顺序。
       *
       *   文本上"几分钟前"与"十几分钟前"的两笔可能字字相同,
       *   BM25 的细微差别(甚至只是流水号长短导致的文档长度差)就能把最新那笔排到第五。
       *   客户说"刚才那笔",他要的是**最新那一笔** —— 所以先按相关度筛出候选
       *   (不低于最高分 60%),再按时间倒序。
       */
      const topScore = sorted[0]?.score ?? 0;
      const ordered = recencyWeight > 0.3
        ? sorted.filter((h) => h.score >= topScore * 0.6).sort((a, b) => b.ts - a.ts)
        : sorted;

      const hits = ordered.slice(0, topK);

      if (hits.length === 0) return { hits: [], confidence: 0 };
      const best = hits[0]!;
      const confidence = Math.round(Math.min(0.99, Math.min(1, best.score / 10) * 0.8 + 0.15) * 100) / 100;
      return { hits, confidence };
    },
  };
  return index;
}
