/**
 * 检索组装:语料 → 条款 chunk → BM25 索引 → 带置信度与拒答的查询。
 *
 * ★ 这一层只做"检索",不做任何业务判断,也不产出任何金额:
 *   它返回的是"命中哪几条条款、有多确信、要不要拒答",
 *   至于"要不要办、能不能办"由策略引擎决定(检索永不参与裁决)。
 */

import { chunkDocuments, buildChunkIndex, type PolicyDocument, type PolicyChunk } from "./chunking.ts";
import {
  judgeAcceptance,
  looksNumericQuestion,
  looksPersonalEventQuestion,
  PERSONAL_EVENT_TEXT,
  POLICY_REFUSAL_TEXT,
} from "./guard.ts";
import { explainMatched, queryTokens } from "./tokenizer.ts";

export interface PolicyHit {
  docId: string;
  title: string;
  version: string;
  clauseId: string;
  clauseTitle: string;
  text: string;
  effectiveFrom: string;
  issuer: string;
  score: number;
  /** 命中的查询词(用于解释"为什么是这条") */
  matched: string[];
  /** 覆盖率:这条条款覆盖了多少查询词 */
  coverage: number;
}

export interface PolicySearchResult {
  hits: PolicyHit[];
  confidence: number;
  coverage: number;
  /** 是否拒答 */
  refused: boolean;
  /** 拒答理由(面向客户的固定话术) */
  refusalReason: string | null;
  /** 拒答的内部原因(调试/审计用) */
  refusalCode?: "numeric" | "personal_event" | "no_hit" | "low_score" | "low_coverage" | "ambiguous" | "empty_corpus";
}

export interface PolicyIndex {
  /** 条款总数(启动日志里打出来,证明语料真的加载了) */
  size: number;
  search(query: string, topK?: number): PolicySearchResult;
  /** 全部条款(评测与新会话导入用) */
  chunks(): PolicyChunk[];
}

/**
 * 建索引。
 *
 * ★ 纯内存、同步、无磁盘写入(32 文档 P5.3 验收:启动 ≤100ms)。
 *   语料 20 条条款,建索引的耗时在微秒级 —— 不需要缓存到磁盘,
 *   缓存反而会引入"语料更新了但索引没更新"的新问题。
 */
export function buildPolicyIndex(documents: PolicyDocument[]): PolicyIndex {
  const chunks = chunkDocuments(documents);
  const byId = new Map(chunks.map((c) => [c.id, c]));
  const bm25 = buildChunkIndex(chunks);

  /**
   * ★ 覆盖率的分母只算"语料里真实出现过的查询词"。
   *
   *   一开始按"全部查询词"算,结果大量正确命中被拒答:
   *   「挂失要收钱吗」的查询词是 挂失/失要/要收/收钱/钱吗 ——
   *   后四个词在语料里根本不存在(它们是问句的碎片),
   *   于是一条完全正确的命中只拿到 0.2 的覆盖率,被门槛挡住。
   *
   *   这不是放宽标准,而是换了一个正确的问题:
   *   "语料里压根没有这个词"说明不了"命中的条款不对",
   *   它只是说明用户用了口语。真正的判据是:
   *   语料**认识的**那些词,这条条款覆盖了多少。
   */
  const vocabulary = new Set<string>();
  for (const chunk of chunks) for (const token of chunk.tokens) vocabulary.add(token);

  return {
    size: chunks.length,
    chunks: () => [...chunks],
    search(query: string, topK = 3): PolicySearchResult {
      /**
       * ① 数字类问题:不查索引。
       *    这不是"检索做得不好",而是"这类问题根本不该由制度回答" ——
       *    制度里没有客户的余额,拿检索去凑数字必然是编的。
       */
      if (looksNumericQuestion(query)) {
        return {
          hits: [],
          confidence: 0,
          coverage: 0,
          refused: true,
          refusalReason: POLICY_REFUSAL_TEXT,
          refusalCode: "numeric",
        };
      }

      /**
       * ①b "我自己那笔交易怎么了" —— 制度里没有答案,只能查台账(阶段 2)。
       *     放任它进检索,系统就会拿"转账手续费"回答"为什么失败"。
       */
      if (looksPersonalEventQuestion(query)) {
        return {
          hits: [],
          confidence: 0,
          coverage: 0,
          refused: true,
          refusalReason: PERSONAL_EVENT_TEXT,
          refusalCode: "personal_event",
        };
      }

      const tokens = queryTokens(query);
      const meaningful = tokens.filter((t) => vocabulary.has(t));
      if (tokens.length === 0 || meaningful.length === 0 || chunks.length === 0) {
        return {
          hits: [],
          confidence: 0,
          coverage: 0,
          refused: true,
          refusalReason: POLICY_REFUSAL_TEXT,
          refusalCode: chunks.length === 0 ? "empty_corpus" : "no_hit",
        };
      }

      const scored = bm25.search(tokens);
      const hits: PolicyHit[] = [];
      for (const hit of scored.slice(0, Math.max(1, topK))) {
        const chunk = byId.get(hit.id);
        if (!chunk) continue;
        const matched = explainMatched(meaningful, `${chunk.clauseTitle} ${chunk.text}`);
        hits.push({
          docId: chunk.docId,
          title: chunk.docTitle,
          version: chunk.docVersion,
          clauseId: chunk.clauseId,
          clauseTitle: chunk.clauseTitle,
          text: chunk.text,
          effectiveFrom: chunk.docEffectiveFrom,
          issuer: chunk.docIssuer,
          score: hit.score,
          matched,
          coverage: matched.length / meaningful.length,
        });
      }

      const best = hits[0];
      const second = hits[1];
      // 覆盖率以**全局**查询词为准,而不是"这条命中几个词"里的最大值
      const coverage = best ? best.coverage : 0;
      const verdict = judgeAcceptance({
        bestScore: best?.score ?? 0,
        secondScore: second?.score ?? 0,
        coverage,
      });

      if (!verdict.accepted) {
        return {
          hits: [],
          confidence: verdict.confidence,
          coverage,
          refused: true,
          refusalReason: POLICY_REFUSAL_TEXT,
          ...(verdict.reason ? { refusalCode: verdict.reason } : {}),
        };
      }

      return {
        hits,
        confidence: verdict.confidence,
        coverage,
        refused: false,
        refusalReason: null,
      };
    },
  };
}
