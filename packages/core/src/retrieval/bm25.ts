/**
 * BM25 打分(制度条款检索)。
 *
 * ★ 为什么是 BM25 而不是向量:阶段 1/2 的语料只有 20 条条款,
 *   查询是「怎么免年费」这类短句。BM25 对这种"关键词高度重合"的场景
 *   不但够用,而且**可解释** —— 能直接告诉用户"命中的是哪几个词"。
 *   向量检索在这里买不到任何东西,反而会引入一个不可复现的分数。
 *
 * ★ 三处字段加权(32 文档 §4.2):
 *   · 条款标题  ×2.0 —— 「免年费条件」这种标题命中,通常就是答案;
 *   · 文档标题  ×1.5 —— 「长城信用卡章程」能帮助区分业务域;
 *   · 条款正文  ×1.0。
 */

import { tokenize } from "./tokenizer.ts";

export interface Bm25Document {
  /** 唯一 ID(制度检索里是 `docId#clauseId`) */
  id: string;
  /** 文档标题(如「长城信用卡章程」) */
  docTitle: string;
  /** 条款标题(如「免年费条件」) */
  clauseTitle: string;
  /** 条款正文 */
  text: string;
}

export interface Bm25Hit {
  id: string;
  score: number;
  /** 命中的查询词(用于解释与调试) */
  matched: string[];
}

export interface Bm25Index {
  /** 文档数 */
  size: number;
  /** 返回按分数降序的全部命中(分数为 0 的不返回) */
  search(queryTokens: string[]): Bm25Hit[];
}

const K1 = 1.5;
const B = 0.75;
const WEIGHT_DOC_TITLE = 1.5;
/**
 * ★ 条款标题权重从 2.0 提到 4.0(评测校准的结果,见 32 文档 §7.2)。
 *
 *   提权的原因很具体:两个边界用例都栽在"标题命中了、但正文里的偶然词把它压过去"上 ——
 *   · 「单笔多少钱以上要人脸」:正确答案的标题就是「人脸触发」,
 *     却输给了价目条款里"单笔…以上…手续费"这三个偶然词;
 *   · 「争议最晚多久能提」:正确答案的标题是「争议交易时限」,
 *     却输给了另一条正文里"争议最长不超过…"的巧合。
 *   条款标题是**人工提炼过的主题词**,命中它的证据强度远高于正文里的偶合,
 *   所以它的权重必须能把这类巧合压下去。
 */
const WEIGHT_CLAUSE_TITLE = 4.0;
const WEIGHT_TEXT = 1.0;

interface PreparedDoc {
  id: string;
  /** 加权词频 */
  tf: Map<string, number>;
  /** 加权文档长度 */
  length: number;
}

/** 把一条文档的三个字段压成"加权词频表"(BM25 只看词频与长度,字段差异用权重表达) */
function prepare(doc: Bm25Document): PreparedDoc {
  const tf = new Map<string, number>();
  const add = (tokens: string[], weight: number): number => {
    for (const token of tokens) tf.set(token, (tf.get(token) ?? 0) + weight);
    return tokens.length * weight;
  };
  const length =
    add(tokenize(doc.docTitle), WEIGHT_DOC_TITLE) +
    add(tokenize(doc.clauseTitle), WEIGHT_CLAUSE_TITLE) +
    add(tokenize(doc.text), WEIGHT_TEXT);
  return { id: doc.id, tf, length };
}

/**
 * 建索引(纯内存、可重复构建、同一输入两次结果完全一致)。
 *
 * ★ "同一查询两次得分一致"是硬要求(32 文档 P5.1 验收):
 *   演示时同一个问题问两次给出不同置信度,客户会立刻怀疑系统在编数字。
 */
export function buildBm25Index(documents: Bm25Document[]): Bm25Index {
  const prepared = documents.map(prepare);
  const avgdl =
    prepared.length > 0 ? prepared.reduce((sum, d) => sum + d.length, 0) / prepared.length : 0;

  // 文档频率:某个词在多少篇文档里出现过(三个字段合起来算一次)
  const df = new Map<string, number>();
  for (const doc of prepared) {
    for (const term of doc.tf.keys()) df.set(term, (df.get(term) ?? 0) + 1);
  }
  const total = prepared.length;
  const idf = (term: string): number => {
    const n = df.get(term) ?? 0;
    if (n === 0) return 0;
    return Math.log(1 + (total - n + 0.5) / (n + 0.5));
  };

  return {
    size: total,
    search(queryTokens: string[]): Bm25Hit[] {
      const terms = [...new Set(queryTokens)];
      if (terms.length === 0 || total === 0) return [];

      const hits: Bm25Hit[] = [];
      for (const doc of prepared) {
        let score = 0;
        const matched: string[] = [];
        for (const term of terms) {
          const tf = doc.tf.get(term) ?? 0;
          if (tf <= 0) continue;
          matched.push(term);
          const norm = 1 - B + (B * doc.length) / (avgdl > 0 ? avgdl : 1);
          score += idf(term) * ((tf * (K1 + 1)) / (tf + K1 * norm));
        }
        if (score > 0) hits.push({ id: doc.id, score: Math.round(score * 10000) / 10000, matched });
      }
      // 同分时按 id 排,保证结果稳定(不依赖 Map/排序实现细节)
      return hits.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    },
  };
}
