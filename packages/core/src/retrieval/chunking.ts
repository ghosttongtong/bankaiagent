/**
 * 按条款切分(不是按字符切)。
 *
 * ★ 这条规则看起来理所当然,但它是 RAG 里最容易做错的一步:
 *   如果按固定长度切块,一条条款会被拦腰截断 —— 客户拿到的依据变成
 *   「……补卡工本费 20 元」的前半句「补卡工本费」,或者后半句「20 元」。
 *   制度问答的答案是**一条完整条款**,所以切分单位必须与条款边界一致。
 *
 * ★ 同时把"文档标题 / 版本 / 生效日期 / 出据方"一路带到每个 chunk 上:
 *   它们是"可追溯"的载体 —— 客户看到的不该只是一句话,而是
 *   「《长城信用卡章程(2026 版)》第 4.2 条,2026-01-01 生效,出据方:信用卡中心」。
 */

import { buildBm25Index, type Bm25Index } from "./bm25.ts";
import { tokenize } from "./tokenizer.ts";

/** 语料里的一条条款 */
export interface PolicyClause {
  clauseId: string;
  title: string;
  text: string;
}

/** 语料里的一份制度文档 */
export interface PolicyDocument {
  docId: string;
  title: string;
  version: string;
  effectiveFrom: string;
  issuer: string;
  clauses: PolicyClause[];
}

/** 切分后的可检索单元 = 一条条款 + 它所属文档的元数据 */
export interface PolicyChunk {
  /** 检索 ID:`docId#clauseId` */
  id: string;
  docId: string;
  docTitle: string;
  docVersion: string;
  docEffectiveFrom: string;
  docIssuer: string;
  clauseId: string;
  clauseTitle: string;
  text: string;
  /** 条款关键词(建索引用,也用于解释命中) */
  tokens: string[];
}

/** 把语料切成"条款级"检索单元 */
export function chunkDocuments(documents: PolicyDocument[]): PolicyChunk[] {
  const chunks: PolicyChunk[] = [];
  for (const doc of documents) {
    for (const clause of doc.clauses) {
      chunks.push({
        id: `${doc.docId}#${clause.clauseId}`,
        docId: doc.docId,
        docTitle: doc.title,
        docVersion: doc.version,
        docEffectiveFrom: doc.effectiveFrom,
        docIssuer: doc.issuer,
        clauseId: clause.clauseId,
        clauseTitle: clause.title,
        text: clause.text,
        tokens: tokenize(`${doc.title} ${clause.title} ${clause.text}`),
      });
    }
  }
  return chunks;
}

/** 为条款集合建 BM25 索引(文档标题 / 条款标题 / 正文分别加权) */
export function buildChunkIndex(chunks: PolicyChunk[]): Bm25Index {
  return buildBm25Index(
    chunks.map((chunk) => ({
      id: chunk.id,
      docTitle: chunk.docTitle,
      clauseTitle: chunk.clauseTitle,
      text: chunk.text,
    })),
  );
}
