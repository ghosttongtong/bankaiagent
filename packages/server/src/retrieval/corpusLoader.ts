/**
 * 语料加载:把 `packages/bankcore/corpus/policies.json` 读成检索索引。
 *
 * ★ 为什么放在 server 而不是 core:
 *   core 不读文件、不依赖 bankcore(依赖方向向内)。语料从哪来是**部署形态**:
 *   今天是随代码入库的 JSON,明天可能是行内制度库接口。
 *   核心只认 `RetrievalPort`,宿主负责把它填上。
 *
 * ★ 语料缺失不应让整个应用起不来:返回 null,`policy.search` 会如实回答
 *   "检索未就绪" —— 这比让转账、查余额一起挂掉要好得多。
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  buildPolicyIndex,
  type PolicyDocument,
  type PolicyIndex,
  type RetrievalPort,
} from "../../../core/src/index.ts";

/** 默认语料位置(相对本模块解析,不依赖启动目录) */
export const DEFAULT_CORPUS_PATH = fileURLToPath(
  new URL("../../../bankcore/corpus/policies.json", import.meta.url),
);

export interface CorpusFile {
  version: string;
  documents: PolicyDocument[];
}

export interface LoadedCorpus {
  index: PolicyIndex;
  /** 语料版本(如 2026.1) */
  version: string;
  /** 文档数 / 条款数(启动日志与评测脚本会打出来) */
  documentCount: number;
  clauseCount: number;
  /** 建索引耗时(毫秒) */
  buildMs: number;
}

/** 读取并校验语料,建索引 */
export async function loadPolicyCorpus(path: string = DEFAULT_CORPUS_PATH): Promise<LoadedCorpus> {
  const started = performance.now();
  const raw = await readFile(path, "utf8");
  const parsed = JSON.parse(raw) as Partial<CorpusFile>;

  if (!Array.isArray(parsed.documents) || parsed.documents.length === 0) {
    throw new Error(`语料为空或格式不对:${path}`);
  }
  // ★ 每条条款都必须带 version / effectiveFrom / issuer —— 少一样就不能作答,
  //   因为回答里必须展示它们(可追溯)。缺字段的语料宁可在启动时就报错。
  for (const doc of parsed.documents) {
    for (const field of ["docId", "title", "version", "effectiveFrom", "issuer"] as const) {
      if (typeof doc[field] !== "string" || doc[field].length === 0) {
        throw new Error(`语料 ${doc.docId ?? "(未知文档)"} 缺少 ${field}`);
      }
    }
    if (!Array.isArray(doc.clauses) || doc.clauses.length === 0) {
      throw new Error(`语料 ${doc.docId} 没有条款`);
    }
  }

  const index = buildPolicyIndex(parsed.documents);
  return {
    index,
    version: parsed.version ?? "unknown",
    documentCount: parsed.documents.length,
    clauseCount: index.size,
    buildMs: Math.round((performance.now() - started) * 100) / 100,
  };
}

/** 把索引包装成核心认识的检索端口(阶段 1 只实现制度检索) */
export function createRetrievalPort(index: PolicyIndex): RetrievalPort {
  return {
    async searchPolicy(query: string, topK?: number) {
      return index.search(query, topK);
    },
  };
}
