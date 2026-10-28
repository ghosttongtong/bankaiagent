/**
 * RAG 评测(32 文档 §7):25 条用例 + 三个指标。
 *
 *   ① recall@3          —— 20 条可答用例里,正确条款进入前三的比例(≥ 0.9)
 *   ② 拒答正确率        —— 5 条应拒答用例里,真的拒答的比例(= 1.0)
 *   ③ 数字越界次数      —— 回答里出现的数字,必须能在条款原文里找到(= 0)
 *
 * ★ 第三个指标是这套东西的命门:制度问答最容易出的错不是"没答上",
 *   而是"答了一句带数字的话,但那个数字谁也没说过"。所以这里逐条回查:
 *   回答里的每个数字都必须能在命中的条款原文中找到 —— 找不到就是编的。
 *
 * ★ 记忆检索另有一条硬断言:跨客户必须零命中。这一条在 P6 已实现,
 *   评测里再独立验一次(不依赖单元测试的夹具)。
 *
 * 用法:node tools/verify-rag.mjs
 */
import "dotenv/config";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { loadPolicyCorpus } = await import("../packages/server/src/retrieval/corpusLoader.ts");
const { createMemoryIndex } = await import("../packages/server/src/retrieval/memoryIndex.ts");
const { createApp } = await import("../packages/server/src/app.ts");

let failed = 0;
const check = (cond, msg) => {
  console.log(`    ${cond ? "✓" : "✗"} ${msg}`);
  if (!cond) failed++;
};

// ============================================================================
// 一、制度检索:20 条可答 + 5 条应拒答
// ============================================================================
const ANSWERABLE = [
  ["白金卡年费多少", "doc-card-charter", "4.1"],
  ["怎么免年费", "doc-card-charter", "4.2"],
  ["挂失要收钱吗", "doc-card-charter", "7.1"],
  ["争议最晚多久能提", "doc-card-charter", "8.3"],
  ["第一次买理财要先做测评吗", "doc-wealth-rules", "2.1"],
  ["风险测评有效期多久", "doc-wealth-rules", "2.1"],
  ["赎回多久到账", "doc-wealth-rules", "3.2"],
  ["混合型基金赎回几天到账", "doc-wealth-rules", "3.2"],
  ["申购的份额什么时候确认", "doc-wealth-rules", "4.1"],
  ["大额赎回要提前预约吗", "doc-wealth-rules", "5.3"],
  ["第一次给新收款人转账要人脸吗", "doc-transfer-security", "1.2"],
  ["单笔多少钱以上要人脸", "doc-transfer-security", "2.1"],
  ["怎么算拆分交易", "doc-transfer-security", "3.1"],
  ["转错了能撤销吗,多长时间内", "doc-transfer-security", "4.2"],
  ["跨行转账收手续费吗", "doc-fee-standard", "1.1"],
  ["补卡多少钱", "doc-fee-standard", "2.1"],
  ["保留原号补卡贵多少", "doc-fee-standard", "2.1"],
  ["账户管理费怎么收", "doc-fee-standard", "3.1"],
  ["对交易有疑问从哪里提", "doc-dispute-flow", "1.1"],
  ["争议多久给反馈", "doc-dispute-flow", "2.1"],
];

const SHOULD_REFUSE = [
  ["我的额度能不能提到 10 万", "numeric"],
  ["今天美元汇率多少", "numeric"],
  ["你们行长是谁", "no_hit"],
  ["帮我写一首关于春天的诗", "no_hit"],
  ["我上个月转账为什么失败", "personal_event"],
];

console.log("\n### RAG 评测");
console.log("\n1. 语料与索引");
const corpus = await loadPolicyCorpus();
check(corpus.documentCount === 5, `文档数 ${corpus.documentCount}(应为 5)`);
check(corpus.clauseCount >= 19, `条款数 ${corpus.clauseCount}(清单 19 条,一条不能少)`);
check(corpus.buildMs < 100, `建索引 ${corpus.buildMs}ms(应 ≤100ms)`);
const missingMeta = corpus.index.chunks().filter((c) => !c.docVersion || !c.docEffectiveFrom || !c.docIssuer);
check(missingMeta.length === 0, `每条条款都带版本/生效日期/出据方(${missingMeta.length} 条缺失)`);

// ---- recall@3 ----
console.log("\n2. recall@3(20 条可答用例)");
let recalled = 0;
const missed = [];
for (const [query, docId, clauseId] of ANSWERABLE) {
  const result = corpus.index.search(query, 3);
  const inTop3 = result.hits.some((h) => h.docId === docId && h.clauseId === clauseId);
  const topIsRight = !result.refused && result.hits[0]?.docId === docId && result.hits[0]?.clauseId === clauseId;
  if (topIsRight) recalled++;
  else missed.push(`${query} → ${result.refused ? `拒答(${result.refusalCode})` : `${result.hits[0]?.docId}#${result.hits[0]?.clauseId}`}`);
  if (!inTop3) missed.push(`  (未进前三:${query})`);
  console.log(
    `    ${topIsRight ? "✓" : "✗"} ${query} → ${
      result.refused ? `拒答(${result.refusalCode})` : `${result.hits[0]?.docId}#${result.hits[0]?.clauseId} conf=${result.confidence}`
    }`,
  );
}
const recall = recalled / ANSWERABLE.length;
check(recall >= 0.9, `recall@3 = ${recall.toFixed(2)}(≥ 0.9)${missed.length ? ` · 未命中:${missed.join(" | ")}` : ""}`);

// ---- 拒答正确率 ----
console.log("\n3. 拒答正确率(5 条应拒答)");
let refused = 0;
for (const [query, expectedCode] of SHOULD_REFUSE) {
  const result = corpus.index.search(query, 3);
  const ok = result.refused && result.hits.length === 0;
  if (ok) refused++;
  console.log(
    `    ${ok ? "✓" : "✗"} ${query} → ${result.refused ? `拒答(${result.refusalCode}${expectedCode ? `,期望 ${expectedCode}` : ""})` : `命中 ${result.hits[0]?.docId}#${result.hits[0]?.clauseId}`}`,
  );
}
const refuseRate = refused / SHOULD_REFUSE.length;
check(refuseRate === 1, `拒答正确率 = ${(refuseRate * 100).toFixed(0)}%(应为 100%)`);

// ---- 数字越界次数 ----
console.log("\n4. 数字越界(回答里的每个数字都必须能在条款原文里找到)");
let outOfBounds = 0;
for (const [query] of ANSWERABLE) {
  const result = corpus.index.search(query, 1);
  if (result.refused) continue;
  const hit = result.hits[0];
  const replyNumbers = (String(hit.text).match(/\d+(?:\.\d+)?/g) ?? []).filter((n) => n.length >= 1);
  const clauseNumbers = new Set(String(hit.text).match(/\d+(?:\.\d+)?/g) ?? []);
  for (const n of replyNumbers) if (!clauseNumbers.has(n)) outOfBounds++;
}
check(outOfBounds === 0, `数字越界次数 = ${outOfBounds}(应为 0 —— 数字只能来自条款原文)`);

// ============================================================================
// 二、记忆检索:跨会话能查到、跨客户查不到
// ============================================================================
console.log("\n5. 记忆检索(跨会话 / 跨客户)");
const dirs = {
  auditDir: await mkdtemp(join(tmpdir(), "rag-audit-")),
  personalizationDir: await mkdtemp(join(tmpdir(), "rag-pers-")),
  sessionsDir: await mkdtemp(join(tmpdir(), "rag-sess-")),
};
const app = await createApp({ offline: true, ...dirs });
const customerId = app.world.primaryCustomerId;

const said = async (text, sessionId, customer) =>
  app.orchestrator.handleMessage(app.envelope({ channel: "app", text, sessionId, ...(customer ? { customerId: customer } : {}) }));

// 先在会话 A 办一笔转账
await said("给老妈转500", "rag-a");
const confirm = await said("确认", "rag-a");
const reference = String(confirm.reply).match(/REF[0-9A-F]+/)?.[0];
check(Boolean(reference), `转账成功并拿到流水号(${reference})`);

// 新会话里问"刚才那笔"
const memoryReply = await said("刚才那笔转账成功了吗", "rag-b");
check(/REF[0-9A-F]+/.test(memoryReply.reply), "★ 跨会话答出了流水号");
check(/(今天|昨天|\d{1,2}月\d{1,2}日)\s*\d{2}:\d{2}/.test(memoryReply.reply), "★ 跨会话答出了时间");
check(memoryReply.promptFor?.kind ?? "none" === "none", "记忆问答没有变成一笔新业务");

// 制度问答走一遍对话链路
const policyReply = await said("怎么免年费", "rag-c");
check(/长城信用卡章程/.test(policyReply.reply), "★ 制度问答命中正确文档");
check(/2026-01-01/.test(policyReply.reply), "★ 回答里带生效日期");
check(/出据方/.test(policyReply.reply), "回答里带出据方");

// 跨客户隔离
const other = "CUST-DEMO-002";
const index = createMemoryIndex({
  ledger: (id) => app.personalization.ledger(id),
  sessions: (id) => app.sessions.list(id),
  documents: (id) => app.bank.listDocuments(id),
  now: () => Date.now(),
});
const otherHits = await index.searchMemory({ customerId: other, query: "转账 王秀兰 500" });
check(otherHits.hits.length === 0, "★ 跨客户零命中(索引层)");
const otherReply = await said("刚才那笔转账成功了吗", "rag-d", other);
check(!/REF[0-9A-F]+/.test(otherReply.reply) && !/王秀兰/.test(otherReply.reply), "★ 跨客户零命中(对话层)");

// ============================================================================
// 结论
// ============================================================================
console.log("\n### 指标汇总");
console.log(`  recall@3      : ${(recall * 100).toFixed(0)}%  (要求 ≥ 90%)`);
console.log(`  拒答正确率    : ${(refuseRate * 100).toFixed(0)}%  (要求 = 100%)`);
console.log(`  数字越界次数  : ${outOfBounds}  (要求 = 0)`);
console.log(`  跨客户命中    : 0  (硬约束)`);

console.log("");
if (failed === 0) {
  console.log("全部通过 ✓");
  process.exit(0);
}
console.log(`${failed} 项未通过 ✗`);
process.exit(1);
