/**
 * 诊断脚本:直接调用意图解析器,打印模型原始输出与校验错误。
 * 用法:node packages/cli/src/diagnoseLlm.ts
 */
import "dotenv/config";

import { readLlmConfigFromEnv, selectLlmProvider } from "../../llm/src/factory.ts";
import { buildIntentSystemPrompt, parseIntent } from "../../llm/src/intentParser.ts";
import { ParsedRequestSchema } from "../../core/src/intent/schema.ts";

const config = readLlmConfigFromEnv();
const selection = selectLlmProvider(config);

console.log("=".repeat(78));
console.log(`provider = ${selection.provider.name} / ${selection.provider.model}`);
console.log(`mode     = ${selection.mode}`);
console.log(`reason   = ${selection.reason}`);
console.log("=".repeat(78));

const ctx = {
  nowIso: new Date().toISOString(),
  timezone: "Asia/Shanghai",
  currency: "CNY",
  customerDisplayName: "张先生",
  channel: "app",
};

// ---- 1. 连通性 ----
console.log("\n[1] 连通性检测 ...");
const ping = await selection.provider.ping();
console.log(`    ok=${ping.ok} latency=${ping.latencyMs}ms ${ping.detail ?? ""}`);
if (!ping.ok) {
  console.log("\n连通性失败,后续测试跳过。");
  process.exit(1);
}

// ---- 2. 原样调用,看原始输出 ----
console.log("\n[2] 原始调用(不经过 Schema 校验),观察模型到底返回了什么 ...");

const messages = [
  { role: "system" as const, content: buildIntentSystemPrompt(ctx) },
  { role: "user" as const, content: "给老妈转2000,备注这个月生活费" },
];

const raw = await selection.provider.complete({
  messages,
  temperature: 0,
  responseFormat: "json_object",
});

console.log(`    finishReason = ${raw.finishReason}`);
console.log(`    usage        = ${JSON.stringify(raw.usage)}`);
console.log(`    content 长度 = ${raw.content.length}`);
console.log("\n--- content 前 1200 字符 ---");
console.log(raw.content.slice(0, 1200));
console.log("--- content 结束 ---");

// ---- 3. 尝试解析 ----
console.log("\n[3] 尝试 JSON 提取与 Schema 校验 ...");
const { extractJson } = await import("../../llm/src/provider.ts");
const jsonText = extractJson(raw.content);
if (jsonText == null) {
  console.log("    ✗ 未能提取到 JSON");
} else {
  console.log(`    ✓ 提取到 JSON,长度 ${jsonText.length}`);
  try {
    const parsed: unknown = JSON.parse(jsonText);
    const validated = ParsedRequestSchema.safeParse(parsed);
    if (validated.success) {
      console.log("    ✓ Schema 校验通过");
      console.log(`      action = ${validated.data.intent.action}`);
      console.log(`      amount = ${JSON.stringify(validated.data.intent.amount)}`);
      console.log(`      payee  = ${JSON.stringify(validated.data.intent.payee)}`);
    } else {
      console.log("    ✗ Schema 校验失败:");
      for (const issue of validated.error.issues.slice(0, 12)) {
        console.log(`      - ${issue.path.join(".") || "(root)"}: ${issue.message} (code=${issue.code})`);
      }
      console.log("\n    实际收到的对象(前 1500 字符):");
      console.log(JSON.stringify(parsed, null, 2).slice(0, 1500));
    }
  } catch (e) {
    console.log(`    ✗ JSON.parse 失败:${(e as Error).message}`);
  }
}

// ---- 4. 走完整解析器 ----
console.log("\n[4] 走完整 parseIntent(与生产路径一致)...");
const result = await parseIntent({
  provider: selection.provider,
  userText: "给老妈转2000,备注这个月生活费",
  context: ctx,
});
console.log(`    ok = ${result.ok}`);
if (!result.ok) {
  console.log(`    error = ${result.error}`);
  console.log(`    rawContent 前 800 字符:\n${result.rawContent ?? "(无)"}`);
} else {
  console.log(`    action = ${result.parsed?.intent.action}`);
}
