/**
 * 大模型供应商抽象层
 *
 * 设计原则:
 *   1. 模型是可替换的零件,不是架构核心。核心是能力注册表 + 策略引擎。
 *   2. 必须支持**离线降级**:LLM_OFFLINE=1 时使用确定性规则解析器,
 *      整条链路(意图 → 计划 → 裁决 → 确认 → 执行 → 审计)依然完整跑通。
 *      这不是妥协,而是可演示性保障 —— 现场网络不可控。
 *   3. 模型只负责"理解与规划",绝不参与裁决(I1)。
 */

import type { z } from "zod";

export interface LlmMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** 工具调用(assistant 消息发起) */
  toolCalls?: LlmToolCall[];
  /** 工具结果(tool 消息) */
  toolCallId?: string;
  name?: string;
}

export interface LlmToolCall {
  id: string;
  name: string;
  /** 原始 JSON 字符串,需经 Schema 校验后才可使用 */
  arguments: string;
}

export interface LlmToolDefinition {
  name: string;
  description: string;
  /** JSON Schema(由 zod 转换而来) */
  parameters: Record<string, unknown>;
}

export interface LlmCompletionRequest {
  messages: LlmMessage[];
  tools?: LlmToolDefinition[];
  /** 强制工具调用 */
  toolChoice?: "auto" | "none" | { name: string };
  temperature?: number;
  maxTokens?: number;
  /** 要求返回严格 JSON */
  responseFormat?: "text" | "json_object";
}

export interface LlmUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

/**
 * 系统注入的"伪用户消息"标记。
 *
 * ★ 为什么必须有个统一清单:
 *   为了让模型遵守格式,我们会在真正的用户消息之后**再追加一条 role:"user" 的消息**,
 *   内容是系统写的提示语(重试提醒、多意图提醒等)。
 *   这对大模型是有效的(离生成最近,影响力最大),但对**离线规则解析器**是陷阱 ——
 *   它按"取最后一条用户消息"来定位待解析文本,于是会去解析系统自己写的提示语。
 *
 *   实测踩过两次,后果都很隐蔽:
 *     ① 重试提示语被当成用户输入 → 用户说「帮我AA一下」,系统回「请问这笔钱要转给谁?」;
 *     ② 多意图提示语被当成用户输入 → 「先给我妈转200,再给李明转200」被判成
 *        "只完整理解了第一件",整批计划直接消失。
 *   两次都属于"增强/恢复机制自己成了错误来源",所以集中登记并统一过滤。
 */
export const SYSTEM_INJECTED_MARKERS = ["你上一次的输出无法通过校验", "【系统提示】"] as const;

/** 判断一条 user 消息是否是系统注入的(而不是用户真的说了这句话) */
export function isSystemInjectedMessage(content: string): boolean {
  return SYSTEM_INJECTED_MARKERS.some((m) => content.includes(m));
}

export interface LlmCompletionResult {
  content: string;
  toolCalls: LlmToolCall[];
  usage: LlmUsage;
  model: string;
  finishReason: string;
  latencyMs: number;
}

export interface LlmProvider {
  readonly name: string;
  readonly model: string;
  complete(request: LlmCompletionRequest): Promise<LlmCompletionResult>;
  /** 连通性检测 */
  ping(): Promise<{ ok: boolean; latencyMs: number; detail?: string }>;
}

/**
 * 把 JSON 中的 null 归一化为 undefined。
 *
 * ★ 这是踩过的真实坑,值得单独说明:
 *   LLM 表达"这个字段没有值"时习惯输出 `null`(尤其是它认为该字段存在但为空时)。
 *   而 zod 的 `.optional()` 只接受 `undefined`,收到 `null` 会直接判为类型错误。
 *   结果就是:模型返回的意图**完全正确**,却因为一堆 `"rawExpression": null`
 *   被 Schema 全部拒绝,系统回复"我没能理解你的意思" —— 演示时全盘失效。
 *
 *   为什么用归一化而不是放宽 Schema:
 *     把每个字段都写成 `.nullable().optional()` 会让 Schema 变成噪音,
 *     也让"必填"与"可选"的边界模糊 —— 而这道边界是防幻觉的第一道闸门。
 *     归一化只做一件事:把 JSON 语义上的"空"统一为 TypeScript 语义上的"无"。
 *     这不是"猜测性修复",因为它不改变任何有值字段;缺必填依然会被拒绝。
 */
export function nullsToUndefined(value: unknown): unknown {
  if (value === null) return undefined;
  if (Array.isArray(value)) {
    return value.map((v) => {
      const n = nullsToUndefined(v);
      return n === undefined ? null : n; // 数组元素保留 null,避免改变数组长度语义
    });
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const normalized = nullsToUndefined(v);
      if (normalized !== undefined) out[k] = normalized;
    }
    return out;
  }
  return value;
}

/**
 * 结构化输出辅助:要求模型返回 JSON 并用 zod 校验。
 *
 * 这是"防幻觉"的第一道工程闸门 —— 模型输出不合法直接拒绝,不做猜测性修复。
 * 唯一的例外是 null → undefined 的语义归一化(见 nullsToUndefined)。
 */
export async function completeStructured<T>(
  provider: LlmProvider,
  request: LlmCompletionRequest,
  schema: z.ZodType<T>,
  options?: { retries?: number },
): Promise<{ ok: true; value: T; raw: LlmCompletionResult } | { ok: false; error: string; raw?: LlmCompletionResult }> {
  const retries = options?.retries ?? 1;
  let lastError = "";
  let lastRaw: LlmCompletionResult | undefined;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const result = await provider.complete({
      ...request,
      responseFormat: "json_object",
      messages:
        attempt === 0
          ? request.messages
          : [
              ...request.messages,
              {
                role: "assistant" as const,
                content: lastRaw?.content?.slice(0, 800) ?? "",
              },
              {
                role: "user" as const,
                content:
                  `你上一次的输出无法通过校验,原因如下:\n${lastError}\n\n` +
                  `请修正后重新输出**完整**的 JSON 对象。特别注意:\n` +
                  `1. 不要使用 null 表示"没有值",直接省略该字段;\n` +
                  `2. 所有必填字段必须出现(尤其 restatedIntent);\n` +
                  `3. 只输出 JSON 本身,不要任何解释文字或 Markdown 代码块标记。`,
              },
            ],
    });
    lastRaw = result;

    const jsonText = extractJson(result.content);
    if (jsonText == null) {
      lastError = "未能从输出中提取到 JSON";
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText);
    } catch (err) {
      lastError = `JSON 解析失败:${(err as Error).message}`;
      continue;
    }

    // ★ 语义归一化:JSON 的 null → TypeScript 的 undefined
    const normalized = nullsToUndefined(parsed);

    const validated = schema.safeParse(normalized);
    if (!validated.success) {
      lastError = validated.error.issues
        .slice(0, 5)
        .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
        .join("; ");
      continue;
    }

    return { ok: true, value: validated.data, raw: result };
  }

  return { ok: false, error: lastError, raw: lastRaw };
}

/**
 * 从模型输出中稳健地提取 JSON。
 * 兼容:纯 JSON、```json 代码块、前后夹带解释文字的情况。
 */
export function extractJson(text: string): string | null {
  const trimmed = text.trim();
  if (trimmed.length === 0) return null;

  // 情况 1:本身就是合法 JSON
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const balanced = sliceBalanced(trimmed);
    if (balanced) return balanced;
  }

  // 情况 2:Markdown 代码块
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence?.[1]) {
    const inner = fence[1].trim();
    const balanced = sliceBalanced(inner);
    if (balanced) return balanced;
  }

  // 情况 3:夹带解释文字,定位第一个平衡的 {} 或 []
  const start = trimmed.search(/[{[]/);
  if (start >= 0) {
    const balanced = sliceBalanced(trimmed.slice(start));
    if (balanced) return balanced;
  }

  return null;
}

/** 从字符串开头截取第一个括号平衡的片段(正确处理字符串内的括号与转义) */
function sliceBalanced(text: string): string | null {
  const open = text[0];
  if (open !== "{" && open !== "[") return null;
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      if (inString) escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) return text.slice(0, i + 1);
    }
  }
  return null;
}
