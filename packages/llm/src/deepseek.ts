/**
 * DeepSeek 供应商实现(OpenAI 兼容接口)
 *
 * 安全要点:
 *   - API Key 仅存在于服务端进程内存,永不写入日志、审计或模型上下文。
 *   - 所有错误信息在返回前经过脱敏(防止 Key 随错误体泄漏)。
 *   - 超时与并发上限硬编码兜底,避免演示时被限流拖死。
 */

import type {
  LlmCompletionRequest,
  LlmCompletionResult,
  LlmMessage,
  LlmProvider,
  LlmToolCall,
} from "./provider.ts";

export interface DeepSeekConfig {
  apiKey: string;
  baseUrl?: string;
  model?: string;
  temperature?: number;
  timeoutMs?: number;
  maxTokens?: number;
}

const DEFAULT_BASE_URL = "https://api.deepseek.com";
const DEFAULT_MODEL = "deepseek-chat";

export class DeepSeekProvider implements LlmProvider {
  readonly name = "deepseek";
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly defaultTemperature: number;
  private readonly timeoutMs: number;
  private readonly defaultMaxTokens: number;

  constructor(config: DeepSeekConfig) {
    if (!config.apiKey || config.apiKey.trim().length === 0) {
      throw new Error("DeepSeek API Key 为空。请在 .env 中设置 DEEPSEEK_API_KEY,或设置 LLM_OFFLINE=1 使用离线模式。");
    }
    this.apiKey = config.apiKey.trim();
    // 归一化 base URL:去掉尾部斜杠;要求 https(除非显式本地地址)
    const raw = (config.baseUrl ?? DEFAULT_BASE_URL).trim().replace(/\/+$/, "");
    this.baseUrl = normalizeBaseUrl(raw);
    this.model = config.model ?? DEFAULT_MODEL;
    this.defaultTemperature = config.temperature ?? 0;
    this.timeoutMs = config.timeoutMs ?? 60_000;
    this.defaultMaxTokens = config.maxTokens ?? 2048;
  }

  async complete(request: LlmCompletionRequest): Promise<LlmCompletionResult> {
    const started = Date.now();

    const body: Record<string, unknown> = {
      model: this.model,
      messages: request.messages.map(toApiMessage),
      temperature: request.temperature ?? this.defaultTemperature,
      max_tokens: request.maxTokens ?? this.defaultMaxTokens,
      stream: false,
    };

    if (request.tools && request.tools.length > 0) {
      body["tools"] = request.tools.map((t) => ({
        type: "function",
        function: { name: t.name, description: t.description, parameters: t.parameters },
      }));
      if (request.toolChoice === "none") body["tool_choice"] = "none";
      else if (typeof request.toolChoice === "object") {
        body["tool_choice"] = { type: "function", function: { name: request.toolChoice.name } };
      } else {
        body["tool_choice"] = "auto";
      }
    }

    if (request.responseFormat === "json_object") {
      body["response_format"] = { type: "json_object" };
      // DeepSeek 要求 JSON 模式提示词中必须包含 "json" 字样
      const messages = body["messages"] as Array<Record<string, unknown>>;
      if (!messages.some((m) => typeof m["content"] === "string" && /json/i.test(m["content"] as string))) {
        messages.push({
          role: "user",
          content: "请以 JSON 格式输出结果(JSON only,不要任何额外文字)。",
        });
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      const e = err as Error;
      if (e.name === "AbortError") {
        throw new Error(`DeepSeek 请求超时(${this.timeoutMs}ms)。可临时设置 LLM_OFFLINE=1 使用离线模式。`);
      }
      throw new Error(`DeepSeek 网络请求失败:${sanitize(e.message)}`);
    } finally {
      clearTimeout(timer);
    }

    const rawText = await response.text();

    if (!response.ok) {
      throw new Error(describeHttpError(response.status, rawText));
    }

    let payload: unknown;
    try {
      payload = JSON.parse(rawText);
    } catch {
      throw new Error(`DeepSeek 返回内容无法解析为 JSON:${sanitize(rawText.slice(0, 200))}`);
    }

    const choice = (payload as DeepSeekChatResponse).choices?.[0];
    if (!choice) throw new Error("DeepSeek 返回了空的 choices,请稍后重试。");

    const toolCalls: LlmToolCall[] = (choice.message.tool_calls ?? []).map((tc) => ({
      id: tc.id,
      name: tc.function.name,
      arguments: tc.function.arguments,
    }));

    const usage = (payload as DeepSeekChatResponse).usage;

    return {
      content: choice.message.content ?? "",
      toolCalls,
      usage: {
        promptTokens: usage?.prompt_tokens ?? 0,
        completionTokens: usage?.completion_tokens ?? 0,
        totalTokens: usage?.total_tokens ?? 0,
      },
      model: (payload as DeepSeekChatResponse).model ?? this.model,
      finishReason: choice.finish_reason ?? "stop",
      latencyMs: Date.now() - started,
    };
  }

  async ping(): Promise<{ ok: boolean; latencyMs: number; detail?: string }> {
    const started = Date.now();
    try {
      const result = await this.complete({
        messages: [
          { role: "system", content: "你是连通性测试。只回复 OK。" },
          { role: "user", content: "ping" },
        ],
        maxTokens: 8,
        temperature: 0,
      });
      return {
        ok: true,
        latencyMs: Date.now() - started,
        detail: `model=${result.model} finish=${result.finishReason} tokens=${result.usage.totalTokens}`,
      };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - started, detail: (err as Error).message };
    }
  }
}

// ============================================================================
// 内部工具
// ============================================================================

interface DeepSeekChatResponse {
  model?: string;
  choices?: Array<{
    message: {
      content?: string | null;
      tool_calls?: Array<{
        id: string;
        type: "function";
        function: { name: string; arguments: string };
      }>;
    };
    finish_reason?: string;
  }>;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

function toApiMessage(m: LlmMessage): Record<string, unknown> {
  const out: Record<string, unknown> = { role: m.role, content: m.content };
  if (m.toolCalls && m.toolCalls.length > 0) {
    out["tool_calls"] = m.toolCalls.map((tc) => ({
      id: tc.id,
      type: "function",
      function: { name: tc.name, arguments: tc.arguments },
    }));
  }
  if (m.toolCallId) out["tool_call_id"] = m.toolCallId;
  if (m.name) out["name"] = m.name;
  return out;
}

function normalizeBaseUrl(url: string): string {
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?/.test(url);
  if (!url.startsWith("https://") && !isLocal) {
    throw new Error(`DEEPSEEK_BASE_URL 必须使用 https(收到的值不是 https 也不是本地地址):${url.slice(0, 40)}`);
  }
  return url;
}

/**
 * 把 HTTP 错误翻译成人能看懂的话。
 * **绝不回显响应体原文**,因为它可能包含请求头回显等敏感信息。
 * ★ `_bodyText` 收下但刻意不用:它就是"我们拿到了原文,但不往外说"这件事的落点。
 */
function describeHttpError(status: number, _bodyText: string): string {
  const hint = ((): string => {
    switch (status) {
      case 401:
        return "API Key 无效。请检查 .env 中 DEEPSEEK_API_KEY 是否正确、前后无空格、无引号。";
      case 402:
        return "账户余额不足。请到 DeepSeek 平台充值。";
      case 403:
        return "访问被拒绝。请确认该 Key 有调用权限。";
      case 404:
        return "接口地址不存在。请确认 DEEPSEEK_BASE_URL=https://api.deepseek.com";
      case 422:
        return "请求参数不被接受。可能是模型名错误,请确认 DEEPSEEK_MODEL=deepseek-chat。";
      case 429:
        return "触发限流。请稍后重试,或临时设置 LLM_OFFLINE=1。";
      default:
        return status >= 500 ? "DeepSeek 服务端异常,请稍后重试。" : "请求失败。";
    }
  })();
  return `DeepSeek API 返回 ${status}:${hint}`;
}

/** 脱敏:移除任何形似 API Key 的片段与 Bearer 令牌 */
function sanitize(text: string): string {
  return text
    .replace(/sk-[A-Za-z0-9_-]{8,}/g, "sk-***REDACTED***")
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer ***REDACTED***");
}
