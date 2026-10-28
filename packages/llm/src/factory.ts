/**
 * 模型供应商工厂
 *
 * 依据环境变量选择实现:
 *   LLM_OFFLINE=1 或未配置 DEEPSEEK_API_KEY → DeterministicProvider(离线确定性解析)
 *   否则 → DeepSeekProvider
 *
 * 离线模式不是"功能缺失",而是**可演示性保障**:
 * 现场网络不可控,一键切换后整条链路依然完整跑通。
 */

import { DeepSeekProvider, type DeepSeekConfig } from "./deepseek.ts";
import { DeterministicProvider } from "./deterministic.ts";
import type { LlmProvider } from "./provider.ts";

export interface LlmRuntimeConfig {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
  temperature?: number;
  timeoutMs?: number;
  offline: boolean;
}

export function readLlmConfigFromEnv(env: NodeJS.ProcessEnv = process.env): LlmRuntimeConfig {
  const apiKey = env["DEEPSEEK_API_KEY"]?.trim();
  const offlineFlag = (env["LLM_OFFLINE"] ?? "").trim();
  const offline = offlineFlag === "1" || offlineFlag.toLowerCase() === "true";

  return {
    apiKey: apiKey && apiKey.length > 0 ? apiKey : undefined,
    baseUrl: env["DEEPSEEK_BASE_URL"]?.trim() || undefined,
    model: env["DEEPSEEK_MODEL"]?.trim() || undefined,
    temperature: env["DEEPSEEK_TEMPERATURE"] ? Number(env["DEEPSEEK_TEMPERATURE"]) : undefined,
    timeoutMs: env["DEEPSEEK_TIMEOUT_MS"] ? Number(env["DEEPSEEK_TIMEOUT_MS"]) : undefined,
    offline,
  };
}

export interface LlmSelection {
  provider: LlmProvider;
  mode: "deepseek" | "offline";
  /** 选择原因,用于启动日志与答辩说明 */
  reason: string;
}

export function selectLlmProvider(config: LlmRuntimeConfig): LlmSelection {
  if (config.offline) {
    return {
      provider: new DeterministicProvider(),
      mode: "offline",
      reason: "LLM_OFFLINE=1,已强制启用离线确定性解析器(演示兜底路径)",
    };
  }
  if (!config.apiKey) {
    return {
      provider: new DeterministicProvider(),
      mode: "offline",
      reason: "未配置 DEEPSEEK_API_KEY,自动回退到离线确定性解析器。填入 .env 后即可启用真实模型。",
    };
  }
  const dsConfig: DeepSeekConfig = {
    apiKey: config.apiKey,
    ...(config.baseUrl ? { baseUrl: config.baseUrl } : {}),
    ...(config.model ? { model: config.model } : {}),
    ...(config.temperature != null ? { temperature: config.temperature } : {}),
    ...(config.timeoutMs != null ? { timeoutMs: config.timeoutMs } : {}),
  };
  return {
    provider: new DeepSeekProvider(dsConfig),
    mode: "deepseek",
    reason: `已连接 DeepSeek(${config.model ?? "deepseek-chat"})`,
  };
}

export * from "./provider.ts";
export * from "./deepseek.ts";
export * from "./deterministic.ts";
