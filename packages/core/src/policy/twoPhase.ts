/**
 * ★ 第 3 项:提交点与取消 —— 两阶段执行的公共约定。
 *
 * 这套系统对"取消"的立场,可以用一句话说清:
 *
 *   **取消不是"随时把执行杀掉",而是"在提交点之前改主意"。**
 *
 * 为什么不能随便杀:资金操作被中途杀掉会留下最坏的一种状态 ——
 * "钱扣了,状态未知"。所以流程被切成三段,只允许两种结局:
 *
 *   ① prepare(零副作用) → 读取消信号 → 命中取消 → abort → **余额一个字节没动**
 *   ② prepare(零副作用) → 读取消信号 → 未命中 → commit(**唯一副作用点**)
 *      → commit 之后才来的取消 → 走已有的 compensateWith 补偿链路
 *
 * **不允许存在第三种状态**:既不是"半扣着",也不是"提交了但没人知道"。
 *
 * 为什么用"抛一个带类型的错误"把取消带回执行边界,而不是让每个能力自己判断:
 *   提交点只有银行核心知道。让 30 多个能力各自处理取消,必然有的漏、有的写错。
 *   所以取消在**执行边界**(编排器调用能力的那一处)统一转成 outcome:
 *   能力不需要知道取消的存在,编排器知道,审计知道。
 */
import type { OperationScope } from "../types.js";

/** 取消发生的阶段 */
export type CancellationPhase = "before_commit" | "after_commit";

/**
 * 提交前取消。**它不表示失败** —— 它表示"什么都没做",所以调用方
 * 绝不能把它当成 execution_failed 记,否则审计会说谎。
 */
export class OperationCancelledError extends Error {
  /** 用于跨模块实例识别(测试替身/多份依赖副本也不会误判) */
  readonly __bankOperationCancelled = true as const;
  readonly op: string;
  readonly preparedId: string;
  readonly phase: CancellationPhase;
  readonly reason: string;
  readonly source?: string;

  constructor(input: {
    op: string;
    preparedId: string;
    reason: string;
    source?: string;
    phase?: CancellationPhase;
  }) {
    super(`操作 ${input.op} 已在提交前取消:${input.reason}`);
    this.name = "OperationCancelledError";
    this.op = input.op;
    this.preparedId = input.preparedId;
    this.phase = input.phase ?? "before_commit";
    this.reason = input.reason;
    this.source = input.source;
  }
}

/** 判断任意抛出物是否为"提交前取消" */
export function isOperationCancelled(e: unknown): e is OperationCancelledError {
  return Boolean(
    e &&
      typeof e === "object" &&
      (e as { __bankOperationCancelled?: boolean }).__bankOperationCancelled === true,
  );
}

/**
 * 提交边界:决定"这一笔该不该提交"。
 *
 * ★ 它是**纯函数**,输入是取消意图快照 —— 这保证同一笔操作在任何时候
 *   用同一个快照判定都得到同一个结论(可回归、可复现)。
 *   真正的"杀不杀"从来不是在这里决定的,这里只回答一个问题:
 *   "提交点之前,客户是否已经改主意了?"
 */
export function decideAtCommitBoundary(
  scope: OperationScope | null | undefined,
): { abort: false } | { abort: true; reason: string; source?: string } {
  const c = scope?.cancellation;
  if (!c?.requested) return { abort: false };
  const reason = c.reason ?? "上游要求中止执行";
  return { abort: true, reason, ...(c.source ? { source: c.source } : {}) };
}

/** 审计用的取消详情(payload 形状固定,便于事后 grep) */
export function cancellationAuditPayload(input: {
  op: string;
  preparedId: string;
  reason: string;
  source?: string;
  scope?: OperationScope | null;
}): Record<string, unknown> {
  return {
    op: input.op,
    preparedId: input.preparedId,
    phase: "before_commit" as CancellationPhase,
    cause: input.source ?? "user",
    reason: input.reason,
    ...(input.scope?.planId ? { planId: input.scope.planId } : {}),
    ...(input.scope?.nodeId ? { nodeId: input.scope.nodeId } : {}),
    note: "提交点之前的干净中止:未扣款、未改状态,可安全重试。",
  };
}