/**
 * 任务规划器(Task Planner)—— 复杂任务拆解为有序子任务 DAG
 *
 * ★ 对应技术要求:"复杂任务需拆解为有序的子任务 DAG(有向无环图);
 *   执行过程中支持中断、回退和人工接管。"
 *
 * 设计要点与取舍:
 *
 * 1. **模型只输出意图序列,不输出执行细节。**
 *    模型给的是"用户想按这个顺序做这几件事";DAG 的节点、依赖、补偿策略
 *    由本模块确定性地推导。模型不参与拓扑设计 —— 否则它可以通过构造
 *    畸形依赖(如让"转账"依赖"查询余额"之后再偷偷加一个节点)绕过审查。
 *
 * 2. **每个副作用节点独立裁决。**
 *    对应不变量 I5:不继承前置节点的许可。多步任务的每一步都要单独过策略引擎,
 *    不能"用户确认了整个计划"就一路绿灯。
 *
 * 3. **资金操作逐笔确认,不打包确认。**
 *    这是刻意的体验取舍:一次性确认三笔转账确实更"流畅",
 *    但它把三笔独立的资金操作合并成了一次授权 —— 用户对第三笔的注意力
 *    必然远低于第一笔。真实银行不会这么做。
 *    非资金操作(查询/分析)可以自动执行,不打断用户。
 *
 * 4. **回退(补偿)按节点声明式定义。**
 *    每个副作用节点可以带 compensateWith,失败时由执行器调用它做反向操作。
 *    没有补偿动作的节点,失败时进入"需人工接管"状态而不是假装成功。
 */

import type { AuditPort, ExecutionContext } from "../types.ts";

// ============================================================================
// 计划结构
// ============================================================================

export interface PlannedStep {
  /** 稳定节点 ID,如 n1 / n2 */
  nodeId: string;
  /** 能力名 */
  capability: string;
  /** 面向用户的一句话描述,如"给老妈转 2000 元(生活费)" */
  label: string;
  /** 该节点的入参(尚未注入风险信号) */
  input: Record<string, unknown>;
  /** 依赖的节点 ID */
  dependsOn: string[];
  /** 是否涉及资金(决定是否需要用户逐笔确认) */
  moneyMovement: boolean;
  /** 是否为只读步骤(不改变状态,因此可与其他步骤并行,也不打断副作用链) */
  readOnly: boolean;
  /** 该节点失败时的处理 */
  onFailure: "abort" | "continue" | "compensate";
  /** 补偿方案 */
  compensateWith?: { capability: string; input: Record<string, unknown> };
  /** 执行状态 */
  status: "pending" | "running" | "succeeded" | "failed" | "skipped" | "compensated" | "awaiting_confirm";
  /** 执行结果摘要 */
  resultSummary?: string;
  /**
   * ★ 执行结果数据(第 3 项:让**跨轮次**的补偿能解析 $ref)。
   *
   * 为什么必须把它挂在节点上:计划是跨轮次共享的 —— 第一步在"验证"那一轮执行成功,
   * 客户下一轮才说"取消"。此时 rollback 要撤销第一步,靠的是
   * `$n1.transferId` 这样的引用,而引用值只存在于**当初那次执行的返回值**里。
   *
   * 踩过的坑(实测):只在单次 runPlan 内的内存 Map 里缓存输出,
   * 跨轮次回退时 $ref 必然解析失败 —— 结果是"钱已经转出去,补偿却跳过,
   * 标记需人工处理"。审计上看起来"如实",但客户的钱没有自己回来。
   * 因此输出必须随节点一起留在计划对象上。
   */
  resultData?: Record<string, unknown>;
  /** 失败原因 */
  error?: string;
}

export interface ExecutionPlan {
  planId: string;
  /** 对整句话的复述 */
  restatedIntent: string;
  steps: PlannedStep[];
  createdAt: number;
  status: "draft" | "running" | "paused" | "completed" | "aborted" | "awaiting_handoff";
  /** 当前执行到哪个节点 */
  cursor: number;
}

// ============================================================================
// 计划构造与校验
// ============================================================================

export class PlanError extends Error {
  readonly kind: "cycle" | "missing_dependency" | "empty" | "duplicate_id";

  constructor(message: string, kind: "cycle" | "missing_dependency" | "empty" | "duplicate_id") {
    super(message);
    this.name = "PlanError";
    this.kind = kind;
  }
}

/**
 * 校验并归一化计划。
 *
 * ★ 为什么必须校验:依赖关系是"模型影响执行顺序"的唯一入口。
 *   如果模型能构造出一个环,执行器就会死循环;
 *   如果能引用不存在的节点,执行器就会空转。
 *   这些都不能靠模型自觉 —— 必须在确定性代码里检查。
 */
export function validatePlan(steps: PlannedStep[]): void {
  if (steps.length === 0) throw new PlanError("计划为空", "empty");

  const ids = new Set<string>();
  for (const s of steps) {
    if (ids.has(s.nodeId)) throw new PlanError(`节点 ID 重复:${s.nodeId}`, "duplicate_id");
    ids.add(s.nodeId);
  }

  for (const s of steps) {
    for (const dep of s.dependsOn) {
      if (!ids.has(dep)) {
        throw new PlanError(`节点 ${s.nodeId} 依赖了不存在的节点 ${dep}`, "missing_dependency");
      }
      if (dep === s.nodeId) {
        throw new PlanError(`节点 ${s.nodeId} 依赖自身`, "cycle");
      }
    }
  }

  // 拓扑检测:用 Kahn 算法判断是否存在环
  const indegree = new Map<string, number>();
  const adjacency = new Map<string, string[]>();
  for (const s of steps) {
    indegree.set(s.nodeId, s.dependsOn.length);
    adjacency.set(s.nodeId, []);
  }
  for (const s of steps) {
    for (const dep of s.dependsOn) {
      adjacency.get(dep)!.push(s.nodeId);
    }
  }

  const queue = [...indegree.entries()].filter(([, d]) => d === 0).map(([id]) => id);
  let visited = 0;
  while (queue.length > 0) {
    const id = queue.shift()!;
    visited++;
    for (const next of adjacency.get(id) ?? []) {
      const d = (indegree.get(next) ?? 1) - 1;
      indegree.set(next, d);
      if (d === 0) queue.push(next);
    }
  }
  if (visited !== steps.length) {
    throw new PlanError("计划中存在循环依赖,不是合法的 DAG", "cycle");
  }
}

/** 计算可执行的顺序(拓扑序;同层按原始顺序保持稳定) */
export function topologicalOrder(steps: PlannedStep[]): PlannedStep[] {
  const byId = new Map(steps.map((s) => [s.nodeId, s]));
  const indegree = new Map<string, number>();
  const adjacency = new Map<string, string[]>();
  for (const s of steps) {
    indegree.set(s.nodeId, s.dependsOn.length);
    adjacency.set(s.nodeId, []);
  }
  for (const s of steps) {
    for (const dep of s.dependsOn) adjacency.get(dep)!.push(s.nodeId);
  }

  const ready: string[] = [];
  for (const s of steps) {
    if ((indegree.get(s.nodeId) ?? 0) === 0) ready.push(s.nodeId);
  }

  const order: PlannedStep[] = [];
  while (ready.length > 0) {
    const id = ready.shift()!;
    order.push(byId.get(id)!);
    for (const next of adjacency.get(id) ?? []) {
      const d = (indegree.get(next) ?? 1) - 1;
      indegree.set(next, d);
      if (d === 0) ready.push(next);
    }
  }
  return order;
}

// ============================================================================
// 多意图 → 计划
// ============================================================================

/**
 * 由模型输出的意图序列构造执行计划。
 *
 * ★ 依赖关系的推导规则(这一条踩过坑,值得完整说明):
 *
 *   规则:**每一个有副作用的步骤,都依赖它前面那个有副作用的步骤。**
 *   只有纯只读操作(查询/分析)不依赖任何人,可以自由穿插。
 *
 *   为什么不是"只有资金操作串行":
 *     早期版本只让资金操作两两串行,AA 收款被当作非资金操作,于是它没有依赖。
 *     用户说"先给老妈转 2000,再给房东转 5800,然后 AA 团建费 1800",
 *     结果执行顺序变成 [转老妈] → [AA 收款] → [转房东] ——
 *     因为第一步暂停等确认时,没有依赖约束的 AA 步骤被拓扑排序提前了。
 *
 *     更糟的是它**看起来是成功的**:三步都打了 ✅,只是顺序与用户表述不符。
 *     用户以为按顺序办了,实际上 AA 在房租之前就发出去了。
 *
 *   为什么这让 DAG 仍然有意义:
 *     只读步骤(查余额、分析账单)确实可以和资金步骤并行 ——
 *     它们不改变状态,不会因为顺序不同产生不同结果。
 *     所以"只读自由、副作用串行"既保持了并发空间,又保证了用户表述的顺序语义。
 */
export function buildPlan(input: {
  restatedIntent: string;
  intents: Array<{
    capability: string;
    label: string;
    input: Record<string, unknown>;
    moneyMovement: boolean;
    /** 是否为只读步骤(不改变任何状态) */
    readOnly: boolean;
  }>;
  now: number;
}): ExecutionPlan {
  const steps: PlannedStep[] = [];
  let lastSideEffectNodeId: string | null = null;

  input.intents.forEach((it, idx) => {
    const nodeId = `n${idx + 1}`;
    const dependsOn: string[] = [];

    if (it.readOnly) {
      // 只读步骤:不依赖、也不被依赖(它是纯观察,不改变状态)
      // 但它**不打断**副作用链 —— 所以不更新 lastSideEffectNodeId。
    } else if (lastSideEffectNodeId) {
      // 有副作用的步骤必须串行,保持用户表述的顺序
      dependsOn.push(lastSideEffectNodeId);
    }

    steps.push({
      nodeId,
      capability: it.capability,
      label: it.label,
      input: it.input,
      dependsOn,
      moneyMovement: it.moneyMovement,
      readOnly: it.readOnly,
      // 副作用步骤失败即中止后续 —— 继续执行会让用户以为整批都完成了
      onFailure: it.readOnly ? "continue" : "abort",
      status: "pending",
    });

    if (!it.readOnly) lastSideEffectNodeId = nodeId;
  });

  validatePlan(steps);

  return {
    planId: `plan_${Math.random().toString(36).slice(2, 12)}`,
    restatedIntent: input.restatedIntent,
    steps,
    createdAt: input.now,
    status: "draft",
    cursor: 0,
  };
}

// ============================================================================
// 计划摘要(用于展示给用户)
// ============================================================================

export interface PlanPreview {
  /** 总步数 */
  total: number;
  /** 涉及资金的步数 */
  moneySteps: number;
  /** 需要用户逐笔确认的次数 */
  confirmationsRequired: number;
  /** 逐条人话描述 */
  lines: string[];
  /** 面向用户的整体说明 */
  summary: string;
}

export function previewPlan(plan: ExecutionPlan): PlanPreview {
  const moneySteps = plan.steps.filter((s) => s.moneyMovement).length;

  const lines = plan.steps.map((s, i) => {
    const tag = s.moneyMovement ? "需确认" : "查询";
    return `  ${i + 1}. [${tag}] ${s.label}`;
  });

  const parts: string[] = [];
  parts.push(`已识别 ${plan.steps.length} 项待办:`);
  parts.push(...lines);

  const summary =
    moneySteps > 0
      ? `其中 ${moneySteps} 笔涉及资金,将逐笔确认;其余 ${plan.steps.length - moneySteps} 笔为查询,可直接办理。`
      : `以上均为查询,将直接办理。`;

  return {
    total: plan.steps.length,
    moneySteps,
    confirmationsRequired: moneySteps,
    lines,
    summary,
  };
}

// ============================================================================
// 执行器(含中断与回退)
// ============================================================================

/** 单节点执行函数(由编排器注入,内部会走完整的裁决-确认-执行链路) */
export type StepExecutor = (
  step: PlannedStep,
  ctx: ExecutionContext,
) => Promise<{
  ok: boolean;
  summary?: string;
  /** 执行结果数据。用于补偿参数的 $ref 解析(如 transferId) */
  data?: unknown;
  error?: string;
  /** 是否需要用户交互(确认/验证)。若为真,执行暂停,等待下一轮 */
  needsUserAction?: boolean;
  /** 用户交互类型 */
  promptKind?: "confirm" | "strong_auth" | "clarify";
  /**
   * ★ 提交点之前被取消(第 3 项)。
   *
   * 它**既不是失败也不是成功**:这一步什么都没做(余额、流水、回执一个字节没动)。
   * 与"失败"混为一谈会让审计和台账以为钱可能动过 —— 那是必须避免的误导。
   */
  cancelled?: { op: string; preparedId: string; phase: string; reason: string; source?: string };
}>;

/** 补偿执行函数(回退) */
export type Compensator = (
  step: PlannedStep,
  ctx: ExecutionContext,
) => Promise<{ ok: boolean; summary?: string }>;

// ============================================================================
// 补偿参数解析($ref 引用)
// ============================================================================

/** 节点执行结果缓存:用于把 `$n1.transferId` 解析成真实值 */
export type NodeOutputs = Map<string, Record<string, unknown>>;

/**
 * 解析补偿参数里的 `$ref` 引用。
 *
 * ★ 为什么需要它:回退一个多步计划时,"撤销第一笔转账"这个动作
 *   需要知道第一笔的 `transferId` —— 而这个值只有在它执行**成功之后**才存在。
 *   计划是事先构造的,不可能预知 ID,所以必须用引用形式表达。
 *
 * 支持的语法:
 *   "$n1.transferId"            → 取 n1 输出的 transferId
 *   "$n1.receipt.reference"     → 支持一层嵌套
 *   { "$ref": "n1.transferId" } → 显式对象形式(与字符串形式等价)
 *
 * 设计约束:
 *   - 解析失败时**返回 undefined 并让补偿失败**,而不是猜一个值。
 *     回退动作用错参数比不执行更危险(可能撤销错误的转账)。
 *   - 只允许引用**已成功执行过**的节点输出。这条由调用时机保证
 *     (回退只对 succeeded 节点执行补偿,而被引用的前置节点必然已成功)。
 */
export function resolveRefs(
  input: Record<string, unknown>,
  outputs: NodeOutputs,
): { ok: true; value: Record<string, unknown> } | { ok: false; missing: string } {
  const out: Record<string, unknown> = {};

  for (const [key, raw] of Object.entries(input)) {
    // 显式对象形式
    if (raw && typeof raw === "object" && !Array.isArray(raw) && "$ref" in (raw as object)) {
      const refValue = (raw as { $ref: unknown })["$ref"];
      if (typeof refValue !== "string") return { ok: false, missing: `${key}: $ref 必须是字符串` };
      const resolved = resolveOne(refValue, outputs);
      if (!resolved.ok) return { ok: false, missing: `${key} → ${resolved.missing}` };
      out[key] = resolved.value;
      continue;
    }

    // 字符串形式
    if (typeof raw === "string" && raw.startsWith("$")) {
      const resolved = resolveOne(raw.slice(1), outputs);
      if (!resolved.ok) return { ok: false, missing: `${key} → ${resolved.missing}` };
      out[key] = resolved.value;
      continue;
    }

    // 嵌套对象递归处理
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      const nested = resolveRefs(raw as Record<string, unknown>, outputs);
      if (!nested.ok) return { ok: false, missing: `${key}.${nested.missing}` };
      out[key] = nested.value;
      continue;
    }

    out[key] = raw;
  }

  return { ok: true, value: out };
}

function resolveOne(
  path: string,
  outputs: NodeOutputs,
): { ok: true; value: unknown } | { ok: false; missing: string } {
  const dot = path.indexOf(".");
  if (dot < 0) return { ok: false, missing: `引用格式应为 nodeId.field,收到 "${path}"` };

  const nodeId = path.slice(0, dot);
  const fieldPath = path.slice(dot + 1).split(".");

  const nodeOutput = outputs.get(nodeId);
  if (!nodeOutput) return { ok: false, missing: `节点 ${nodeId} 没有可用的输出(未成功执行?)` };

  let cursor: unknown = nodeOutput;
  for (const f of fieldPath) {
    if (cursor == null || typeof cursor !== "object") {
      return { ok: false, missing: `节点 ${nodeId} 的输出里找不到 ${fieldPath.join(".")}` };
    }
    cursor = (cursor as Record<string, unknown>)[f];
    if (cursor === undefined) {
      return { ok: false, missing: `节点 ${nodeId} 的输出里缺少字段 ${f}` };
    }
  }
  return { ok: true, value: cursor };
}

export interface PlanRunResult {
  plan: ExecutionPlan;
  /** 实际执行的节点 */
  executed: Array<{ nodeId: string; label: string; ok: boolean; summary?: string; error?: string }>;
  /** 补偿(回退)记录 */
  compensations: Array<{ nodeId: string; ok: boolean; summary?: string }>;
  /** 是否需要用户交互(用于暂停) */
  awaiting?: { nodeId: string; kind: "confirm" | "strong_auth" | "clarify" };
  /** 是否被中断 */
  interrupted?: boolean;
  /**
   * ★ 被中断的具体原因(第 3 项)。
   *
   * `interrupted` 只说"停了",说不出"停在哪一侧"。而提交点前后的差别是
   * **钱有没有动**:之前 = 什么都没发生,之后 = 已提交、已走补偿。
   * 这不是措辞问题,对账时要靠它。
   */
  cancellation?: { op: string; preparedId: string; phase: string; reason: string; source?: string };
  /** 是否需人工接管 */
  handoffRequired?: boolean;
}

/**
 * 执行计划。
 *
 * 中断与回退的语义:
 *   - **中断**:ctx 未提供 cancel 信号时按顺序执行;若某个节点返回 needsUserAction,
 *     计划进入 paused 状态并返回 awaiting,由编排器在下一轮从断点继续。
 *     用户说"取消"则整个计划终止,已完成的副作用节点按补偿策略回退。
 *   - **回退**:仅对声明了 compensateWith 的节点执行补偿。
 *     没有补偿方案的节点**不回退也不假装成功** —— 标记为 failed 并进入人工接管。
 *     这是诚实的设计:不能把"转出去的钱"假装退回来。
 */
export async function runPlan(input: {
  plan: ExecutionPlan;
  ctx: ExecutionContext;
  executeStep: StepExecutor;
  compensate?: Compensator;
  /** 中断信号:返回 true 表示应停止执行 */
  shouldInterrupt?: () => boolean;
}): Promise<PlanRunResult> {
  const { plan, ctx, executeStep, compensate, shouldInterrupt } = input;

  const executed: PlanRunResult["executed"] = [];
  const compensations: PlanRunResult["compensations"] = [];
  /** 节点输出缓存:供补偿参数的 $ref 解析使用 */
  const outputs: NodeOutputs = new Map();

  /**
   * ★ 先把**上一轮已经成功**的节点输出装回缓存(第 3 项)。
   *
   * 计划跨轮次共享:第一步可能在上一次 runPlan(确认/验证那一轮)就执行完了。
   * 本轮 rollback 若要撤销它,必须能解析 `$n1.transferId` —— 而那个值
   * 只留在 step.resultData 里。不装回来的话,补偿会以
   * "引用无法解析"被跳过并转人工:钱出去了,却没有任何自动动作。
   */
  for (const s of plan.steps) {
    if (s.resultData && (s.status === "succeeded" || s.status === "compensated")) {
      outputs.set(s.nodeId, s.resultData);
    }
  }

  plan.status = "running";
  const order = topologicalOrder(plan.steps);

  for (const step of order) {
    // ---- ★ 幂等:已成功的节点绝不重跑 ----
    // 计划对象跨轮次共享(在"等待用户确认"处暂停、下一轮继续),
    // 因此每次 runPlan 都会遍历全部节点。已经成功的节点必须直接跳过 ——
    // 否则一次"确认"就会把钱再转一遍。这不是理论风险:
    // 测试中真的出现过同一笔「给老妈转2000」转出两次、两个不同流水号。
    // 同时它也不进 executed 列表,避免把上一轮的结果当成这一轮的结果汇报。
    if (step.status === "succeeded") continue;

    // ---- 中断检查(每个节点之前) ----
    if (shouldInterrupt?.()) {
      plan.status = "aborted";
      /**
       * ★ 被中断时,把**还没走到的节点**如实标成"跳过"。
       *
       *   不标的话,计划里会留下一批 `awaiting_confirm`/`pending` 的节点 ——
       *   计划状态是 aborted、却又有节点显示"正在等你确认",读审计的人
       *   无法一眼看出"这步到底有没有发生"。而"哪几步真的动过钱"正是
       *   提交点这件事最不能含糊的地方。
       *   注意:已成功/已补偿/已失败的节点保持原状 —— 它们的结局是事实。
       */
      for (const s of order) {
        if (s.status === "succeeded" || s.status === "compensated" || s.status === "failed") continue;
        s.status = "skipped";
        s.error = "计划已取消,这一步没有执行(余额与账户状态没有任何变化)";
      }
      await rollback(order, compensate, ctx, compensations, plan, outputs);
      return { plan, executed, compensations, interrupted: true };
    }

    // ---- 依赖未成功则跳过 ----
    const unmetDependency = step.dependsOn.find((dep) => {
      const d = plan.steps.find((s) => s.nodeId === dep);
      // ★ 关键:依赖节点必须"成功"才算满足。失败或跳过都不满足 ——
      //   否则"前一笔转账失败了,后一笔照转"这种事就会发生。
      //
      //   但这里有一个必须处理的边界:**依赖节点正在等待用户确认时**,
      //   不能算作"未满足"而直接跳过 —— 它只是暂停了,不是失败了。
      //   早期版本漏了这个判断,导致"计划在第 1 步暂停,用户确认后
      //   第 2 步被当成'前置未成功'直接跳过",钱少转了却显示成功。
      if (!d) return true;
      if (d.status === "succeeded") return false;
      if (d.status === "awaiting_confirm") return false; // 暂停中,不算失败
      return true;
    });
    if (unmetDependency && step.status !== "awaiting_confirm") {
      // 若前置步骤仍在等待确认,则本轮也应保持等待,而不是跳过
      const dep = plan.steps.find((s) => s.nodeId === unmetDependency);
      if (dep?.status === "awaiting_confirm") {
        plan.status = "paused";
        return {
          plan,
          executed,
          compensations,
          awaiting: { nodeId: dep.nodeId, kind: "confirm" },
        };
      }
      step.status = "skipped";
      step.error = `前置步骤 ${unmetDependency} 未成功完成`;
      executed.push({ nodeId: step.nodeId, label: step.label, ok: false, error: step.error });
      plan.status = "aborted";
      await rollback(order, compensate, ctx, compensations, plan, outputs);
      return { plan, executed, compensations };
    }

    // ---- 执行 ----
    step.status = "running";
    const outcome = await executeStep(step, ctx);

    /**
     * ★ 提交点之前被取消(第 3 项)。
     *
     * 发生在这里说明:银行核心在**动账那一行之前**读到了取消信号,于是干净退出。
     * 于是这一步什么都没做 —— 因此:
     *   · 它不记 failed(那会暗示"试着做了、可能改了状态");
     *   · 整个计划立即中止,并按补偿策略回退**已经成功**的节点
     *     (那些节点是真的提交过了,只能补偿,不能假装没发生)。
     * 这就是"取消只在提交点之前有效,提交点之后只能补偿"在计划层的落点。
     */
    if (outcome.cancelled) {
      step.status = "skipped";
      // ★ 对客文案:reason 可能来自上游("timeout"等),不回显;完整值在审计链里
      step.error = "已取消,这一步没有执行(未产生任何副作用)";
      executed.push({ nodeId: step.nodeId, label: step.label, ok: false, error: step.error });
      plan.status = "aborted";
      await rollback(order, compensate, ctx, compensations, plan, outputs);
      return { plan, executed, compensations, interrupted: true, cancellation: outcome.cancelled };
    }

    if (outcome.needsUserAction) {
      // 需要用户确认/验证 → 暂停,保留游标,下一轮继续
      step.status = "awaiting_confirm";
      plan.status = "paused";
      plan.cursor = order.indexOf(step);
      return {
        plan,
        executed,
        compensations,
        awaiting: { nodeId: step.nodeId, kind: outcome.promptKind ?? "confirm" },
      };
    }

    if (outcome.ok) {
      step.status = "succeeded";
      step.resultSummary = outcome.summary;
      if (outcome.data && typeof outcome.data === "object") {
        // ★ 同时留在节点上:跨轮次的补偿要靠它解析 $ref(见 resultData 注释)
        step.resultData = outcome.data as Record<string, unknown>;
        outputs.set(step.nodeId, outcome.data as Record<string, unknown>);
      }
      executed.push({ nodeId: step.nodeId, label: step.label, ok: true, ...(outcome.summary ? { summary: outcome.summary } : {}) });
      continue;
    }

    // ---- 失败处理 ----
    step.status = "failed";
    step.error = outcome.error;
    executed.push({
      nodeId: step.nodeId,
      label: step.label,
      ok: false,
      ...(outcome.error ? { error: outcome.error } : {}),
    });

    if (step.onFailure === "abort") {
      plan.status = "aborted";
      await rollback(order, compensate, ctx, compensations, plan, outputs);
      return { plan, executed, compensations };
    }

    if (step.onFailure === "compensate") {
      if (compensate && step.compensateWith) {
        const r = await compensate(step, ctx);
        compensations.push({ nodeId: step.nodeId, ok: r.ok, ...(r.summary ? { summary: r.summary } : {}) });
        step.status = r.ok ? "compensated" : "failed";
      } else {
        // 没有补偿方案 → 不假装成功,转人工
        plan.status = "awaiting_handoff";
        return { plan, executed, compensations, handoffRequired: true };
      }
    }
    // onFailure === "continue":记录失败,继续后续
  }

  plan.status = "completed";
  return { plan, executed, compensations };
}

/** 回退已成功的节点(逆序补偿) */
async function rollback(
  order: PlannedStep[],
  compensate: Compensator | undefined,
  ctx: ExecutionContext,
  compensations: PlanRunResult["compensations"],
  plan: ExecutionPlan,
  outputs: NodeOutputs,
): Promise<void> {
  if (!compensate) return;

  // 逆序回退:后发生的先撤销
  const succeeded = order
    .filter((s) => s.status === "succeeded" || s.status === "compensated")
    .reverse();

  for (const step of succeeded) {
    if (!step.compensateWith) {
      // 没有补偿方案的节点:如实标记,不静默跳过
      compensations.push({
        nodeId: step.nodeId,
        ok: false,
        summary: "该步骤没有定义补偿方案,无法自动回退,需人工处理",
      });
      continue;
    }

    // ★ 解析补偿参数里的 $ref(如撤销第一笔转账需要它的 transferId)
    const resolved = resolveRefs(step.compensateWith.input, outputs);
    if (!resolved.ok) {
      // 引用解析失败 → 补偿**不执行**,如实标记需人工。
      // 用错参数去撤销转账比不撤销更危险(可能撤销了错误的那一笔)。
      compensations.push({
        nodeId: step.nodeId,
        ok: false,
        summary: `补偿参数引用无法解析(${resolved.missing}),为避免误操作已跳过自动回退,需人工处理`,
      });
      continue;
    }

    const r = await compensate({ ...step, compensateWith: { ...step.compensateWith, input: resolved.value } }, ctx);
    compensations.push({ nodeId: step.nodeId, ok: r.ok, ...(r.summary ? { summary: r.summary } : {}) });
    if (r.ok) step.status = "compensated";
  }
  plan.status = "aborted";
}

// ============================================================================
// 审计辅助
// ============================================================================

export async function auditPlanEvent(
  audit: AuditPort,
  input: {
    traceId: string;
    step: string;
    plan: ExecutionPlan;
    detail?: Record<string, unknown>;
    ctx: { sessionId: string; customerId: string; channel: string; now: number };
  },
): Promise<void> {
  await audit.append({
    ts: input.ctx.now,
    traceId: input.traceId,
    sessionId: input.ctx.sessionId,
    customerId: input.ctx.customerId,
    channel: input.ctx.channel as never,
    type: "plan_created",
    payload: {
      stage: input.step,
      planId: input.plan.planId,
      status: input.plan.status,
      total: input.plan.steps.length,
      moneySteps: input.plan.steps.filter((s) => s.moneyMovement).length,
      steps: input.plan.steps.map((s) => ({
        nodeId: s.nodeId,
        capability: s.capability,
        label: s.label,
        dependsOn: s.dependsOn,
        moneyMovement: s.moneyMovement,
        status: s.status,
        ...(s.error ? { error: s.error } : {}),
        ...(s.resultSummary ? { resultSummary: s.resultSummary } : {}),
      })),
      ...(input.detail ?? {}),
    },
  });
}
