/**
 * 受限专家(Specialists)—— "多 Agent"在本项目里的正确形态
 *
 * ★ 先说结论:本系统是**单控制面**的 Agent,不是自由协作的多 Agent 蜂群。
 *   主循环(orchestrator)是唯一的决策与执行入口;
 *   文档/账单这类分析工作交给**受限专家**,而不是交给会自己拿主意的第二个 Agent。
 *
 *   理由与全项目的立场一致:
 *     · **裁决不可外包。** 是否放行、要不要人脸、能不能转,必须由确定性策略引擎说,
 *       而策略引擎只有一个。让"另一个 Agent"参与裁决,审计就再也说不清是谁决定的。
 *     · **权限边界会扩散。** 多 Agent 最常见的事故不是"协作失败",而是
 *       "某个子 Agent 手里有它本不该有的工具"。它的权限一旦比主流程宽,
 *       攻击面就不再受主流程约束。
 *     · **可解释性下降。** 客户问"为什么说这笔异常",答案必须是一套规则 + 一条证据链,
 *       而不是"另一个模型也这么觉得"。
 *
 * ★ 那"多 Agent"能带来什么?两件真实的好处,这里都保留:
 *   ① **角色化的工具边界**:每个专家只有一组白名单能力,且**只能读**。
 *   ② **可审计的派发**:每一次"把活交给专家"都进审计(specialist_dispatched),
 *      事后能回答"这一步是谁做的、它当时能用哪些工具"。
 *
 *   也就是说:用多 Agent 的**结构**来收窄权限,而不用它的**自治性**来放松裁决。
 */

export interface SpecialistRole {
  id: string;
  /** 面向客户也面向审计的名字 */
  name: string;
  /** 职责说明 */
  purpose: string;
  /** 白名单:不在这个列表里的能力,专家一律调不动 */
  allowedCapabilities: string[];
  /** 专家只读 —— 这是硬约束,不是约定 */
  readOnly: boolean;
}

export const SPECIALISTS: SpecialistRole[] = [
  {
    id: "doc_analyst",
    name: "材料核对专家",
    purpose: "把客户提交的多份材料摆到一起,找出金额/主体/付款条件等字段级矛盾",
    allowedCapabilities: ["document.compare"],
    readOnly: true,
  },
  {
    id: "review_officer",
    name: "异常复核专家",
    purpose: "权衡重扫成本与遗漏风险、维护异常清单、处理误报撤回",
    allowedCapabilities: ["account.detect_anomalies", "account.review_anomalies"],
    readOnly: true,
  },
];

export class SpecialistRegistry {
  private readonly roles = SPECIALISTS;

  /** 能力 → 负责它的专家(没有则说明这一步由主流程自己完成) */
  resolve(capability: string): SpecialistRole | null {
    return this.roles.find((r) => r.allowedCapabilities.includes(capability)) ?? null;
  }

  /**
   * 校验"这个专家能不能调这个能力"。
   *
   * 之所以要有这一步而不是直接信任路由:
   * 路由是会变的。今天 document.compare 被分给材料专家,
   * 明天有人把一笔**写操作**也挂到同一个专家名下 —— 那一刻必须被拦住,
   * 而不是等它真的写进去了才发现"专家怎么会有写权限"。
   */
  check(role: SpecialistRole, capability: string): { allowed: boolean; reason?: string } {
    if (this.roleFor(capability)?.id !== role.id) {
      return { allowed: false, reason: `能力 ${capability} 不属于专家「${role.name}」的职责范围` };
    }
    if (role.readOnly && !role.allowedCapabilities.includes(capability)) {
      return { allowed: false, reason: `专家「${role.name}」是只读角色,不能调用 ${capability}` };
    }
    return { allowed: true };
  }

  private roleFor(capability: string): SpecialistRole | null {
    return this.resolve(capability);
  }

  list(): SpecialistRole[] {
    return [...this.roles];
  }
}
