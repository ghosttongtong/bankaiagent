/**
 * 展示用的域标签映射(单一出处)。
 *
 * ★ 为什么单独一处:同一个"账户类型 → 中文"的映射原来在 `eventPlan.ts` 与
 *   `registry.ts` 里各有一份。两份的**兜底**还不一样(一份给「账户」,
 *   一份原样回显类型串)。这就是典型的"改一处漏一处":
 *   客户在方案卡上看到的是「活期账户」,在账户列表里却可能看到一个内部类型串。
 *
 * ★ 兜底口径(明确写死):**绝不回显英文类型串**。
 *   客户看到 `deposit` 这种词毫无意义,反而暴露内部枚举名 ——
 *   这正是 capabilityLabel 那一类缺陷(内部标识摊到客户面前)的同族问题。
 *   调用方如需自定义兜底,显式传 fallback。
 */

/** 账户类型 → 客户说法 */
export const ACCOUNT_TYPE_LABELS: Record<string, string> = {
  current: "活期账户",
  savings: "储蓄账户",
  credit: "信用卡",
  ewallet: "电子钱包",
};

/** 账户类型 → 客户说法(未登记时给中性说法,不回显内部枚举名) */
export function accountTypeLabel(type: string, fallback = "账户"): string {
  return ACCOUNT_TYPE_LABELS[type] ?? fallback;
}

/** 定时任务状态 → 客户说法 */
export const SCHEDULE_STATUS_LABELS: Record<string, string> = {
  active: "执行中",
  paused: "已暂停",
  completed: "已完成",
  cancelled: "已取消",
};

/** 定时任务状态 → 客户说法(未登记时给中性说法,不回显内部枚举名) */
export function scheduleStatusLabel(status: string, fallback = "状态未知"): string {
  return SCHEDULE_STATUS_LABELS[status] ?? fallback;
}