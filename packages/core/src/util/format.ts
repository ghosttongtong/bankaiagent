/**
 * 展示层的格式化工具(单一出处)。
 *
 * ★ 为什么要有这个文件:
 *   以下这些"两行函数"原来在仓库里各有 3~7 份**逐字相同**的拷贝:
 *     · `round2`      —— 金额四舍五入到分:billAnalysis / eventPlan / wealth / subscription / registry
 *     · `fmtMoney`    —— 两位小数金额:wealth / card / documentCompare / operationStatus / provenance / flowTrace / 检索层
 *     · `fmtYuan`     —— 带 ¥ 的金额:policy/engine、intent/resolvePayee、server/index
 *     · `fmtDay`      —— `YYYY-MM-DD`:wealth / card
 *
 *   拷贝本身不会出错,出错的是**改一处漏六处**:只要有一个地方的口径被单独调整
 *   (千分位、负数、四舍五入方向),同一个金额就会在两个页面上长得不一样,
 *   而客户看到的正是这种"同一笔钱两个数"。审计链那种"看起来对不上"的怀疑
 *   往往就是从这里开始的。所以这里收成一份,调用方各自 re-export 保持原导入路径不变。
 *
 * ★ 口径(刻意写死,不许各处自行发挥):
 *   · 金额一律**两位小数**,千分位按 zh-CN(12,345.60);
 *   · 负数保留负号(-1,234.50),不改成括号或红色;
 *   · `round2` 用 `Math.round(n * 100) / 100` —— 对负数是"向 +∞ 取整"(-1.005 → -1),
 *     这是刻意与既有行为保持一致:改口径会让历史审计里的金额与新算的对不上。
 */

/** 金额四舍五入到分 */
export function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** 两位小数金额(不带货币符号):12345.6 → `12,345.60` */
export function fmtMoney(n: number): string {
  return n.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

/** 带人民币符号的金额:12345.6 → `¥12,345.60` */
export function fmtYuan(n: number): string {
  return `¥${fmtMoney(n)}`;
}

/** 日期(本地时区):`2026-09-29` */
export function fmtDay(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** 日期(本地时区,中文):`2026年9月29日` */
export function fmtDateCn(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
}