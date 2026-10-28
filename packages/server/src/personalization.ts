/**
 * 个性化存储(常用流程 + 历史业务记录)
 *
 * ★ 这个文件存在的唯一理由:让"常用流程"是**真的记住了**。
 *
 *   需求里点得很明确:"此功能要真实能用,不要只是做个演示效果,实际根本没有记住常用流程"。
 *   所以这里必须落盘:进程重启、换一个浏览器、第二天再来,常用流程还在原处。
 *   内存里放一个数组是最容易写的做法,也是最容易露馅的做法 ——
 *   演示时刷新一次页面就穿帮了。
 *
 * ★ 存两份数据,用途完全不同:
 *   · `flows`    客户显式保存的**意图模板**(可反复调用的"套路"),进常用服务快捷入口;
 *   · `history`  客户办过的**业务记录**(能力、金额、对手方、时间),用于个性化建议。
 *   把两者混成一份,就会出现"把某一次转账当成模板"的荒唐结果。
 *
 * ★ 落盘是**追加安全**的:写临时文件再重命名(原子替换),
 *   避免进程在写一半时被杀导致文件损坏 —— 客户存了十条常用流程,
 *   不应该因为一次崩溃全丢掉。
 */

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { SavedFlowTemplate } from "../../core/src/agent/turnExtras.ts";
import { instantiateTemplate } from "../../core/src/agent/flowTrace.ts";
import type { OperationStatus } from "../../core/src/agent/operationStatus.ts";

/**
 * 一条业务记录 / 操作台账条目。
 *
 * ★ 从"个性化用的历史"升级成"操作台账":原来的字段只够回答
 *   "客户最近办过什么、金额多少"(建议的燃料);要回答
 *   "哪一次对话办的、办到哪一步了、流水号是多少",就必须补上
 *   sessionId / opId / status / detail / reference / traceId。
 *
 * ★ 新字段全部可选:旧文件里没有它们,读取时缺省即可 ——
 *   演示数据可以丢,但不该因为多了几个字段就打不开旧文件。
 */
export interface HistoryRecord {
  ts: number;
  /** 能力名 */
  capability: string;
  /** 业务族名(面向客户,如"转账汇款") */
  family: string;
  /** ★ 所属会话(没有它就无法回答"哪次对话办的") */
  sessionId?: string;
  /** 涉及金额(可选) */
  amount?: number;
  /** 对手方或对象(如收款人姓名、产品名) */
  subject?: string;
  /** ★ 流水号 / 申请单号 / 订单号 */
  reference?: string;
  /** ★ 业务态(八档,见 core/agent/operationStatus.ts) */
  status?: OperationStatus;
  /** ★ 业务态的客户口径,如「提额申请已提交 · 待银行审核」 */
  statusLabel?: string;
  /** ★ 业务态补充,如「保留原号 · 预计 12 个工作日」「份额 T+1 确认」 */
  detail?: string;
  /** 是否已办结(而不是只展示了确认卡) */
  completed: boolean;
  /** ★ 台账条目 ID = OP-<traceId 尾 8 位> */
  opId?: string;
  /** ★ 本轮 traceId —— 用它才能精确回查审计(审计不拿去做相似度检索) */
  traceId?: string;
  /** ★ 台账生成时间(与 ts 同源;分开留是为了将来允许"补录"时有独立时间轴) */
  createdAt?: number;
}

/**
 * 把台账的**事件流水**折叠成**一笔业务一行**。
 *
 * ★ 为什么必须有这一步:台账是事件级的 —— 一笔转账留下两行
 *   (「待你确认」pending + 「已转账成功」done),一次提额留下「待你验证」+
 *   「提额申请已提交 · 待银行审核」。历史列表如果直接铺事件,客户会看到
 *   同一笔转账出现两次 —— 那比"看不见第二笔"更糟。
 *   (真实数据可查:var/personalization/<客户>.json 里 OP-B421604A 与
 *    OP-58BFC94A 就是同一笔转账的两行。)
 *
 * ★ 折叠规则(按时间**正序**走一遍):
 *   同一 (sessionId, capability) 上若有一笔**还没落定**的业务(它最新一行是
 *   pending,即在等客户确认/验证),紧随其后的那一行就是它的结局 —— 合并进去,
 *   而不是新开一笔;否则就是**新的一笔**。
 *
 *   这条规则同时满足两件看起来矛盾的事:
 *   · "一次转账的确认 + 成功"= 一笔(落定后游标关闭,不会把两笔转账并成一条);
 *   · "同一个对话里转两次账"= 两笔(第一笔 done 之后,第二个 pending 开新的一笔)。
 *   单纯按 capability 分组会把后者错并成一笔 —— 那是更严重的数据错误。
 *
 * ★ 口径来源:`sessions.ts` 的 summarizeSession 早就定了"同一件事只认它的最新
 *   状态,不同的事之间才比严重程度"。这里是同一条口径落到**业务**这一层。
 */
export function collapseBusinesses(rows: HistoryRecord[]): HistoryRecord[] {
  const asc = [...rows].sort((a, b) => (a.createdAt ?? a.ts) - (b.createdAt ?? b.ts));
  const out: HistoryRecord[] = [];
  /** 还开着(在等客户)的那一笔在 out 里的下标 —— 键是 sessionId + capability */
  const open = new Map<string, number>();

  for (const row of asc) {
    const key = `${row.sessionId ?? ""}\u0000${row.capability}`;
    const idx = open.get(key);
    if (idx !== undefined) {
      /**
       * ★ 生成**新对象**再替换,绝不在原对象上改:
       *   history() 返回的是缓存文件的浅拷贝(元素仍是同一批对象),
       *   就地改会把"已转账成功"写回 store 的内存态,并在下一次 persist 时落盘 ——
       *   事件流水被永久篡改,审计追溯就废了。
       */
      const merged: HistoryRecord = { ...out[idx]!, ...row };
      out[idx] = merged;
      if (merged.status !== "pending") open.delete(key);
      continue;
    }
    out.push({ ...row });
    if (row.status === "pending") open.set(key, out.length - 1);
  }

  // 倒序返回:最近变化的业务在最前(与 ledger() 的排序口径一致)
  return out.sort((a, b) => (b.createdAt ?? b.ts) - (a.createdAt ?? a.ts));
}

interface CustomerFile {
  version: 1;
  customerId: string;
  flows: SavedFlowTemplate[];
  history: HistoryRecord[];
  /** 建议的冷却:避免同一条建议每轮都推 */
  suggestionCooldown: Record<string, number>;
}

const MAX_HISTORY = 200;
const SUGGESTION_COOLDOWN_MS = 6 * 3600 * 1000;

export class PersonalizationStore {
  private readonly dir: string;
  private readonly cache = new Map<string, CustomerFile>();
  /** 串行化写盘:同一客户的并发写入按顺序落盘 */
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(dir: string) {
    this.dir = dir;
  }

  private pathFor(customerId: string): string {
    // 客户 ID 只允许安全字符,避免路径穿越(客户 ID 来自请求)
    const safe = customerId.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.dir, `${safe}.json`);
  }

  private async load(customerId: string): Promise<CustomerFile> {
    const cached = this.cache.get(customerId);
    if (cached) return cached;

    let file: CustomerFile = {
      version: 1,
      customerId,
      flows: [],
      history: [],
      suggestionCooldown: {},
    };
    try {
      const raw = await readFile(this.pathFor(customerId), "utf8");
      const parsed = JSON.parse(raw) as Partial<CustomerFile>;
      file = {
        version: 1,
        customerId,
        flows: Array.isArray(parsed.flows) ? parsed.flows : [],
        history: Array.isArray(parsed.history) ? parsed.history : [],
        suggestionCooldown: parsed.suggestionCooldown ?? {},
      };
    } catch {
      // 文件不存在或损坏:从空开始(不阻塞业务;损坏的旧文件不会被覆盖,除非再次保存)
    }
    this.cache.set(customerId, file);
    return file;
  }

  /** 原子落盘:先写临时文件再重命名 */
  private persist(customerId: string, file: CustomerFile): Promise<void> {
    const run = async (): Promise<void> => {
      const target = this.pathFor(customerId);
      await mkdir(dirname(target), { recursive: true });
      const tmp = `${target}.tmp-${process.pid}`;
      await writeFile(tmp, JSON.stringify(file, null, 2), "utf8");
      await rename(tmp, target);
    };
    const next = this.writeQueue.then(run, run);
    this.writeQueue = next.catch(() => undefined);
    return next;
  }

  // ---- 常用流程 ----

  async listFlows(customerId: string): Promise<SavedFlowTemplate[]> {
    const file = await this.load(customerId);
    return [...file.flows].sort((a, b) => (b.lastUsedAt ?? b.createdAt) - (a.lastUsedAt ?? a.createdAt));
  }

  /**
   * 保存(或更新)一个常用流程。
   *
   * ★ 幂等:同一个模板 ID 再次保存只更新定义,不会产生两条重复入口 ——
   *   客户连点两次"保存为常用流程"不应该在常用服务里出现两个一样的按钮。
   */
  async saveFlow(customerId: string, template: SavedFlowTemplate): Promise<SavedFlowTemplate> {
    const file = await this.load(customerId);
    const existing = file.flows.find((f) => f.templateId === template.templateId);
    const merged: SavedFlowTemplate = existing
      ? { ...template, createdAt: existing.createdAt, useCount: existing.useCount, ...(existing.lastUsedAt ? { lastUsedAt: existing.lastUsedAt } : {}) }
      : template;
    file.flows = [...file.flows.filter((f) => f.templateId !== template.templateId), merged];
    await this.persist(customerId, file);
    return merged;
  }

  async removeFlow(customerId: string, templateId: string): Promise<boolean> {
    const file = await this.load(customerId);
    const before = file.flows.length;
    file.flows = file.flows.filter((f) => f.templateId !== templateId);
    if (file.flows.length === before) return false;
    await this.persist(customerId, file);
    return true;
  }

  /** 记一次使用:常用流程的顺序按"最近用过"排,客户最常用的自然浮到前面 */
  async touchFlow(customerId: string, templateId: string, now: number): Promise<void> {
    const file = await this.load(customerId);
    const flow = file.flows.find((f) => f.templateId === templateId);
    if (!flow) return;
    flow.useCount += 1;
    flow.lastUsedAt = now;
    await this.persist(customerId, file);
  }

  /**
   * 把模板实例化成一句可以直接发出去的话。
   *
   * ★ 参数预填规则:优先用客户**最近一次用过的值**,其次用示例值。
   *   这样客户点一下"给老妈转账"就能拿到「给 王秀兰 转 500 元,备注 买菜」,
   *   只需要改一个数字 —— 这才是"下次直接调用"的实际体验。
   */
  async instantiate(customerId: string, templateId: string): Promise<string | null> {
    const flows = await this.listFlows(customerId);
    const flow = flows.find((f) => f.templateId === templateId);
    if (!flow) return null;
    return instantiateTemplate(flow, {});
  }

  // ---- 历史业务记录 ----

  async recordHistory(customerId: string, record: HistoryRecord): Promise<void> {
    const file = await this.load(customerId);
    file.history.push(record);
    if (file.history.length > MAX_HISTORY) file.history = file.history.slice(-MAX_HISTORY);
    await this.persist(customerId, file);
  }

  async history(customerId: string): Promise<HistoryRecord[]> {
    const file = await this.load(customerId);
    return [...file.history];
  }

  /**
   * ★ 提交前取消:撤回确认卡留下的「待办理」台账行(第 3 项)。
   *
   *   为什么必须撤:台账的折叠规则靠"后续结局行"关闭 pending 行;
   *   提交前取消**刻意不写任何行**(什么都没发生),于是确认卡那一行会
   *   永远悬在客户历史里显示「待办理」—— 客户会以为这笔转账还挂着,
   *   甚至去找入口确认它。"什么都没发生"必须贯彻到台账:没动钱,就没有这笔业务。
   *
   *   ★ 只撤"该键最新一行仍是 pending"的:若业务已落定(后面有 done/failed 行),
   *   pending 行已被折叠规则关闭,不能动。证据不会丢:取消在审计哈希链里
   *   (`execution_cancelled`),台账是业务视图,审计是系统经历 —— 口径不同。
   */
  async retractPendingOperation(
    customerId: string,
    sessionId: string,
    capability: string,
  ): Promise<boolean> {
    const file = await this.load(customerId);
    let lastIdx = -1;
    for (let i = 0; i < file.history.length; i++) {
      const row = file.history[i]!;
      if ((row.sessionId ?? "") === sessionId && row.capability === capability) lastIdx = i;
    }
    if (lastIdx === -1) return false;
    if (file.history[lastIdx]!.status !== "pending") return false;
    file.history.splice(lastIdx, 1);
    await this.persist(customerId, file);
    return true;
  }

  /**
   * 操作台账:历史记录里**能按 opId 追溯**的那部分,按时间倒序。
   *
   * ★ 与 history() 的区别不是"过滤掉不好看的",而是职责不同:
   *   · history() 是建议的燃料,按发生顺序原样返回,新条目在末尾;
   *   · ledger() 是"客户办过的每一笔操作",给历史列表与「刚才那笔成了吗」用,
   *     所以按时间**倒序**(最近的在最前)且必须带 opId。
   *   旧文件里没有 opId 的记录不算台账(它们连"哪一笔"都指不出来)。
   */
  async ledger(customerId: string): Promise<HistoryRecord[]> {
    const list = await this.history(customerId);
    return list
      .filter((h) => Boolean(h.opId))
      .sort((a, b) => (b.createdAt ?? b.ts) - (a.createdAt ?? a.ts));
  }

  /** 按 opId 取单条操作(历史详情与「那一笔到哪一步了」用) */
  async getLedgerEntry(customerId: string, opId: string): Promise<HistoryRecord | null> {
    const list = await this.history(customerId);
    return list.find((h) => h.opId === opId) ?? null;
  }

  /**
   * 业务台账:**一笔业务一行**。
   *
   * ★ 与 ledger() 的区别就是"事件"与"业务"的区别,不是过滤:
   *   · ledger() 是事件流水 —— 一笔转账留两行(「待你确认」+「已转账成功」);
   *     它要的是"每一步都别丢",给审计追溯与回放用。
   *   · businessLedger() 是客户视角的"我办了几件事" —— 历史列表按它出行。
   *     客户数的是件数,不是系统记了几行事件。
   *
   * ★ 为什么不能简单地"按 capability 去重":
   *   同一个对话里给两个人各转一笔,是**两笔业务**,不能并成一条。
   *   折叠规则见 collapseBusinesses。
   */
  async businessLedger(customerId: string): Promise<HistoryRecord[]> {
    return collapseBusinesses(await this.ledger(customerId));
  }

  async recentCapabilities(customerId: string, sinceMs: number, now: number): Promise<string[]> {
    const list = await this.history(customerId);
    const seen: string[] = [];
    for (const h of [...list].reverse()) {
      if (now - h.ts > sinceMs) continue;
      if (!seen.includes(h.capability)) seen.push(h.capability);
      if (seen.length >= 12) break;
    }
    return seen;
  }

  // ---- 建议冷却 ----

  /**
   * 过滤掉"刚推过"的建议。
   *
   * ★ 为什么必须做:主动建议最容易被做成骚扰。
   *   同一条建议 6 小时内只推一次 —— 客户没点,说明他现在不需要,再推就是打扰。
   */
  async filterSuggestions<T extends { id: string }>(customerId: string, items: T[], now: number): Promise<T[]> {
    const file = await this.load(customerId);
    return items.filter((s) => {
      const last = file.suggestionCooldown[s.id] ?? 0;
      return now - last >= SUGGESTION_COOLDOWN_MS;
    });
  }

  async markSuggestionsShown(customerId: string, ids: string[], now: number): Promise<void> {
    if (ids.length === 0) return;
    const file = await this.load(customerId);
    for (const id of ids) file.suggestionCooldown[id] = now;
    await this.persist(customerId, file);
  }
}
