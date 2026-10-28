/**
 * 场景六(事件联动)的**共用措辞判据**。
 *
 * 为什么要把这几条正则抽出来单独放:
 *   同一个判断在两处出现 —— 离线解析器(`llm/deterministic.ts`,决定"这句话是不是
 *   要办方案里的某一步")与编排器(`agent/orchestrator.ts`,决定"这一步的方向是
 *   预留还是解开")。两处必须**判得一样**,否则会出现最坏的一类不一致:
 *   解析器认为客户要"解开",编排器却认为要"再锁一次" —— 结果系统办成了相反的事。
 *   这类不一致在实测中真的发生过(「取消刚才那个预留」曾经被读成再锁一次),
 *   当时的修法就是"两处都判";现在把判据本身收敛成一份,让"两处都判"不再依赖自觉。
 *
 * 设计纪律:这里只放**措辞 → 意图**的映射,不放任何业务判断与文案。
 */

/** 步骤序号:「第2步」「第二步」「第 2 步」「第3 步」 */
export const STEP_ORDINAL_PATTERN = String.raw`第\s*(?:[0-9]+|[一二两三四五六七八九十]+)\s*步`;

/**
 * 解开预留的说法。
 *
 * ★ 两种语序都要接住,这不是"多写一条更宽容",而是中文里两种说法同样自然:
 *   · 动词在前:「取消/解开/解锁/放回/释放/撤掉/解掉 + (那笔)预留」;
 *   · 名词在前:「(那笔)预留/锁定/冻结/定时任务 + 解开/解锁/取消」——
 *     漏掉这一条,「把预留解开」就会掉到通用澄清里,客户会以为系统没听懂。
 * ★ 中间的指代词必须允许(「取消**刚才那个**预留」):这是最自然的一句口语。
 */
const RELEASE_VERB_THEN_NOUN =
  /(?:取消|解开|解锁|放回|释放|撤掉|解掉)[^。;；\n]{0,8}?(?:预留|锁定|冻结|定时任务)/;
const RELEASE_NOUN_THEN_VERB =
  /(?:预留|锁定|冻结|定时任务)[^。;；\n]{0,4}?(?:解开|解锁|放回|释放|取消|撤掉|解掉)/;

/** 客户是否**明说**要解开预留(而不是"再锁一次") */
export function isEventReleaseSpoken(text: string): boolean {
  return RELEASE_VERB_THEN_NOUN.test(text) || RELEASE_NOUN_THEN_VERB.test(text);
}

/**
 * 客户是否在**按序号点名方案里的某一步**(「执行第2步」「办第二步」「落实第 3 步」)。
 *
 * ★ 序号必须和"执行"类动词一起出现,且**任一种语序**都算:
 *   「执行第2步」与「第2步执行」都是人话。
 *   只认「第一步/第1步」是不够的 —— 实测中「执行第2步」因为没被接住,
 *   掉进了转账意图,被解析成"转给「执行第」2 元",系统当场开始问金额。
 */
const STEP_ACTION_VERB = /(?:执行|办|走|按|开始|落实|办一下|办理)/;

export function isOrderedStepExecutionSpoken(text: string): boolean {
  const ordinal = new RegExp(STEP_ORDINAL_PATTERN);
  if (!ordinal.test(text)) return false;
  // 动词在前:「执行第2步」;动词在后:「第2步走一下」
  return (
    new RegExp(`${STEP_ACTION_VERB.source}[^。;；\\n]{0,6}?${STEP_ORDINAL_PATTERN}`).test(text) ||
    new RegExp(`${STEP_ORDINAL_PATTERN}[^。;；\\n]{0,4}?${STEP_ACTION_VERB.source}`).test(text)
  );
}