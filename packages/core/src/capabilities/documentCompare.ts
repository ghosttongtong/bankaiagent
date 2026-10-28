/**
 * 多份材料比对(纯函数)
 *
 * ★ 这一层的全部价值在于**判定可复现**:
 *   "合同金额 128,000 与发票 138,000 差 10,000 元" 这句话,
 *   审计员能拿着两份材料逐字核对,客户也能自己按一遍计算器。
 *   而"模型觉得这两份不太一致"是没法复核的。
 *
 * ★ 难点不在算差值,而在**避免把表述差异当矛盾**:
 *   同一件事在两份材料里几乎不会用一模一样的字写 ——
 *   合同叫"整体装修",报价单叫"装修工程";金额一个写"128000"一个写"¥128,000.00"。
 *   如果按字符串相等来比,系统会对每一份材料都报"全部不一致",
 *   客户第一次看到就会关掉这个功能(而且他从此不再相信任何"风险提示")。
 *   所以这里对文本用"包含 / 二元组重合度"判定,对金额用数值 + 容差判定。
 */

import { fmtMoney } from "../util/format.ts";
import type { CustomerDocument, CustomerDocumentField } from "../types.ts";

export type ConflictSeverity = "high" | "medium" | "low";

export interface DocDiffValueCell {
  docId: string;
  text: string;
  differs: boolean;
}

export interface DocDiffRowOut {
  label: string;
  severity: "conflict" | "warn" | "ok";
  values: DocDiffValueCell[];
  note?: string;
}

export interface DocConflict {
  fieldKey: string;
  label: string;
  severity: ConflictSeverity;
  /** 参与冲突的各材料取值 */
  values: Array<{ documentId: string; documentLabel: string; text: string }>;
  /** 面向客户的一句话:差在哪、差多少 */
  explanation: string;
  /** 金额类冲突差额(绝对值为正) */
  amountGap?: number;
}

export interface DocCompareResult {
  documents: Array<{ id: string; label: string; kindLabel: string }>;
  rows: DocDiffRowOut[];
  conflicts: DocConflict[];
  consistentCount: number;
  conflictCount: number;
  /** 一句话结论 */
  verdict: string;
  summary: string;
}

/** 字段的规范顺序与中文名(与 types 里的 key 对齐) */
const FIELD_ORDER: Array<{ key: string; label: string; kind: "amount" | "text" | "date" }> = [
  { key: "subject", label: "项目", kind: "text" },
  { key: "counterparty", label: "对方主体", kind: "text" },
  { key: "amount", label: "金额", kind: "amount" },
  { key: "paymentTerms", label: "付款条件", kind: "text" },
  { key: "completionDate", label: "完工日期", kind: "date" },
];

/** 文本规整:去空白与常见标点,全角转半角数字 */
function normalizeText(raw: string | number): string {
  return String(raw)
    .replace(/[\s\u3000]/g, "")
    .replace(/[，,。、;；:：·\-—_()（）【】\[\]"'"']/g, "")
    .toLowerCase();
}

/** 金额解析:容忍 ¥ / 元 / 千分位 */
export function parseAmount(raw: string | number): number | null {
  if (typeof raw === "number") return Number.isFinite(raw) ? raw : null;
  const cleaned = String(raw).replace(/[¥￥,\s元]/g, "");
  const n = Number(cleaned);
  return Number.isFinite(n) && cleaned.length > 0 ? n : null;
}

/** 中文二元组集合(用于重合度) */
function bigrams(s: string): Set<string> {
  const out = new Set<string>();
  for (let i = 0; i < s.length - 1; i += 1) out.add(s.slice(i, i + 2));
  return out;
}

/**
 * 两段文本是否"说的是同一件事"。
 *
 * 判据从强到弱:
 *   ① 规整后完全相等;
 *   ② 一方包含另一方(且较短者至少 4 字 —— 避免"装修"包含于一切);
 *   ③ 二元组 Jaccard 重合度 ≥ 0.6。
 */
export function textEquivalent(a: string | number, b: string | number): boolean {
  const x = normalizeText(a);
  const y = normalizeText(b);
  if (!x || !y) return x === y;
  if (x === y) return true;

  const [shorter, longer] = x.length <= y.length ? [x, y] : [y, x];
  if (shorter.length >= 4 && longer.includes(shorter)) return true;

  const bx = bigrams(x);
  const by = bigrams(y);
  if (bx.size === 0 || by.size === 0) return false;
  let inter = 0;
  for (const g of bx) if (by.has(g)) inter += 1;
  const union = bx.size + by.size - inter;
  return union > 0 && inter / union >= 0.6;
}

/** 金额是否相等(按字段容差;没有容差时按 0.01 元) */
function amountEquivalent(a: number, b: number, tolerance?: number): boolean {
  const tol = tolerance ?? 0.01;
  return Math.abs(a - b) <= tol;
}

/** 该字段冲突的严重程度 */
function severityFor(kind: "amount" | "text" | "date", fieldKey: string): ConflictSeverity {
  if (kind === "amount") return "high";
  if (kind === "date") return "medium";
  // 主体不一致比"项目名写法不同"严重得多:它意味着收款对象可能不是同一家
  if (fieldKey === "counterparty" || fieldKey === "paymentTerms") return "high";
  return "low";
}

function rowSeverity(sev: ConflictSeverity): "conflict" | "warn" | "ok" {
  return sev === "high" ? "conflict" : sev === "medium" ? "warn" : "warn";
}

/** 两位小数金额 —— 与全仓金额口径共用一份实现(见 util/format.ts) */
const money = (n: number): string => fmtMoney(n);

/**
 * 比对多份材料,找出矛盾点。
 *
 * @param documents 至少两份;不足两份时由调用方决定如何提示
 */
export function compareDocuments(documents: CustomerDocument[]): DocCompareResult {
  const docs = documents.filter((d) => d.fields.length > 0);
  const result: DocCompareResult = {
    documents: docs.map((d) => ({ id: d.documentId, label: d.title, kindLabel: d.kindLabel })),
    rows: [],
    conflicts: [],
    consistentCount: 0,
    conflictCount: 0,
    verdict: "",
    summary: "",
  };

  if (docs.length < 2) {
    result.verdict = "只有一份材料,没有可比对的对象。";
    result.summary = result.verdict;
    return result;
  }

  // 建立 key → 每份材料的字段
  const byKey = new Map<string, Map<string, CustomerDocumentField>>();
  for (const doc of docs) {
    for (const f of doc.fields) {
      if (!byKey.has(f.key)) byKey.set(f.key, new Map());
      byKey.get(f.key)!.set(doc.documentId, f);
    }
  }

  const known = new Set(FIELD_ORDER.map((f) => f.key));
  // 已知字段按固定顺序,未知字段(未来新增)按出现顺序接在后面
  const orderedKeys = [
    ...FIELD_ORDER.map((f) => f.key),
    ...[...byKey.keys()].filter((k) => !known.has(k)),
  ];

  for (const key of orderedKeys) {
    const perDoc = byKey.get(key);
    if (!perDoc || perDoc.size === 0) continue;

    const meta = FIELD_ORDER.find((f) => f.key === key);
    const kind = meta?.kind ?? "text";
    const label = meta?.label ?? [...perDoc.values()][0]!.label;

    // 每份材料在这一行上的取值(缺失的留空并标差异)
    const cells: DocDiffValueCell[] = docs.map((doc) => {
      const f = perDoc.get(doc.documentId);
      return {
        docId: doc.documentId,
        text: f ? String(f.value) : "—",
        differs: false,
      };
    });

    // 只有一份材料写了这个字段:不算矛盾,但值得提示
    if (perDoc.size === 1) {
      result.rows.push({
        label,
        severity: "ok",
        values: cells,
        note: "只有一份材料写了这项",
      });
      continue;
    }

    let conflict = false;
    if (kind === "amount") {
      const values = [...perDoc.values()];
      const nums = values.map((v) => parseAmount(v.value)).filter((n): n is number => n != null);
      const tol = Math.max(...values.map((v) => v.tolerance ?? 0.01), 0.01);
      const max = Math.max(...nums);
      const min = Math.min(...nums);
      conflict = nums.length > 1 && !amountEquivalent(max, min, tol);
      if (conflict) {
        const gap = Math.round((max - min) * 100) / 100;
        result.conflicts.push({
          fieldKey: key,
          label,
          severity: severityFor(kind, key),
          values: docs
            .filter((d) => perDoc.has(d.documentId))
            .map((d) => ({
              documentId: d.documentId,
              documentLabel: `${d.kindLabel}「${d.title}」`,
              text: String(perDoc.get(d.documentId)!.value),
            })),
          explanation: `金额相差 ${money(gap)} 元(最大 ${money(max)}、最小 ${money(min)})`,
          amountGap: gap,
        });
      }
    } else {
      const values = [...perDoc.values()];
      // 以第一份材料为基准,逐个比
      const baseline = values[0]!.value;
      conflict = values.slice(1).some((v) => !textEquivalent(baseline, v.value));
      if (conflict) {
        result.conflicts.push({
          fieldKey: key,
          label,
          severity: severityFor(kind, key),
          values: docs
            .filter((d) => perDoc.has(d.documentId))
            .map((d) => ({
              documentId: d.documentId,
              documentLabel: `${d.kindLabel}「${d.title}」`,
              text: String(perDoc.get(d.documentId)!.value),
            })),
          explanation:
            key === "counterparty"
              ? "出据方不是同一家主体 —— 收款对象可能不一致,务必先确认打给谁"
              : key === "paymentTerms"
                ? "付款节奏不一致 —— 按哪份执行会直接影响您什么时候要付多少钱"
                : key === "completionDate"
                  ? "完工日期不一致 —— 验收与尾款时间会受影响"
                  : "表述不一致,请确认是否为同一事项",
        });
      }
    }

    if (conflict) {
      result.conflictCount += 1;
      const c = result.conflicts[result.conflicts.length - 1]!;
      /**
       * ★ 有矛盾时,**整行都标红**,而不是只标"与第一份不同的那格"。
       *
       *   三种材料里两份一致、一份不同时,如果只标那一份,
       *   界面看上去像"这份材料错了" —— 但系统并不知道谁对。
       *   比对能回答的只是"这三份在这一项上对不上,您得去问清楚",
       *   所以整行高亮、差异值加 ≠ 才是最诚实的画法。
       */
      for (const cell of cells) {
        cell.differs = true;
      }
      result.rows.push({
        label,
        severity: rowSeverity(c.severity),
        values: cells,
        note: c.explanation,
      });
    } else {
      result.consistentCount += 1;
      result.rows.push({ label, severity: "ok", values: cells });
    }
  }

  const high = result.conflicts.filter((c) => c.severity === "high").length;
  const medium = result.conflicts.filter((c) => c.severity === "medium").length;

  result.verdict =
    result.conflictCount === 0
      ? `已比对 ${docs.length} 份材料,关键信息一致,可以继续。`
      : high > 0
        ? `发现 ${result.conflictCount} 处矛盾,其中 ${high} 处属于实质性不一致(金额/主体/付款条件),建议先与对方确认再付款。`
        : `发现 ${result.conflictCount} 处不一致(${medium} 处日期类),建议先确认。`;

  const lines: string[] = [];
  lines.push(result.verdict);
  for (const c of result.conflicts) {
    lines.push(`· ${c.label}:${c.explanation}`);
  }
  result.summary = lines.join("\n");
  return result;
}
