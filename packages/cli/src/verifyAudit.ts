/**
 * 审计链校验工具
 *
 * 用途:验证 `var/audit/audit-chain.jsonl` 是否完整、有没有被篡改,
 * 并导出证据包。这是答辩现场最有说服力的一步 ——
 *
 *   1. 先跑一遍:链完整;
 *   2. 手动改掉任意一条事件的金额(记事本即可);
 *   3. 再跑一遍:系统精确报出断点位置(第几条)。
 *
 * 用法:
 *   node packages/cli/src/verifyAudit.ts              # 校验默认目录
 *   node packages/cli/src/verifyAudit.ts --dir=./var/audit
 *   node packages/cli/src/verifyAudit.ts --export=./evidence-bundle.json
 *   node packages/cli/src/verifyAudit.ts --show=20    # 额外打印最近 20 条事件
 */

import { resolve } from "node:path";
import { existsSync } from "node:fs";

import { EVENT_HASH_VERSION, GENESIS_HASH, HashChainAudit } from "../../core/src/audit/hashChain.ts";

function argValue(name: string): string | undefined {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : undefined;
}

const auditDir = resolve(process.cwd(), argValue("dir") ?? "./var/audit");
const exportPath = argValue("export");
const showCount = Number(argValue("show") ?? "0");

console.log("");
console.log("═".repeat(66));
console.log("  审计哈希链校验");
console.log("═".repeat(66));
console.log(`  目录:${auditDir}`);

if (!existsSync(auditDir)) {
  console.log("");
  console.log("  ✗ 目录不存在 —— 还没有产生审计记录。");
  console.log("    先跑一次演示或测试即可生成:");
  console.log("      npm run demo -- --offline");
  console.log("      npm test");
  console.log("");
  process.exit(1);
}

const audit = new HashChainAudit({ auditDir });
const loaded = await audit.loadFromDisk();
console.log(`  已载入事件:${loaded.loaded} 条`);

const verification = await audit.verifyChain();
console.log("");

if (verification.intact) {
  console.log("  ✓ 哈希链完整,未被篡改");
  console.log(`    事件总数:${audit.size}`);
  console.log(`    创世哈希:${GENESIS_HASH}`);
  console.log(`    哈希公式:${EVENT_HASH_VERSION}(覆盖客户 / 会话 / 链路 / 渠道)`);
  if (verification.segmented) {
    console.log(
      "    ★ 注意:审计目录正被另一个写入者持有,本进程只写分片 —— " +
        "上面的结论只覆盖本进程这一段,主链请用同样的命令在停掉另一个写入者后再校验。",
    );
  }
  if (verification.checkedEvents === 0) {
    console.log("    ★ 注意:本次实际校验了 0 条事件(链是空的),这不等于「历史记录没被改过」。");
  }
  if ((verification.legacyEvents ?? 0) > 0) {
    console.log(
      `    ★ 历史事件 ${verification.legacyEvents} 条:它们是旧公式(v1)算的,` +
        "归属字段不在哈希保护范围内(改动这些条目的归属不会被发现)。",
    );
  }
} else {
  console.log("  ✗ 哈希链已损坏 —— 检测到篡改");
  console.log(`    断点位置:第 ${verification.brokenAtSeq ?? "?"} 条事件`);
  console.log("");
  console.log("  说明:任何一条事件被修改、删除或插入,都会导致该条之后的整条链校验失败。");
  console.log("  断点位置就是被改动的那一条 —— 这正是哈希链相对普通日志的价值:");
  console.log("  普通日志只能证明「我们记了」,哈希链能证明「我们没改过」。");
}

if (showCount > 0) {
  const events = await audit.readAll();
  const tail = events.slice(-showCount);
  console.log("");
  console.log(`  ── 最近 ${tail.length} 条事件 ──`);
  for (const e of tail) {
    const brief = JSON.stringify(e.payload).slice(0, 96);
    console.log(`  [${String(e.seq).padStart(4)}] ${e.type.padEnd(22)} ${brief}`);
  }
}

if (exportPath) {
  const out = resolve(process.cwd(), exportPath);
  const result = await audit.exportEvidenceBundle(out);
  console.log("");
  console.log(`  ✓ 证据包已导出:${result.path}(${result.count} 条事件,链完整性:${result.intact ? "完整" : "已损坏"})`);
  console.log("    内容:算法声明、创世哈希、事件总数、链完整性、全部事件。");
}

console.log("");
console.log("═".repeat(66));
console.log("");

process.exit(verification.intact ? 0 : 2);
