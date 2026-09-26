import type { GateReport, PackageResult, ProvenanceGateConfig, Verdict } from './policy.ts';
import { isViolation } from './policy.ts';

const LABELS: Record<Verdict, string> = {
  ok: 'attested, repo allowlisted',
  'no-provenance': 'no provenance',
  mismatch: 'attested, repo NOT allowlisted',
  unverifiable: 'attested, but unreadable',
  'invalid-signature': 'INVALID registry signature',
  'missing-signature': 'MISSING registry signature',
  ignored: 'ignored (config)',
};

function pkgLabel(r: PackageResult): string {
  return `${r.name}@${r.version}`;
}

/** Human-readable report for the CLI. */
export function formatText(report: GateReport, config: ProvenanceGateConfig): string {
  const lines: string[] = [];
  const violations = report.results.filter((r) => isViolation(r, config, report.reportOnly));
  const missing = report.results.filter((r) => r.verdict === 'no-provenance');

  if (report.reportOnly) {
    lines.push(
      '! No allowlist configured (empty or missing "allow") — running report-only.',
      '  Repo-mismatch enforcement is disabled until you add at least one entry.',
      '',
    );
  }

  if (violations.length > 0) {
    lines.push(`Policy violations (${violations.length}):`);
    for (const r of violations) {
      const suffix = r.repository ? ` — ${r.repository}` : r.detail ? ` — ${r.detail}` : '';
      lines.push(`  x  ${pkgLabel(r)}  [${LABELS[r.verdict]}]${suffix}`);
    }
    lines.push('');
  } else {
    lines.push('No policy violations.', '');
  }

  if (missing.length > 0) {
    const verb = config.failOnMissing ? 'failing the gate (failOnMissing)' : 'informational only';
    lines.push(`No provenance at all: ${missing.length} package(s) — ${verb}.`);
    if (!config.failOnMissing) {
      const preview = missing.slice(0, 12).map(pkgLabel);
      lines.push(`  ${preview.join(', ')}${missing.length > preview.length ? ', ...' : ''}`);
    }
    lines.push('');
  }

  const total = report.results.length;
  lines.push(
    `Checked ${total} package(s): ${report.counts.ok} ok, ${report.counts.mismatch} mismatched, ` +
      `${report.counts.unverifiable} unverifiable, ${report.counts['invalid-signature']} invalid-signature, ` +
      `${report.counts['missing-signature']} missing-signature, ${report.counts['no-provenance']} no-provenance, ` +
      `${report.counts.ignored} ignored.`,
  );

  return lines.join('\n');
}

/** Machine-readable report for `--json`. */
export function formatJson(report: GateReport, config: ProvenanceGateConfig): string {
  return JSON.stringify(
    {
      reportOnly: report.reportOnly,
      hasViolations: report.hasViolations,
      counts: report.counts,
      results: report.results.map((r) => ({ ...r, violation: isViolation(r, config, report.reportOnly) })),
    },
    null,
    2,
  );
}
