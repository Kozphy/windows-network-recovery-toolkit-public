"use client";

import { PlatformShell } from "../../../components/PlatformShell";

export default function PolicyPage() {
  return (
    <PlatformShell title="Policy decisions" subtitle="Read-only recommendations — no automatic kill" active="/platform/policy">
      <ul>
        <li>ALLOW / OBSERVE — known dev tooling (Cursor, VS Code, dev servers)</li>
        <li>ALERT — unknown localhost proxy, correlation-only drift</li>
        <li>BLOCK_RECOMMENDED — suspicious writer posture (human confirmation required)</li>
        <li>ESCALATE_REVIEW — possible MITM risk</li>
      </ul>
      <p>Registry mutation and proxy-disable require typed confirmation via existing CLI paths.</p>
    </PlatformShell>
  );
}
