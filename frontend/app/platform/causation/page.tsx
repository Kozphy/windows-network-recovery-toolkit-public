"use client";

import { PlatformShell } from "../../../components/PlatformShell";

export default function CausationPage() {
  return (
    <PlatformShell title="Final causation" subtitle="Registry writer proof via Sysmon Event ID 13" active="/platform/causation">
      <p>
        Final causation requires Sysmon Event ID 13 on WinINET proxy keys within the observation window.
        Listener correlation alone is not proof.
      </p>
      <p>See proxy incidents for per-event causation levels: final causation, correlation only, unknown.</p>
    </PlatformShell>
  );
}
