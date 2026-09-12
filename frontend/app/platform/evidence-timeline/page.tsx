"use client";

import { useEffect, useState } from "react";
import { PlatformShell } from "../../../components/PlatformShell";
import { triskFetch } from "../../../lib/trisk-api";

export default function EvidenceTimelinePage() {
  const [events, setEvents] = useState<{ items: unknown[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    triskFetch("/v1/events?limit=50")
      .then(setEvents)
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <PlatformShell
      title="Evidence Timeline"
      subtitle="Domain events from trisk_domain_events"
      active="/platform/evidence-timeline"
    >
      {error ? <p style={{ color: "crimson" }}>{error}</p> : null}
      <pre style={{ fontSize: "0.75rem", overflow: "auto", maxHeight: "70vh" }}>
        {JSON.stringify(events, null, 2)}
      </pre>
    </PlatformShell>
  );
}
