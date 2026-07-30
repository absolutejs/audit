import { describe, expect, test } from "bun:test";
import { createAudit, memorySink, recordHandoffEvidence } from "../src";

describe("handoff audit observer", () => {
  test("records operational identity without customer-visible evidence", async () => {
    const sink = memorySink();
    const audit = createAudit({ sinks: [sink] });
    recordHandoffEvidence(audit)({
      at: 10,
      attempt: 2,
      correlationId: "handoff-1",
      externalId: "private-external-id",
      message: "customer-visible error",
      operation: "invoice_payment",
      outcome: "failed",
      reference: "private-reference",
      service: "gateway",
      source: "external_surface_report",
    });
    await audit.flush();

    const [event] = (await sink.list?.()) ?? [];
    expect(event).toEqual({
      at: 10,
      kind: "handoff.invoice_payment.failed",
      metadata: {
        attempt: 2,
        correlationId: "handoff-1",
        operation: "invoice_payment",
        outcome: "failed",
        service: "gateway",
        source: "external_surface_report",
      },
      target: "handoff-1",
    });
    expect(JSON.stringify(event)).not.toContain("private-reference");
    expect(JSON.stringify(event)).not.toContain("customer-visible error");
  });
});
