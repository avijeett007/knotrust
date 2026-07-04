/**
 * @knotrust/approval — localhost approval page HTML templates (P0-E6-T3,
 * R99): escaping is the acceptance. A `<script>`-laden argument, tool name,
 * server name, or grant-preview string must render INERT — no live tag, no
 * attribute breakout — in every template this module exports.
 */
import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  renderApprovalPage,
  renderDonePage,
  renderMessagePage,
} from "./html.js";

const XSS_PAYLOAD = "<script>alert(1)</script>";

function baseView(
  over: Partial<Parameters<typeof renderApprovalPage>[0]> = {},
) {
  return {
    approvalId: "apr_abc123",
    token: "tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    csrfToken: "csrf_deadbeef",
    tool: "stripe.create_refund",
    server: "stripe",
    tier: "critical" as const,
    args: { amount: 4200 },
    grantPreview:
      "stripe.create_refund on stripe_charge:ch_3P — expires in 30 days",
    ...over,
  };
}

describe("escapeHtml", () => {
  it("escapes &, <, >, \", ' — in that order (& first)", () => {
    expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
  });

  it("does not double-escape an already-escaped ampersand", () => {
    // If '&' were replaced AFTER '<'/'>' etc., "&lt;" would become
    // "&amp;lt;" — wrong. Escaping '&' FIRST avoids this.
    expect(escapeHtml("&amp;")).toBe("&amp;amp;");
  });

  it("leaves plain text untouched", () => {
    expect(escapeHtml("stripe.create_refund")).toBe("stripe.create_refund");
  });
});

describe("renderApprovalPage — XSS-proof argument/tool/server rendering (R99)", () => {
  it("a <script> argument value renders escaped/inert, never as a live tag", () => {
    const html = renderApprovalPage(
      baseView({ args: { reason: XSS_PAYLOAD } }),
    );
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("a </textarea>-laden argument value cannot break out of any container", () => {
    const html = renderApprovalPage(
      baseView({ args: { note: "</textarea><script>alert(2)</script>" } }),
    );
    expect(html).not.toContain("</textarea><script>");
    expect(html).toContain("&lt;/textarea&gt;&lt;script&gt;");
  });

  it("a double-quote in an argument value cannot break out of an attribute", () => {
    const html = renderApprovalPage(
      baseView({ args: { path: '"><img src=x onerror=alert(3)>' } }),
    );
    expect(html).not.toContain('"><img src=x onerror=alert(3)>');
    expect(html).toContain("&quot;&gt;&lt;img src=x onerror=alert(3)&gt;");
  });

  it("a hostile tool name renders escaped", () => {
    const html = renderApprovalPage(baseView({ tool: XSS_PAYLOAD }));
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("a hostile server name renders escaped", () => {
    const html = renderApprovalPage(baseView({ server: XSS_PAYLOAD }));
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("a hostile grant-preview string renders escaped", () => {
    const html = renderApprovalPage(baseView({ grantPreview: XSS_PAYLOAD }));
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("the approval id/token/csrf are embedded as hidden form fields, escaped", () => {
    const html = renderApprovalPage(
      baseView({ approvalId: '"><script>x</script>' }),
    );
    expect(html).not.toContain('"><script>x</script>');
    expect(html).toContain(
      'name="id" value="&quot;&gt;&lt;script&gt;x&lt;/script&gt;"',
    );
  });

  it("renders the three POST-only action buttons and no client-side JavaScript", () => {
    const html = renderApprovalPage(baseView());
    expect(html).toContain('<form method="POST" action="/approve/action">');
    expect(html).toContain('name="action" value="approve"');
    expect(html).toContain('name="action" value="always_allow"');
    expect(html).toContain('name="action" value="deny"');
    expect(html).not.toContain("<script");
    expect(html).not.toMatch(/\bonclick\b|\bonerror\b|\bonload\b/i);
  });

  it("renders with no arguments as an explicit empty state, not an empty/absent table", () => {
    const html = renderApprovalPage(baseView({ args: undefined }));
    expect(html).toContain("(no arguments)");
  });
});

describe("renderDonePage / renderMessagePage — escape dynamic text", () => {
  it("renderMessagePage escapes a hostile message", () => {
    const html = renderMessagePage("Forbidden", XSS_PAYLOAD);
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("renderDonePage renders a distinct message per action", () => {
    expect(renderDonePage("approve")).toContain("may now proceed");
    expect(renderDonePage("deny")).toContain("will not proceed");
    expect(renderDonePage("always_allow")).toContain(
      "standing grant was created",
    );
  });
});
