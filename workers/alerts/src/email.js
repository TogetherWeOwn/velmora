// Email through the `send_email` binding (ALERT_EMAIL). The recipient is a
// secret (ALERT_EMAIL_TO) and must be a verified destination address of the
// account's Email Routing: sends to it are free and need no sending domain.
// The sender (ALERT_FROM) must be an address on a domain with Email Routing.

function fmt(ms) {
  return ms ? new Date(Number(ms)).toISOString().replace(".000Z", "Z") : "-";
}

export function alertMessage(claim, now, nextGapMs) {
  const lines = [
    claim.detail,
    "",
    `key: ${claim.key}`,
    `source: ${claim.source}`,
    `holding since: ${fmt(claim.active_since)}`,
    `reports since the last email: ${claim.covered}`,
    `sent: ${fmt(now)}`,
    `next email for this key, if it still holds: not before ${fmt(now + nextGapMs)}`,
    "",
    "The daily digest lists everything that held or cleared in the last 24 h.",
  ];
  return { subject: `[velmora] ${claim.title}`, text: lines.join("\n") };
}

export function digestMessage(d, figures, now) {
  const L = [];
  const n = d.active.filter((a) => a.severity === "page").length;
  L.push(n === 0 ? "Nothing is wrong right now." : `${n} problem(s) holding right now:`);
  for (const a of d.active.filter((x) => x.severity === "page")) {
    L.push(`- ${a.title} (since ${fmt(a.active_since)}): ${a.detail}`);
  }
  L.push("");
  L.push("Cleared in the last 24 h:");
  if (d.resolved.length === 0) L.push("- none");
  for (const r of d.resolved) L.push(`- ${r.title} (cleared ${fmt(r.resolved_at)})`);
  if (d.info.length > 0) {
    L.push("");
    L.push("Notices (no email of their own):");
    for (const i of d.info) L.push(`- ${i.title} (${fmt(i.last_seen_at)}): ${i.detail}`);
  }
  L.push("");
  L.push(`Alert emails in the last 24 h: ${d.emailsSent}`);
  L.push(`Dead-letter messages in the last 24 h: ${d.dlq24h}`);
  if (d.dlqSample) L.push(`Latest dead-letter message: ${d.dlqSample}`);
  if (figures.length > 0) {
    L.push("");
    L.push("Figures now:");
    for (const f of figures) L.push(`- ${f}`);
  }
  L.push("");
  L.push(`Generated ${fmt(now)}. This digest arrives every day; if it stops, alerting is down.`);
  const subject = n === 0 ? "[velmora] Daily digest: all clear" : `[velmora] Daily digest: ${n} problem(s)`;
  return { subject, text: L.join("\n") };
}

/** Sends one email. Throws on failure (the caller gives its claim back). */
export async function send(env, { subject, text }) {
  if (!env.ALERT_EMAIL) throw new Error("ALERT_EMAIL binding missing");
  if (!env.ALERT_EMAIL_TO) throw new Error("ALERT_EMAIL_TO secret missing");
  if (!env.ALERT_FROM) throw new Error("ALERT_FROM var missing");
  const r = await env.ALERT_EMAIL.send({
    to: env.ALERT_EMAIL_TO,
    from: { email: env.ALERT_FROM, name: "velmora alerts" },
    subject: subject.slice(0, 200),
    text: text.slice(0, 20_000),
  });
  return r?.messageId ?? null;
}
