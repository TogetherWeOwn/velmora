// Minimal readers for the flat XML S3 answers this console uses.
// Workers have no DOMParser; the S3 response shapes are fixed and none of
// the elements read here nest inside themselves.

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos);/g, (_, e) => {
    switch (e) {
      case "amp":
        return "&";
      case "lt":
        return "<";
      case "gt":
        return ">";
      case "quot":
        return '"';
      case "apos":
        return "'";
      default: {
        const cp = e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try {
          return String.fromCodePoint(cp);
        } catch {
          return "";
        }
      }
    }
  });
}

/** Inner text of every `<tag>...</tag>` (raw, not decoded). */
export function blocks(xml, tag) {
  const out = [];
  const open = new RegExp(`<${tag}(?:\\s[^>]*)?>`, "g");
  const close = `</${tag}>`;
  let m;
  while ((m = open.exec(xml))) {
    const start = m.index + m[0].length;
    const end = xml.indexOf(close, start);
    if (end < 0) break;
    out.push(xml.slice(start, end));
    open.lastIndex = end + close.length;
  }
  return out;
}

/** Decoded text of the first `<tag>`, or `undefined`. */
export function text(xml, tag) {
  const b = blocks(xml, tag);
  return b.length ? decodeEntities(b[0]) : undefined;
}

export function escapeXml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]);
}

/** Removes every `<tag>...</tag>` block (to read top-level fields). */
export function strip(xml, tag) {
  return xml.replace(new RegExp(`<${tag}(?:\\s[^>]*)?>[\\s\\S]*?</${tag}>`, "g"), "");
}
