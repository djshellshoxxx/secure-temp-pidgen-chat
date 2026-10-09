// Tiny XML parser, enough for XMPP stanzas (no DTD, no processing beyond entities).
// Returns { name (local name), attrs, children, text }.

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
export const unesc = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => {
  if (e[0] === '#') return String.fromCodePoint(e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
  return ENT[e.toLowerCase()];
});
export const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');

const local = (n) => n.slice(n.indexOf(':') + 1);

export function parseXml(src) {
  const re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([^\s/>]+)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
  const root = { name: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  let m;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) { top.text += m[1]; continue; }
    if (m[6] !== undefined) { top.text += unesc(m[6]); continue; }
    if (m[3] === undefined) continue; // comment / PI
    if (m[2]) { if (stack.length > 1) stack.pop(); continue; }
    const attrs = {};
    const ar = /([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    let a;
    while ((a = ar.exec(m[4]))) attrs[a[1]] = unesc(a[2] !== undefined ? a[2] : a[3]);
    const el = { name: local(m[3]), attrs, children: [], text: '' };
    top.children.push(el);
    if (!m[5]) stack.push(el);
  }
  return root.children[0] || null;
}
export const child = (el, name) => el && el.children.find((c) => c.name === name);
