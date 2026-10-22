import { EngbrainError } from "../errors.js";

/**
 * A deliberately small XML reader for CI artifacts (JUnit, Cobertura). It exists so that untrusted XML never reaches a general parser: DOCTYPE and ENTITY declarations are REFUSED (no
 * external entities, no entity expansion, so no XXE and no billion-laughs), only the five predefined and numeric character references are decoded, and size, depth, node and attribute
 * counts are capped. Iterative (no recursion), linear time, never executes or fetches anything.
 */
export const XML_LIMITS = { bytes: 20 * 1024 * 1024, depth: 64, nodes: 500_000, attributes: 64, attributeLength: 8192, textLength: 65_536, nameLength: 128 } as const;

export interface XmlNode { name: string; attrs: Record<string, string>; children: XmlNode[]; text: string }

const NAMED: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function decode(text: string): string {
  if (!text.includes("&")) {
    return text;
  }
  return text.replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-z]{2,4});/g, (whole, ref: string) => {
    if (ref.startsWith("#")) {
      const code = ref[1] === "x" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) && code !== 0xfffe && code !== 0xffff && (code >= 0x20 || code === 9 || code === 10 || code === 13) ? String.fromCodePoint(code) : "";
    }
    return NAMED[ref] ?? whole; // an unknown entity is left as written, never looked up
  });
}

const NAME = /^[A-Za-z_][\w.:-]{0,127}$/;

export function parseXml(source: string): XmlNode {
  if (Buffer.byteLength(source, "utf8") > XML_LIMITS.bytes) {
    throw new EngbrainError("POLICY_REFUSED", "the XML document is larger than the 20 MiB limit");
  }
  if (/<!DOCTYPE|<!ENTITY/i.test(source)) {
    throw new EngbrainError("POLICY_REFUSED", "XML with a DOCTYPE or ENTITY declaration is refused (no external or expanded entities are ever processed)");
  }
  const root: XmlNode = { name: "#document", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  let nodes = 0;
  let i = 0;
  const n = source.length;
  while (i < n) {
    const lt = source.indexOf("<", i);
    const top = stack[stack.length - 1]!;
    if (lt === -1) {
      top.text += decode(source.slice(i)).slice(0, XML_LIMITS.textLength);
      break;
    }
    if (lt > i && top.text.length < XML_LIMITS.textLength) {
      top.text += decode(source.slice(i, lt)).slice(0, XML_LIMITS.textLength - top.text.length);
    }
    if (source.startsWith("<!--", lt)) {
      const end = source.indexOf("-->", lt + 4);
      if (end === -1) {
        throw new EngbrainError("POLICY_REFUSED", "unterminated XML comment");
      }
      i = end + 3;
    } else if (source.startsWith("<![CDATA[", lt)) {
      const end = source.indexOf("]]>", lt + 9);
      if (end === -1) {
        throw new EngbrainError("POLICY_REFUSED", "unterminated CDATA section");
      }
      top.text += source.slice(lt + 9, end).slice(0, Math.max(0, XML_LIMITS.textLength - top.text.length));
      i = end + 3;
    } else if (source.startsWith("<?", lt)) {
      const end = source.indexOf("?>", lt + 2);
      if (end === -1) {
        throw new EngbrainError("POLICY_REFUSED", "unterminated processing instruction");
      }
      i = end + 2;
    } else if (source.startsWith("</", lt)) {
      const end = source.indexOf(">", lt + 2);
      if (end === -1) {
        throw new EngbrainError("POLICY_REFUSED", "unterminated closing tag");
      }
      const name = source.slice(lt + 2, end).trim();
      if (stack.length <= 1 || stack[stack.length - 1]!.name !== name) {
        throw new EngbrainError("POLICY_REFUSED", "mismatched XML tags");
      }
      stack.pop();
      i = end + 1;
    } else {
      // an opening tag: find its end, honouring quotes inside attribute values
      let k = lt + 1;
      let quote = "";
      while (k < n) {
        const c = source[k]!;
        if (quote !== "") {
          if (c === quote) {
            quote = "";
          }
        } else if (c === '"' || c === "'") {
          quote = c;
        } else if (c === ">") {
          break;
        }
        k += 1;
      }
      if (k >= n) {
        throw new EngbrainError("POLICY_REFUSED", "unterminated XML tag");
      }
      const selfClosing = source[k - 1] === "/";
      const inner = source.slice(lt + 1, selfClosing ? k - 1 : k);
      const nameMatch = /^([^\s/>]+)/.exec(inner);
      if (nameMatch === null || !NAME.test(nameMatch[1]!)) {
        throw new EngbrainError("POLICY_REFUSED", "invalid XML element name");
      }
      const attrs: Record<string, string> = {};
      let count = 0;
      for (const m of inner.slice(nameMatch[1]!.length).matchAll(/\s+([A-Za-z_][\w.:-]{0,127})\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
        if (++count > XML_LIMITS.attributes) {
          throw new EngbrainError("POLICY_REFUSED", "too many XML attributes on one element");
        }
        const value = decode(m[2] ?? m[3] ?? "");
        if (value.length > XML_LIMITS.attributeLength) {
          throw new EngbrainError("POLICY_REFUSED", "an XML attribute value is too long");
        }
        attrs[m[1]!] = value;
      }
      if (++nodes > XML_LIMITS.nodes) {
        throw new EngbrainError("POLICY_REFUSED", "the XML document has too many elements");
      }
      const node: XmlNode = { name: nameMatch[1]!, attrs, children: [], text: "" };
      top.children.push(node);
      if (!selfClosing) {
        if (stack.length >= XML_LIMITS.depth) {
          throw new EngbrainError("POLICY_REFUSED", "the XML document is nested too deeply");
        }
        stack.push(node);
      }
      i = k + 1;
    }
  }
  if (stack.length !== 1) {
    throw new EngbrainError("POLICY_REFUSED", "the XML document has unclosed elements");
  }
  const first = root.children[0];
  if (first === undefined || root.children.length !== 1) {
    throw new EngbrainError("POLICY_REFUSED", "the XML document must have exactly one root element");
  }
  return first;
}

/** Depth-first element walk without recursion. */
export function* walk(node: XmlNode): Generator<XmlNode> {
  const stack: XmlNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    yield current;
    for (let i = current.children.length - 1; i >= 0; i -= 1) {
      stack.push(current.children[i]!);
    }
  }
}
