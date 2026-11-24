// The part of @xmldom/xmldom that src/saml-metadata.ts uses, imported from its lib/ entry, which
// has no types of its own: the package's types pull in the browser's DOM library, which clashes
// with the Workers types.
declare module '@xmldom/xmldom/lib/dom-parser.js' {
  export interface XmlElement {
    readonly localName: string | null;
    readonly textContent: string | null;
    readonly parentNode: XmlElement | null;
    getAttribute(name: string): string | null;
    getElementsByTagNameNS(namespace: string, localName: string): ArrayLike<XmlElement>;
  }
  export interface XmlDocument {
    readonly documentElement: XmlElement | null;
  }
  export class DOMParser {
    constructor(options?: {
      onError?: (level: 'warning' | 'error' | 'fatalError', message: string) => void;
    });
    parseFromString(source: string, mimeType: string): XmlDocument;
  }
}
