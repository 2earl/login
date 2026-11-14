// The part of node:crypto that src/saml.ts uses. Workers provide it with nodejs_compat;
// declaring it here keeps Node's whole type library out of the Worker's types.
declare module 'node:crypto' {
  export class X509Certificate {
    constructor(buffer: string);
    /** The end of the validity period, as a date string. */
    readonly validTo: string;
  }
}
