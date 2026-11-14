export const partialHeaderNames = ['strict-transport-security','content-security-policy','content-security-policy-report-only','x-content-type-options','referrer-policy','permissions-policy','set-cookie'] as const;
export type PartialHeaders = Readonly<{present: readonly (typeof partialHeaderNames)[number][]; completeness: 'headers_validated_body_incomplete'}>;

/** Closed presence-only projection: never accept header or cookie values. */
export function validatePartialHeaders(value: unknown): asserts value is PartialHeaders {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('Invalid partial headers');
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes('present') || !keys.includes('completeness') || keys.some(k => !('value' in Object.getOwnPropertyDescriptor(value, k)!))) throw new TypeError('Invalid partial headers');
  const x = value as Record<string, unknown>;
  if (x.completeness !== 'headers_validated_body_incomplete' || !Array.isArray(x.present) || x.present.length > partialHeaderNames.length || x.present.some(v => typeof v !== 'string' || !(partialHeaderNames as readonly string[]).includes(v)) || new Set(x.present).size !== x.present.length) throw new TypeError('Invalid partial headers');
}
