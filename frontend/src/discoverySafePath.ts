// Only a closed vocabulary is displayable; never treat this as a network URL.
const segments = new Set(['login','account','admin','api','users','products','search','{segment}','{id}']);
export function isSanitizedPath(value: unknown): value is string {
 if (typeof value !== 'string' || value.length > 128 || !value.startsWith('/')) return false;
 if (value === '/') return true;
 const parts = value.slice(1).split('/');
 return parts.length <= 20 && parts.every(part => segments.has(part));
}
