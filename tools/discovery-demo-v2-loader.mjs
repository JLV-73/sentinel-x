export async function resolve(specifier, context, nextResolve) {
  if (specifier === './discoveryReport' && context.parentURL?.endsWith('/frontend/src/discoveryLabAdapter.ts'))
    return nextResolve('./discoveryReport.ts', context);
  return nextResolve(specifier, context);
}
