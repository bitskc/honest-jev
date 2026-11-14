// Interval arithmetic for jev-eval. Every proportion the runner prints carries n and a named method.
//   wilson(k, n)        two-sided 95% Wilson score interval for a proportion
//   zeroUpper95(n)      one-sided exact 95% upper bound on a rate after 0 events in n trials: 1 - 0.05^(1/n)
// Different methods, so reports name the method beside each figure (a two-sided interval and a one-sided bound are not
// interchangeable).
const Z95 = 1.959963984540054;

export function wilson(k, n, z = Z95) {
  if (!(n > 0)) return null;
  const p = k / n, d = 1 + (z * z) / n;
  const centre = (p + (z * z) / (2 * n)) / d;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return { low: Math.max(0, centre - half), high: Math.min(1, centre + half) };
}

export function zeroUpper95(n) {
  return n > 0 ? 1 - Math.pow(0.05, 1 / n) : 1;
}

/** {k, n, p, low, high, method} for a proportion, or p/low/high null when n is 0. */
export function proportion(k, n) {
  const w = wilson(k, n);
  return { k, n, p: n > 0 ? k / n : null, low: w ? w.low : null, high: w ? w.high : null, method: "wilson-95-two-sided" };
}
