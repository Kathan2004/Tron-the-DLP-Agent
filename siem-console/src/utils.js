// Small shared helpers.

// Run a state-updating loader after the current effect, so effects only start async work
// (avoids synchronous setState inside useEffect and cascading renders).
export const runSoon = (fn) => {
  let cancelled = false;
  Promise.resolve().then(() => { if (!cancelled) fn(); });
  return () => { cancelled = true; };
};

export const cleanKeywords = (k) => (Array.isArray(k) ? k.map(x => String(x).trim()).filter(Boolean) : []);
