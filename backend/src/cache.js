// Tiny in-memory TTL cache. Verdicts are cheap to recompute and this process
// is single-instance for the MVP, so a Map is plenty. Swap for Redis if you
// scale to multiple instances.
export class TtlCache {
  constructor(ttlMs) {
    this.ttl = ttlMs;
    this.store = new Map();
  }

  get(key) {
    const hit = this.store.get(key);
    if (!hit) return null;
    if (Date.now() - hit.ts > this.ttl) {
      this.store.delete(key);
      return null;
    }
    return hit.value;
  }

  set(key, value) {
    this.store.set(key, { value, ts: Date.now() });
  }
}
