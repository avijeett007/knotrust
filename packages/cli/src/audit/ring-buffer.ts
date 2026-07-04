/**
 * A bounded ring (circular) buffer keeping only the last `capacity` items
 * pushed — O(capacity) memory regardless of how many items are ever pushed
 * (P0-E4-T4, R123: "a ring buffer streaming forward keeping last N is O(N)
 * memory and acceptable"). This is what `knotrust audit list|tail` build
 * their `-n`-limited window on top of while consuming
 * `@knotrust/store`'s `streamAuditEvents` generator — the log itself is
 * walked forward exactly once, never held in memory beyond this bounded
 * window.
 */
export interface RingBuffer<T> {
  push(item: T): void;
  /** Items in original insertion order (oldest first), oldest-evicted once over capacity. */
  toArray(): T[];
}

export function createRingBuffer<T>(capacity: number): RingBuffer<T> {
  if (!Number.isSafeInteger(capacity) || capacity <= 0) {
    throw new Error(
      `createRingBuffer: capacity must be a positive integer, got ${capacity}`,
    );
  }
  const buf: T[] = [];
  let start = 0; // index of the OLDEST element, once buf.length === capacity

  return {
    push(item: T): void {
      if (buf.length < capacity) {
        buf.push(item);
        return;
      }
      buf[start] = item;
      start = (start + 1) % capacity;
    },
    toArray(): T[] {
      if (buf.length < capacity) return [...buf];
      return [...buf.slice(start), ...buf.slice(0, start)];
    },
  };
}
