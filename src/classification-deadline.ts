/** Bound hook completion even when an SDK cleanup promise ignores cancellation. */
export function withClassificationDeadline<T>(
  timeoutMs: number,
  classify: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const signal = AbortSignal.timeout(Math.min(timeoutMs, 8000));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve().then(() => classify(signal)).then(
      (result) => {
        signal.removeEventListener("abort", onAbort);
        resolve(result);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}
