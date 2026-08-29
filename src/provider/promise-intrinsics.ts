const applyIntrinsic = Reflect.apply;
const PromiseIntrinsic = Promise;
const promiseResolveIntrinsic = PromiseIntrinsic.resolve;
const promiseThenIntrinsic = PromiseIntrinsic.prototype.then;

type PromiseExecutor<T> = (
  resolve: (value: T | PromiseLike<T>) => void,
  reject: (reason?: unknown) => void,
) => void;

export function createIntrinsicPromise<T>(executor: PromiseExecutor<T>): Promise<T> {
  return new PromiseIntrinsic<T>(executor);
}

export function resolveIntrinsicPromise<T>(value: T | PromiseLike<T>): Promise<Awaited<T>> {
  return applyIntrinsic(promiseResolveIntrinsic, PromiseIntrinsic, [value]) as Promise<
    Awaited<T>
  >;
}

export function thenIntrinsicPromise<T, TResult1 = T, TResult2 = never>(
  promise: Promise<T>,
  onFulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
  onRejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
): Promise<TResult1 | TResult2> {
  return applyIntrinsic(promiseThenIntrinsic, promise, [
    onFulfilled,
    onRejected,
  ]) as Promise<TResult1 | TResult2>;
}

export function raceIntrinsicPromises<T, U>(
  first: Promise<T>,
  second: Promise<U>,
): Promise<T | U> {
  return createIntrinsicPromise<T | U>((resolve, reject) => {
    void thenIntrinsicPromise(first, resolve, reject);
    void thenIntrinsicPromise(second, resolve, reject);
  });
}

export function ignoreIntrinsicPromiseRejection(value: unknown): void {
  const pending = resolveIntrinsicPromise(value);
  void thenIntrinsicPromise(pending, undefined, () => undefined);
}
