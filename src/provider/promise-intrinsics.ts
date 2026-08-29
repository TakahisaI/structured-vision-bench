const applyIntrinsic = Reflect.apply;
const definePropertyIntrinsic = Object.defineProperty;
const getOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const PromiseIntrinsic = Promise;
const promiseThenIntrinsic = PromiseIntrinsic.prototype.then;
const promiseConstructorDescriptor = getOwnPropertyDescriptorIntrinsic(
  PromiseIntrinsic.prototype,
  "constructor",
)!;
const promiseThenDescriptor = getOwnPropertyDescriptorIntrinsic(
  PromiseIntrinsic.prototype,
  "then",
)!;
const promiseSpeciesDescriptor = getOwnPropertyDescriptorIntrinsic(
  PromiseIntrinsic,
  Symbol.species,
)!;

type PromiseExecutor<T> = (
  resolve: (value: T | PromiseLike<T>) => void,
  reject: (reason?: unknown) => void,
) => void;

export function createIntrinsicPromise<T>(executor: PromiseExecutor<T>): Promise<T> {
  return hardenPromiseConstructor(new PromiseIntrinsic<T>(executor));
}

export function resolveIntrinsicPromise<T>(value: T | PromiseLike<T>): Promise<Awaited<T>> {
  return createIntrinsicPromise<Awaited<T>>((resolve) => {
    resolve(value as Awaited<T> | PromiseLike<Awaited<T>>);
  });
}

export function thenIntrinsicPromise<T, TResult1 = T, TResult2 = never>(
  promise: Promise<T>,
  onFulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
  onRejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
): Promise<TResult1 | TResult2> {
  return hardenPromiseConstructor(
    applyIntrinsic(promiseThenIntrinsic, promise, [
      onFulfilled,
      onRejected,
    ]) as Promise<TResult1 | TResult2>,
  );
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

/**
 * Invokes an untrusted callback and adopts only its native Promise result.
 * Promise metadata is restored before the captured native `then` observes the
 * result, so callback mutations cannot alter the internal settlement path.
 */
export function invokeIntrinsicPromiseCallback<T>(callback: () => unknown): Promise<T> {
  let value: unknown;
  try {
    value = callback();
  } finally {
    restoreIntrinsicPromiseMetadata();
  }
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return createIntrinsicPromise<T>((_resolve, reject) => reject(new Error()));
  }
  try {
    const promise = hardenPromiseConstructor(value as Promise<T>);
    // Brand-check and mark a possible rejection handled without interposing an
    // additional settlement Promise. Returning the original hardened Promise
    // preserves the callback boundary's microtask ordering for final checks.
    void thenIntrinsicPromise(promise, () => undefined, () => undefined);
    return promise;
  } catch {
    return createIntrinsicPromise<T>((_resolve, reject) => reject(new Error()));
  }
}

export function ignoreIntrinsicPromiseRejection(value: unknown): void {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return;
  }
  try {
    restoreIntrinsicPromiseMetadata();
    hardenPromiseConstructor(value as Promise<unknown>);
    void thenIntrinsicPromise(value as Promise<unknown>, undefined, () => undefined);
  } catch {
    // The finalizer contract rejects every non-undefined value. Rejection
    // disposal remains best effort when the returned object is not a native
    // Promise or has already made its metadata non-configurable.
  }
}

export function restoreIntrinsicPromiseConstructor(): void {
  restoreIntrinsicPromiseMetadata();
}

export function restoreIntrinsicPromiseMetadata(): void {
  definePropertyIntrinsic(
    PromiseIntrinsic.prototype,
    "constructor",
    promiseConstructorDescriptor,
  );
  definePropertyIntrinsic(PromiseIntrinsic.prototype, "then", promiseThenDescriptor);
  definePropertyIntrinsic(PromiseIntrinsic, Symbol.species, promiseSpeciesDescriptor);
}

function hardenPromiseConstructor<T>(promise: Promise<T>): Promise<T> {
  definePropertyIntrinsic(promise, "constructor", {
    configurable: false,
    value: PromiseIntrinsic,
    writable: false,
  });
  return promise;
}
