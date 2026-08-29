const applyIntrinsic = Reflect.apply;
const definePropertyIntrinsic = Object.defineProperty;
const getOwnPropertyDescriptorIntrinsic = Object.getOwnPropertyDescriptor;
const PromiseIntrinsic = Promise;
const promiseThenIntrinsic = PromiseIntrinsic.prototype.then;
const promiseConstructorDescriptor = getOwnPropertyDescriptorIntrinsic(
  PromiseIntrinsic.prototype,
  "constructor",
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

export function ignoreIntrinsicPromiseRejection(value: unknown): void {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") {
    return;
  }
  try {
    definePropertyIntrinsic(value, "constructor", {
      configurable: true,
      value: PromiseIntrinsic,
      writable: true,
    });
  } catch {
    // A non-extensible native Promise still uses the restored intrinsic
    // prototype constructor and can be safely assimilated below.
  }
  const pending = resolveIntrinsicPromise(value);
  void thenIntrinsicPromise(pending, undefined, () => undefined);
}

export function restoreIntrinsicPromiseConstructor(): void {
  definePropertyIntrinsic(
    PromiseIntrinsic.prototype,
    "constructor",
    promiseConstructorDescriptor,
  );
}

function hardenPromiseConstructor<T>(promise: Promise<T>): Promise<T> {
  definePropertyIntrinsic(promise, "constructor", {
    configurable: false,
    value: PromiseIntrinsic,
    writable: false,
  });
  return promise;
}
