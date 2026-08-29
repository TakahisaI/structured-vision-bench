const applyIntrinsic = Reflect.apply;
const abortedGetterValue = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;
const addEventListenerIntrinsic = EventTarget.prototype.addEventListener;
const removeEventListenerIntrinsic = EventTarget.prototype.removeEventListener;
const once = Object.freeze({ once: true });

if (abortedGetterValue === undefined) throw new Error();
const abortedGetter = abortedGetterValue;

export function isAbortSignalAborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  return applyIntrinsic(abortedGetter, signal, []) as boolean;
}

export function addAbortSignalListener(
  signal: AbortSignal | undefined,
  listener: () => void,
): void {
  if (signal === undefined) return;
  applyIntrinsic(addEventListenerIntrinsic, signal, ["abort", listener, once]);
}

export function removeAbortSignalListener(
  signal: AbortSignal | undefined,
  listener: () => void,
): void {
  if (signal === undefined) return;
  applyIntrinsic(removeEventListenerIntrinsic, signal, ["abort", listener]);
}
