const applyIntrinsic = Reflect.apply;
const abortedGetterValue = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;
const addEventListenerIntrinsic = EventTarget.prototype.addEventListener;
const removeEventListenerIntrinsic = EventTarget.prototype.removeEventListener;
const AbortControllerIntrinsic = AbortController;
const abortControllerIntrinsic = AbortController.prototype.abort;
const abortControllerSignalGetterValue = Object.getOwnPropertyDescriptor(
  AbortController.prototype,
  "signal",
)?.get;
const once = Object.freeze({ once: true });

if (
  abortedGetterValue === undefined ||
  abortControllerSignalGetterValue === undefined
) {
  throw new Error();
}
const abortedGetter = abortedGetterValue;
const abortControllerSignalGetter = abortControllerSignalGetterValue;

export function createAbortController(): AbortController {
  return new AbortControllerIntrinsic();
}

export function abortControllerSignal(controller: AbortController): AbortSignal {
  return applyIntrinsic(abortControllerSignalGetter, controller, []) as AbortSignal;
}

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

export function abortController(controller: AbortController | undefined): void {
  if (controller === undefined) return;
  applyIntrinsic(abortControllerIntrinsic, controller, []);
}
