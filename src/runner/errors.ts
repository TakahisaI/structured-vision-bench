import { boundDetails } from "../bundle/validate-bundle.js";

export type RunnerErrorCode =
  | "run_configuration_invalid"
  | "provider_invalid"
  | "provider_failed"
  | "provider_timeout"
  | "provider_response_invalid"
  | "provider_document_too_large"
  | "approval_required"
  | "approval_configuration_invalid"
  | "approval_denied"
  | "approval_timeout"
  | "approval_response_invalid"
  | "sanitizer_required"
  | "sanitizer_requirement_invalid"
  | "sanitizer_configuration_invalid"
  | "sanitizer_policy_missing"
  | "sanitizer_policy_invalid"
  | "sanitizer_policy_target_mismatch"
  | "sanitizer_policy_identity_mismatch"
  | "sanitizer_policy_binding_mismatch"
  | "sanitizer_failed"
  | "sanitizer_timeout"
  | "sanitizer_response_invalid"
  | "provider_document_schema_invalid"
  | "runner_bundle_changed_after_approval"
  | "attempt_exists"
  | "attempt_invalid"
  | "attempt_identity_mismatch"
  | "attempt_document_digest_mismatch"
  | "attempt_write_failed"
  | "runner_input_unreadable"
  | "internal_error";

const MAX_RUNNER_MESSAGE_LENGTH = 240;

export class RunnerError extends Error {
  readonly code: RunnerErrorCode;
  readonly details: string[];

  constructor(code: RunnerErrorCode, message: string, details: string[] = []) {
    super(message.length <= MAX_RUNNER_MESSAGE_LENGTH ? message : `${message.slice(0, 239)}…`);
    this.name = "RunnerError";
    this.code = code;
    this.details = boundDetails(details);
  }
}

export function isRunnerError(error: unknown): error is RunnerError {
  return error instanceof RunnerError;
}
