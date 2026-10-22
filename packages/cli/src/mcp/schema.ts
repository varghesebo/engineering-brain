/**
 * A minimal validator for the closed set of tool input schemas this server publishes (JSON Schema subset: object, string, integer, boolean, array, enum,
 * required, additionalProperties:false, bounds). Every argument is validated BEFORE any handler runs; unknown properties are rejected, not ignored.
 */
export type Schema =
  | { type: "string"; minLength?: number; maxLength: number; enum?: readonly string[]; description?: string }
  | { type: "integer"; minimum: number; maximum: number; description?: string }
  | { type: "boolean"; description?: string }
  | { type: "array"; items: Schema; minItems?: number; maxItems: number; description?: string }
  | { type: "object"; properties: Record<string, Schema>; required?: readonly string[]; additionalProperties: false; description?: string };

export class ValidationError extends Error {}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

export function validate(schema: Schema, value: unknown, at = "arguments"): void {
  switch (schema.type) {
    case "string":
      if (typeof value !== "string") {
        throw new ValidationError(`${at} must be a string`);
      }
      if (value.length < (schema.minLength ?? 0) || value.length > schema.maxLength) {
        throw new ValidationError(`${at} must be ${schema.minLength ?? 0}..${schema.maxLength} characters`);
      }
      if (CONTROL.test(value.replace(/[\n\t]/g, " "))) {
        throw new ValidationError(`${at} contains control characters`);
      }
      if (schema.enum !== undefined && !schema.enum.includes(value)) {
        throw new ValidationError(`${at} must be one of: ${schema.enum.join(", ")}`);
      }
      return;
    case "integer":
      if (typeof value !== "number" || !Number.isInteger(value) || value < schema.minimum || value > schema.maximum) {
        throw new ValidationError(`${at} must be an integer ${schema.minimum}..${schema.maximum}`);
      }
      return;
    case "boolean":
      if (typeof value !== "boolean") {
        throw new ValidationError(`${at} must be a boolean`);
      }
      return;
    case "array":
      if (!Array.isArray(value) || value.length < (schema.minItems ?? 0) || value.length > schema.maxItems) {
        throw new ValidationError(`${at} must be an array of ${schema.minItems ?? 0}..${schema.maxItems} items`);
      }
      value.forEach((item, i) => validate(schema.items, item, `${at}[${i}]`));
      return;
    case "object": {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new ValidationError(`${at} must be an object`);
      }
      const record = value as Record<string, unknown>;
      for (const key of Object.keys(record)) {
        if (!Object.hasOwn(schema.properties, key)) {
          throw new ValidationError(`${at}.${key} is not an accepted property`);
        }
      }
      for (const key of schema.required ?? []) {
        if (record[key] === undefined) {
          throw new ValidationError(`${at}.${key} is required`);
        }
      }
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (record[key] !== undefined) {
          validate(sub, record[key], `${at}.${key}`);
        }
      }
    }
  }
}

/** A repository-relative path argument: no absolute path, drive letter, backslash, NUL or `..` segment. The server still checks it against the index. */
export function isSafeRepoPath(path: string): boolean {
  return path.length > 0 && path.length <= 1024 && !path.startsWith("/") && !/^[A-Za-z]:/.test(path) && !path.includes("\\") && !path.includes("\0") &&
    !path.split("/").some((segment) => segment === ".." || segment === "." || segment === "");
}
