import picomatch from "picomatch";

/**
 * Path-based exclusions (default deny). Content-based exclusions (binary, invalid UTF-8, secrets) happen in
 * the indexer after a bounded read. Users can ADD patterns through config; nothing here can be disabled.
 */
const EXCLUDED_DIRECTORIES = new Set([
  ".git", ".hg", ".svn", "node_modules", ".engineering-brain",
  "dist", "build", "out", "coverage", ".next", ".nuxt", "__pycache__", ".venv", "venv", ".gradle", ".idea"
]);

const SENSITIVE_PATTERNS = [
  "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore",
  "**/id_rsa*", "**/id_dsa*", "**/id_ecdsa*", "**/id_ed25519*", "**/.npmrc", "**/.netrc", "**/.pypirc",
  "**/.htpasswd", "**/credentials*", "**/*.kdbx", "**/*.tfstate", "**/*.tfstate.*",
  "**/.aws/**", "**/.ssh/**", "**/.gnupg/**"
];

const GENERATED_PATTERNS = ["**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/*.min.js", "**/*.min.css", "**/*.map"];
const LOG_PATTERNS = ["**/*.log"];
const BINARY_EXTENSIONS = [
  "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "pdf", "zip", "gz", "tgz", "tar", "7z", "rar",
  "jar", "war", "class", "exe", "dll", "so", "dylib", "bin", "o", "a", "woff", "woff2", "ttf", "otf",
  "eot", "mp3", "mp4", "mov", "avi", "wasm", "sqlite", "sqlite3", "db"
];

/** Names that are matched case-insensitively: on case-insensitive filesystems `.GIT`/`.ENGINEERING-BRAIN` are the same directory. */
const FOLDED_DIRECTORIES = new Set([".git", ".engineering-brain"]);

const isExcludedDirectoryName = (name: string): boolean => EXCLUDED_DIRECTORIES.has(name) || FOLDED_DIRECTORIES.has(name.toLowerCase());

export type ExclusionReason =
  | "excluded_directory"
  | "sensitive_path"
  | "generated"
  | "log"
  | "binary_extension"
  | "config_exclude";

export interface ExclusionMatcher {
  /** Directory pruning for walks. */
  excludesDirectory(name: string): boolean;
  /** Reason a repo-relative file path is excluded, or null. */
  excludesPath(storePath: string): ExclusionReason | null;
}

const MATCH_OPTIONS = { dot: true, nocase: true } as const;

export function createExclusionMatcher(extraPatterns: readonly string[] = []): ExclusionMatcher {
  const sensitive = picomatch([...SENSITIVE_PATTERNS], MATCH_OPTIONS);
  const generated = picomatch([...GENERATED_PATTERNS], MATCH_OPTIONS);
  const logs = picomatch([...LOG_PATTERNS], MATCH_OPTIONS);
  const binary = picomatch(`**/*.{${BINARY_EXTENSIONS.join(",")}}`, MATCH_OPTIONS);
  const custom = extraPatterns.length > 0 ? picomatch([...extraPatterns], MATCH_OPTIONS) : null;

  return {
    excludesDirectory: isExcludedDirectoryName,
    excludesPath(storePath) {
      if (storePath.split("/").some(isExcludedDirectoryName)) {
        return "excluded_directory";
      }
      if (sensitive(storePath)) {
        return "sensitive_path";
      }
      if (generated(storePath)) {
        return "generated";
      }
      if (logs(storePath)) {
        return "log";
      }
      if (binary(storePath)) {
        return "binary_extension";
      }
      if (custom !== null && custom(storePath)) {
        return "config_exclude";
      }
      return null;
    }
  };
}
