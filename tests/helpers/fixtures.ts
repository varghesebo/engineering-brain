/**
 * Deterministic SYNTHETIC repository content (original, redistributable, no customer data).
 * Planted "secrets" are assembled at runtime from fragments so no secret-shaped literal exists in the repo.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function generateRepoFiles(count: number, seed = 1): Map<string, string> {
  const random = mulberry32(seed);
  const files = new Map<string, string>();
  for (let i = 0; i < count; i += 1) {
    const dir = `src/m${i % 7}`;
    const functions = 1 + Math.floor(random() * 4);
    let body = i > 0 ? `import { fn${i - 1}_0 } from "../m${(i - 1) % 7}/file${i - 1}";\n` : "";
    for (let f = 0; f < functions; f += 1) {
      body += `export function fn${i}_${f}(a: number): number {\n  return a + ${Math.floor(random() * 1000)};\n}\n`;
    }
    files.set(`${dir}/file${i}.ts`, body);
  }
  files.set("README.md", "# Synthetic fixture\n\nGenerated for tests.\n");
  return files;
}

export const FAKE_SECRETS = {
  awsKey: (): string => ["AK", "IA", "ABCDEFGH", "IJKLMNOP"].join(""),
  githubToken: (): string => ["gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join(""),
  privateKeyHeader: (): string => ["-----BEGIN ", "RSA PRIVATE", " KEY-----"].join(""),
  slackToken: (): string => ["xo", "xb-", "1234567890-abcdefghij"].join(""),
  passwordAssignment: (): string => `const password = "${["hunter", "2-correct-horse"].join("")}";`,
  urlCredentials: (): string => ["post", "gres://", "admin:", "s3cr3tpass", "@db.internal/app"].join("")
};
