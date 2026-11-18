// Verify the committed Python bundle without needing Python in the Next.js build.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(webRoot, "..");
const digest = (data) => createHash("sha256").update(data).digest("hex");
const pythonSources = (directory, prefix) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
  const name = `${prefix}/${entry.name}`;
  if (entry.isDirectory()) return pythonSources(resolve(directory, entry.name), name);
  return entry.isFile() && entry.name.endsWith(".py") ? [name] : [];
});

try {
  const manifest = JSON.parse(readFileSync(resolve(webRoot, "scan-runtime.manifest.json"), "utf8"));
  if (manifest.format_version !== 1 || manifest.source_normalization !== "utf8-lf" ||
      manifest.archive?.name !== "scan-runtime.zip" || !Array.isArray(manifest.files) || !manifest.files.length) {
    throw new Error("Invalid session scanner manifest.");
  }
  const actualSources = [...pythonSources(resolve(repositoryRoot, "scanner"), "scanner"), "api/ephemeral.py"].sort();
  const recordedSources = manifest.files.map((file) => file.source).sort();
  if (JSON.stringify(actualSources) !== JSON.stringify(recordedSources)) {
    throw new Error("Session scanner source files were added or removed.");
  }
  for (const file of manifest.files) {
    if (typeof file.source !== "string" ||
        !(/^(scanner\/[^.][A-Za-z0-9_\/]*\.py)$/.test(file.source) || file.source === "api/ephemeral.py")) {
      throw new Error("Unexpected file in the session scanner manifest.");
    }
    const source = readFileSync(resolve(repositoryRoot, file.source), "utf8").replace(/\r\n/g, "\n");
    if (digest(source) !== file.sha256) {
      throw new Error(`Session scanner source changed: ${file.source}`);
    }
  }
  if (digest(readFileSync(resolve(webRoot, manifest.archive.name))) !== manifest.archive.sha256) {
    throw new Error("Session scanner archive checksum does not match its manifest.");
  }
  console.log(`Session scanner bundle verified (${manifest.files.length} source files).`);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Cannot verify the session scanner bundle.");
  console.error("Run python scripts/build_session_runtime.py, then commit the archive and manifest.");
  process.exitCode = 1;
}
