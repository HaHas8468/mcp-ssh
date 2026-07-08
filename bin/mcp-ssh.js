#!/usr/bin/env node

// Simple wrapper to run the main server.mjs file.
// We import main() explicitly and call it here instead of relying on a
// "is this module run directly?" check inside server.mjs. The latter is
// brittle on Windows because process.argv[1] uses backslashes while the
// check used forward-slash suffixes (fixes #8).
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const serverUrl = pathToFileURL(path.join(__dirname, '..', 'server.mjs')).href;
const { main } = await import(serverUrl);

main().catch((error) => {
  console.error(`Unhandled error: ${error?.message ?? error}`);
  process.exit(1);
});
