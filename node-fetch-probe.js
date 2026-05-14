const target = process.argv[2];
const timeoutMs = Number(process.argv[3] || 20000);

if (!target) {
  console.error("target argument is required");
  process.exit(2);
}

const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), timeoutMs);
const started = Date.now();

fetch(target, { signal: controller.signal })
  .then(async (response) => {
    const text = await response.text();
    clearTimeout(timeout);
    process.stdout.write(JSON.stringify({
      ok: true,
      statusCode: response.status,
      elapsedMs: Date.now() - started,
      bodySample: text.replace(/\s+/g, " ").slice(0, 240),
      error: null
    }));
  })
  .catch((error) => {
    clearTimeout(timeout);
    process.stdout.write(JSON.stringify({
      ok: false,
      statusCode: null,
      elapsedMs: Date.now() - started,
      bodySample: "",
      error: error && error.message ? error.message : String(error)
    }));
    process.exitCode = 1;
  });
