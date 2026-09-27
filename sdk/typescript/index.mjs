export class PGWSError extends Error {
  constructor(status, body) {
    super(body.code ?? "HTTP_ERROR");
    this.status = status;
    this.code = body.code ?? "HTTP_ERROR";
    this.retryable = body.retryable === true;
    this.body = body;
  }
}
const id = value => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new TypeError("Invalid resource UUID");
  return value.toLowerCase();
};
export class Client {
  #url; #token; #timeout;
  constructor({url, projectId, token, timeout = 15000}) {
    const u = new URL(url);
    const local = u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.username || u.password || u.search || u.hash || !(u.protocol === "https:" || u.protocol === "http:" && local)) throw new TypeError("Use HTTPS or an explicit loopback HTTP address");
    if (!token || !Number.isFinite(timeout) || timeout <= 0) throw new TypeError("Token and positive timeout are required");
    this.#url = url.replace(/\/$/, "") + "/v1/projects/" + id(projectId);
    this.#token = token; this.#timeout = timeout;
  }
  async #request(method, path, body, key, signal, timeout = this.#timeout) {
    if (method !== "GET" && (!key || new TextEncoder().encode(key).length > 200)) throw new TypeError("A stable idempotency key of 1 to 200 bytes is required");
    const headers = {Authorization: "Bearer " + this.#token, "Content-Type": "application/json"};
    if (key) headers["Idempotency-Key"] = key;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined && new TextEncoder().encode(payload).length > 1 << 20) throw new TypeError("Request exceeds 1 MiB");
    const deadline = AbortSignal.timeout(Math.max(1, Math.ceil(timeout)));
    const response = await fetch(this.#url + path, {method, headers, body: payload, redirect: "manual", signal: signal ? AbortSignal.any([deadline, signal]) : deadline});
    const reader = response.body?.getReader();
    const chunks = []; let size = 0;
    if (reader) for (;;) {
      const {value, done} = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > 2 << 20) { await reader.cancel(); throw new Error("Response exceeds 2 MiB"); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let result;
    try { result = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { if (!response.ok) throw new PGWSError(response.status, {}); throw new Error("Invalid JSON response"); }
    if (result === null || typeof result !== "object" || Array.isArray(result)) throw new Error("Response must be an object");
    if (!response.ok) throw new PGWSError(response.status, result);
    return result;
  }
  registerSource(endpoint, secret, key, signal) { return this.#request("POST", "/sources", {connector:"physical", approved_endpoint_reference:endpoint, secret_reference:secret}, key, signal); }
  source(sourceId, signal) { return this.#request("GET", "/sources/" + id(sourceId), undefined, undefined, signal); }
  reseedSource(sourceId, expectedSourceEpoch, key, signal) {
    if (!Number.isSafeInteger(expectedSourceEpoch) || expectedSourceEpoch < 1 || expectedSourceEpoch >= 1e9) throw new TypeError("Source epoch must be a positive integer below one billion");
    return this.#request("POST", "/sources/" + id(sourceId) + "/actions", {action:"reseed", expected_source_epoch:expectedSourceEpoch}, key, signal);
  }
  baselines({cursor, limit = 100, signal} = {}) { const query = new URLSearchParams({limit:String(limit)}); if (cursor !== undefined) query.set("cursor", cursor); return this.#request("GET", "/baselines?" + query, undefined, undefined, signal); }
  usage({cursor, limit = 100, signal} = {}) { const query = new URLSearchParams({limit:String(limit)}); if (cursor !== undefined) query.set("cursor", cursor); return this.#request("GET", "/usage?" + query, undefined, undefined, signal); }
  barrier(sourceId, key, signal) { return this.#request("POST", "/sources/" + id(sourceId) + "/barriers", {after_commit_asserted:true}, key, signal); }
  create(request, key, signal) { return this.#request("POST", "/workspaces", request, key, signal); }
  get(workspaceId, signal) { return this.#request("GET", "/workspaces/" + id(workspaceId), undefined, undefined, signal); }
  action(workspaceId, request, key, signal) { return this.#request("POST", "/workspaces/" + id(workspaceId) + "/actions", request, key, signal); }
  credentials(workspaceId, request, key, signal) { return this.#request("POST", "/workspaces/" + id(workspaceId) + "/credentials", request, key, signal); }
  delete(workspaceId, generation, key, signal) {
    if (!Number.isSafeInteger(generation) || generation < 1) throw new TypeError("Generation must be a positive integer");
    return this.#request("DELETE", "/workspaces/" + id(workspaceId) + "?expected_generation=" + generation, undefined, key, signal);
  }
  operation(operationId, signal) { return this.#request("GET", "/operations/" + id(operationId), undefined, undefined, signal); }
  async wait(operationId, {timeout = 120000, interval = 250, signal} = {}) {
    if (!Number.isFinite(timeout) || !Number.isFinite(interval) || timeout <= 0 || interval <= 0) throw new TypeError("Wait timeout and interval must be positive");
    const end = performance.now() + timeout;
    for (;;) {
      const remaining = end - performance.now();
      if (remaining <= 0) throw new Error("Operation remains recorded; inspect it before retrying");
      const result = await this.#request("GET", "/operations/" + id(operationId), undefined, undefined, signal, Math.min(this.#timeout, remaining));
      if (result.status === "succeeded") return result;
      if (result.status === "failed" || result.status === "cancelled") throw new PGWSError(409, result.error ?? {code: "OPERATION_" + result.status.toUpperCase()});
      if (result.status !== "queued" && result.status !== "running") throw new Error("Unknown operation status");
      await new Promise((resolve, reject) => {
        const abort = () => { clearTimeout(timer); reject(signal.reason); };
        const timer = setTimeout(() => { signal?.removeEventListener("abort", abort); resolve(); }, Math.min(interval, Math.max(0, end - performance.now())));
        if (signal?.aborted) abort(); else signal?.addEventListener("abort", abort, {once:true});
      });
    }
  }
}
