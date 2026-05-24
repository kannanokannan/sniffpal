/**
 * AI inference layer for SniffPal — two-tier design.
 *
 * Tier 1 — Chrome Built-in AI (no download, instant when available):
 *   • Summarizer API  — for session summaries
 *   • LanguageModel API — for per-finding explanations
 *   Both checked via `'Summarizer' in self` / `'LanguageModel' in self` so
 *   accessing them never throws ReferenceError on non-Chrome browsers.
 *
 * Tier 2 — HuggingFace Transformers.js + SmolLM2-360M-Instruct (~200 MB)
 *   Loaded via dynamic import ONLY after the user uploads a capture file.
 *   Falls back to hf-mirror.com if huggingface.co fails.
 *   Pipeline is cached globally — never reloaded between calls.
 *
 * Status values (returned by getAIStatus / probeStatus):
 *   "both"          Both Chrome Summarizer + LanguageModel ready
 *   "summarizer"    Only Summarizer ready
 *   "languagemodel" Only LanguageModel ready
 *   "downloading"   A Chrome model is currently downloading
 *   "transformers"  Transformers.js pipeline ready
 *   "loading"       Transformers.js model currently downloading
 *   "unavailable"   Nothing could be loaded
 *
 * Rules:
 *   • Always try Chrome APIs first — zero download cost
 *   • If either Chrome API is available, skip Transformers.js entirely
 *   • Transformers.js is NEVER imported before initAI() is called by the app
 *   • Every inference call has a hard 30-second timeout
 *   • Every error is caught and logged; nothing crashes the app
 */

// ── Module-level state ────────────────────────────────────────────────────────

/** @type {"both"|"summarizer"|"languagemodel"|"downloading"|"transformers"|"loading"|"unavailable"} */
let _status = 'unavailable';

/** Cached Transformers.js text-generation pipeline (never reloaded) */
let _pipeline = null;

/** Prevents concurrent initAI() runs */
let _initPromise = null;

const SYSTEM_PROMPT =
  'You are a home network security assistant. ' +
  'Explain each finding in plain English for a non-technical user. ' +
  'Max 2 sentences per finding. No jargon.';

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Race a promise against a hard timeout. */
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('AI timeout')), ms)
    ),
  ]);
}

// ── Chrome API probes ─────────────────────────────────────────────────────────
// Use `'API' in self` guards instead of bare global access so ReferenceError
// never escapes on Firefox / Safari.

async function getSummarizerStatus() {
  try {
    if (!('Summarizer' in self)) return 'unavailable';
    // eslint-disable-next-line no-undef
    return await Summarizer.availability();
  } catch {
    return 'unavailable';
  }
}

async function getLMStatus() {
  try {
    if (!('LanguageModel' in self)) return 'unavailable';
    // eslint-disable-next-line no-undef
    return await LanguageModel.availability();
  } catch {
    return 'unavailable';
  }
}

// ── Chrome session factories ──────────────────────────────────────────────────

async function createSummarizer(onProgress) {
  try {
    // eslint-disable-next-line no-undef
    return await Summarizer.create({
      type: 'key-points',
      format: 'plain-text',
      length: 'medium',
      expectedInputLanguages: ['en'],
      outputLanguage: 'en',
      monitor(m) {
        m.addEventListener('downloadprogress', (e) => {
          onProgress?.(Math.round(e.loaded * 100));
        });
      },
    });
  } catch {
    return null;
  }
}

async function createLMSession() {
  try {
    // eslint-disable-next-line no-undef
    return await LanguageModel.create({
      systemPrompt: SYSTEM_PROMPT,
      expectedInputLanguages: ['en'],
      expectedOutputLanguages: ['en'],
    });
  } catch {
    return null;
  }
}

// ── Transformers.js inference ─────────────────────────────────────────────────

async function runTransformers(userPrompt) {
  if (!_pipeline) return null;
  try {
    const messages = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user',   content: userPrompt },
    ];
    const result = await _pipeline(messages, { max_new_tokens: 200, do_sample: false });
    const gen = result[0]?.generated_text;
    if (typeof gen === 'string') return gen.trim() || null;
    if (Array.isArray(gen))      return gen.at(-1)?.content?.trim() || null;
    return null;
  } catch (err) {
    console.error('[SniffPal] Transformers inference failed:', err);
    return null;
  }
}

// ── Initialisation ────────────────────────────────────────────────────────────

async function _doInit(onProgress) {
  // ── Step 1: probe both Chrome APIs in parallel ──
  const [summStatus, lmStatus] = await Promise.all([
    getSummarizerStatus(),
    getLMStatus(),
  ]);

  const summReady     = summStatus === 'available';
  const lmReady       = lmStatus   === 'available';
  const anyDownloading = summStatus === 'downloading' || lmStatus === 'downloading';

  if (summReady && lmReady) { _status = 'both';          return; }
  if (summReady)             { _status = 'summarizer';    return; }
  if (lmReady)               { _status = 'languagemodel'; return; }
  if (anyDownloading)        { _status = 'downloading';   return; }

  // ── Step 2: Transformers.js fallback ───────────
  try {
    _status = 'loading';
    onProgress?.(0, 'Loading AI model…');

    const { pipeline, env } = await import('@huggingface/transformers');
    env.allowLocalModels = false;

    const pipelineOpts = {
      dtype: 'q4',
      progress_callback: ({ status, progress }) => {
        if (status === 'progress') {
          const pct = Math.round(progress ?? 0);
          onProgress?.(pct, `Downloading AI model (${pct}%)… First time only (~200 MB)`);
        } else if (status === 'ready') {
          onProgress?.(100, 'AI model ready');
        }
      },
    };

    // Primary host → mirror fallback, both guarded by a 10-second AbortController
    // so a hung HuggingFace fetch never freezes the page.
    const controller = new AbortController();
    const abortTimer = setTimeout(() => controller.abort(), 10_000);
    try {
      env.fetchOptions = { signal: controller.signal };
      try {
        _pipeline = await pipeline(
          'text-generation', 'HuggingFaceTB/SmolLM2-360M-Instruct', pipelineOpts
        );
      } catch (err1) {
        if (controller.signal.aborted) throw err1; // timed out — skip mirror
        console.warn('[SniffPal] HuggingFace primary failed, trying hf-mirror.com:', err1.message);
        env.remoteHost = 'https://hf-mirror.com';
        _pipeline = await pipeline(
          'text-generation', 'HuggingFaceTB/SmolLM2-360M-Instruct', pipelineOpts
        );
      }
    } catch (e) {
      console.log('[SniffPal] Transformers.js unreachable, using templates');
      _status = 'unavailable';
      return;
    } finally {
      clearTimeout(abortTimer);
    }

    _status = 'transformers';
    onProgress?.(100, 'AI model ready');
  } catch (err) {
    console.error('[SniffPal] Transformers.js init failed:', err);
    _status = 'unavailable';
  }
}

/**
 * Initialise AI — call this ONLY after the user uploads a capture file.
 * Tries Chrome APIs first; falls back to Transformers.js only if both
 * Chrome APIs are unavailable. Safe to call multiple times.
 *
 * @param {(percent: number, message: string) => void} [onProgress]
 */
export async function initAI(onProgress) {
  // Already in a terminal ready/in-progress state — no-op
  if (['both','summarizer','languagemodel','transformers','downloading'].includes(_status)) return;
  // Coalesce concurrent calls
  if (_initPromise) return _initPromise;
  // Defer actual work to the next event-loop tick so initAI() never blocks
  // the current render frame — critical for keeping UI responsive on slow networks.
  _initPromise = new Promise(resolve => setTimeout(resolve, 0))
    .then(() => _doInit(onProgress))
    .finally(() => { _initPromise = null; });
  return _initPromise;
}

/**
 * Lightweight Chrome-only probe — safe to call on mount.
 * Never imports Transformers.js, never modifies module state.
 *
 * @returns {Promise<"both"|"summarizer"|"languagemodel"|"downloading"|"unavailable">}
 */
export async function probeStatus() {
  const [summStatus, lmStatus] = await Promise.all([
    getSummarizerStatus(),
    getLMStatus(),
  ]);
  const summReady      = summStatus === 'available';
  const lmReady        = lmStatus   === 'available';
  const anyDownloading = summStatus === 'downloading' || lmStatus === 'downloading';

  if (summReady && lmReady) return 'both';
  if (summReady)             return 'summarizer';
  if (lmReady)               return 'languagemodel';
  if (anyDownloading)        return 'downloading';
  return 'unavailable';
}

/**
 * Synchronously return the current AI tier status.
 * @returns {"both"|"summarizer"|"languagemodel"|"downloading"|"transformers"|"loading"|"unavailable"}
 */
export function getAIStatus() {
  return _status;
}

/**
 * Backward-compat helper — returns true only when Chrome LanguageModel is ready.
 * @returns {Promise<boolean>}
 */
export async function isGeminiNanoAvailable() {
  try {
    if (!('LanguageModel' in self)) return false;
    // eslint-disable-next-line no-undef
    const s = await LanguageModel.availability();
    return s === 'available';
  } catch {
    return false;
  }
}

// ── Public inference API ──────────────────────────────────────────────────────

/**
 * Explain up to 5 findings in plain English.
 * Uses LanguageModel if available, else Transformers.js.
 *
 * @param {Array<{id:string,title:string,description:string,fix:string}>} findings
 * @returns {Promise<Array<{id:string,explanation:string}>|null>}
 */
export async function explainFindings(findings) {
  if (!findings || findings.length === 0) return null;

  const slice = findings.slice(0, 5);
  const results = [];

  const buildPrompt = (f) =>
    `Finding: ${f.title}\n` +
    `Detail: ${f.description}\n` +
    `Fix: ${f.fix}\n\n` +
    `Explain in 1–2 plain-English sentences what this means for a home user ` +
    `and whether they need to act.`;

  const useLM = _status === 'both' || _status === 'languagemodel';
  const useTF = _status === 'transformers';

  if (useLM) {
    const session = await createLMSession();
    if (!session) return null;
    try {
      for (const f of slice) {
        try {
          const text = await withTimeout(session.prompt(buildPrompt(f)), 30_000);
          results.push({ id: f.id, explanation: text.trim() });
        } catch { /* skip individual failures */ }
      }
    } finally {
      session.destroy?.();
    }
  } else if (useTF) {
    for (const f of slice) {
      try {
        const text = await withTimeout(runTransformers(buildPrompt(f)), 30_000);
        if (text) results.push({ id: f.id, explanation: text });
      } catch { /* skip */ }
    }
  }

  return results.length > 0 ? results : null;
}

/**
 * Generate a 2–3 sentence plain-English session summary.
 * Priority: Summarizer → LanguageModel → Transformers.js
 *
 * @param {number} deviceCount
 * @param {{critical:number,warning:number,info:number}} findingCounts
 * @param {Array<{title:string,description:string}>} topFindings
 * @returns {Promise<string|null>}
 */
export async function summarizeSession(deviceCount, findingCounts, topFindings) {
  const top = (topFindings || [])
    .slice(0, 3)
    .map((f, i) => `${i + 1}. ${f.title}: ${f.description}`)
    .join('\n');

  // Plain-text input for the Summarizer API
  const summarizerInput =
    `Network scan: ${deviceCount} devices. ` +
    `${findingCounts.critical || 0} critical alerts, ` +
    `${findingCounts.warning  || 0} warnings, ` +
    `${findingCounts.info     || 0} informational findings. ` +
    (top ? `Key findings: ${top}` : 'No significant findings.');

  // Instructional prompt for LanguageModel / Transformers.js
  const lmPrompt =
    `Network capture summary:\n` +
    `• ${deviceCount} devices detected\n` +
    `• ${findingCounts.critical || 0} critical alerts, ` +
    `${findingCounts.warning  || 0} warnings, ` +
    `${findingCounts.info     || 0} info findings\n` +
    (top ? `\nTop findings:\n${top}\n` : '') +
    `\nWrite a 2–3 sentence plain-English summary. Is the network safe?`;

  const useSummarizer = _status === 'both' || _status === 'summarizer';
  const useLM         = _status === 'both' || _status === 'languagemodel';
  const useTF         = _status === 'transformers';

  // 1. Chrome Summarizer
  if (useSummarizer) {
    const summarizer = await createSummarizer();
    if (summarizer) {
      try {
        const out = await withTimeout(summarizer.summarize(summarizerInput), 30_000);
        return out.trim();
      } catch {
        // fall through to LM
      }
    }
  }

  // 2. Chrome LanguageModel
  if (useLM) {
    const session = await createLMSession();
    if (session) {
      try {
        return (await withTimeout(session.prompt(lmPrompt), 30_000)).trim();
      } catch {
        return null;
      } finally {
        session.destroy?.();
      }
    }
  }

  // 3. Transformers.js
  if (useTF) {
    try {
      return await withTimeout(runTransformers(lmPrompt), 20_000);
    } catch {
      return null;
    }
  }

  return null;
}
