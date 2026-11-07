/**
 * AI providers for --ai. Each one only turns (system, user) into a JSON string
 * {"explanation": …, "fix": …}. Keys come from the user's environment and are
 * never logged or written anywhere.
 */
import type { FetchLike } from '../osv';

export type AiProviderId = 'claude' | 'openai' | 'ollama';
export const AI_PROVIDERS: readonly AiProviderId[] = ['claude', 'openai', 'ollama'];

export interface AiRequest {
  system: string;
  user: string;
}

export interface AiProvider {
  id: AiProviderId;
  model: string;
  /** Raw text of the answer (expected to be the JSON object). Rejects on any failure. */
  complete(req: AiRequest, signal: AbortSignal): Promise<string>;
}

/** JSON schema of the answer, shared by every provider. */
export const ADVICE_SCHEMA = {
  type: 'object',
  properties: {
    explanation: { type: 'string' },
    fix: { type: 'string' },
  },
  required: ['explanation', 'fix'],
  additionalProperties: false,
} as const;

export const DEFAULT_MODELS: Record<AiProviderId, string> = {
  claude: 'claude-opus-5-5',
  openai: 'gpt-4o-mini',
  ollama: 'llama3.2',
};

const MAX_TOKENS = 4000;

// ---------- Claude (official SDK) ----------

/** Minimal surface of the Anthropic client used here (tests inject a fake). */
export interface ClaudeClientLike {
  beta: {
    messages: {
      create(params: Record<string, unknown>, options?: { signal?: AbortSignal }): Promise<{
        stop_reason: string | null;
        content: { type: string; text?: string }[];
      }>;
    };
  };
}

export function claudeProvider(
  apiKey: string,
  model = DEFAULT_MODELS.claude,
  makeClient?: () => Promise<ClaudeClientLike>,
): AiProvider {
  let client: Promise<ClaudeClientLike> | null = null;
  const getClient = () =>
    (client ??=
      makeClient?.() ??
      import('@anthropic-ai/sdk').then(
        ({ default: Anthropic }) =>
          new Anthropic({ apiKey, maxRetries: 1 }) as unknown as ClaudeClientLike,
      ));

  return {
    id: 'claude',
    model,
    async complete(req, signal) {
      const c = await getClient();
      const res = await c.beta.messages.create(
        {
          model,
          max_tokens: MAX_TOKENS,
          // Server-side fallback: a safety decline is re-run on Anthropic's recommended model.
          betas: ['server-side-fallback-2026-07-01'],
          fallbacks: 'default',
          system: req.system,
          messages: [{ role: 'user', content: req.user }],
          output_config: { effort: 'low', format: { type: 'json_schema', schema: ADVICE_SCHEMA } },
        },
        { signal },
      );
      if (res.stop_reason === 'refusal') throw new Error('Claude declined the request');
      const text = res.content.filter((b) => b.type === 'text').map((b) => b.text ?? '').join('');
      if (!text) throw new Error('Empty answer');
      return text;
    },
  };
}

// ---------- OpenAI (HTTP) ----------

export function openaiProvider(apiKey: string, model = DEFAULT_MODELS.openai, fetchImpl?: FetchLike): AiProvider {
  const doFetch = fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  return {
    id: 'openai',
    model,
    async complete(req, signal) {
      const res = await doFetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model,
          max_tokens: MAX_TOKENS,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: req.system },
            { role: 'user', content: req.user },
          ],
        }),
        signal,
      });
      if (!res.ok) throw new Error(`OpenAI HTTP ${res.status}`);
      const json = (await res.json()) as { choices?: { message?: { content?: unknown } }[] };
      const text = json.choices?.[0]?.message?.content;
      if (typeof text !== 'string' || !text) throw new Error('Empty answer');
      return text;
    },
  };
}

// ---------- Ollama (local HTTP) ----------

export function normalizeOllamaHost(host: string | undefined): string {
  const h = (host ?? '').trim() || 'http://127.0.0.1:11434';
  return (/^https?:\/\//i.test(h) ? h : `http://${h}`).replace(/\/+$/, '');
}

export function isLoopbackUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
    return host === 'localhost' || host === '::1' || /^127(?:\.\d{1,3}){3}$/.test(host);
  } catch {
    return false;
  }
}

export function ollamaProvider(host?: string, model = DEFAULT_MODELS.ollama, fetchImpl?: FetchLike): AiProvider {
  const doFetch = fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const base = normalizeOllamaHost(host);
  return {
    id: 'ollama',
    model,
    async complete(req, signal) {
      const res = await doFetch(`${base}/api/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model,
          stream: false,
          format: ADVICE_SCHEMA,
          messages: [
            { role: 'system', content: req.system },
            { role: 'user', content: req.user },
          ],
        }),
        signal,
      });
      if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
      const json = (await res.json()) as { message?: { content?: unknown } };
      const text = json.message?.content;
      if (typeof text !== 'string' || !text) throw new Error('Empty answer');
      return text;
    },
  };
}

// ---------- Selection ----------

export type ResolveResult =
  | { provider: AiProvider }
  | { provider: null; reason: 'noKey' | 'offline' };

/**
 * `choice` = 'auto' (bare --ai: Claude if ANTHROPIC_API_KEY, else OpenAI if
 * OPENAI_API_KEY) or an explicit provider. Ollama is only used when asked for.
 * With `offline`, remote providers are refused; Ollama only on a loopback host.
 */
export function resolveProvider(
  choice: 'auto' | AiProviderId,
  env: NodeJS.ProcessEnv,
  opts: { offline?: boolean; fetch?: FetchLike; claudeClient?: () => Promise<ClaudeClientLike> } = {},
): ResolveResult {
  const model = env.GARDEFOU_AI_MODEL?.trim() || undefined;
  const anthropicKey = env.ANTHROPIC_API_KEY?.trim();
  const openaiKey = env.OPENAI_API_KEY?.trim();

  const id: AiProviderId | null =
    choice !== 'auto' ? choice : anthropicKey ? 'claude' : openaiKey ? 'openai' : null;
  if (!id) return { provider: null, reason: 'noKey' };

  if (id === 'ollama') {
    const host = normalizeOllamaHost(env.OLLAMA_HOST);
    if (opts.offline && !isLoopbackUrl(host)) return { provider: null, reason: 'offline' };
    return { provider: ollamaProvider(host, model, opts.fetch) };
  }
  if (opts.offline) return { provider: null, reason: 'offline' };
  if (id === 'claude') {
    return anthropicKey
      ? { provider: claudeProvider(anthropicKey, model, opts.claudeClient) }
      : { provider: null, reason: 'noKey' };
  }
  return openaiKey ? { provider: openaiProvider(openaiKey, model, opts.fetch) } : { provider: null, reason: 'noKey' };
}
