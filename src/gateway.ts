import { createHash, randomUUID } from 'node:crypto';
import http from 'node:http';
import type { AuditEvent, AuditSink } from './audit.js';
import { verifySignature } from './hmac.js';
import { TokenError, verifyToken } from './jwt.js';
import type { ChatMessage, LlmClient } from './llm.js';
import { CachedSessionChecker, type SessionStore } from './sessions.js';

export interface ServiceConfig {
  /** Segredo compartilhado só entre o gateway e este serviço. */
  hmacSecret: string;
  /** Menor privilégio: cada serviço só pode usar os modelos desta lista. */
  allowedModels: string[];
}

export interface GatewayOptions {
  jwtSecret: string;
  sessions: SessionStore;
  llm: LlmClient;
  audit: AuditSink;
  services: Record<string, ServiceConfig>;
  /** observe: registra a assinatura inválida e deixa passar. enforce: recusa. */
  signatureMode: 'observe' | 'enforce';
  /** Janela do cache de sessão. Padrão: 30 s. */
  sessionCacheTtlMs?: number;
  /** Se o armazenamento de sessões cair: recusar (closed, padrão) ou deixar passar (open). */
  onSessionStoreError?: 'closed' | 'open';
  /** Endereços que podem ver /metrics. Padrão: só a própria máquina. */
  trustedNetworks?: string[];
  maxBodyBytes?: number;
  maxSkewMs?: number;
  now?: () => number;
  /** Gancho de teste: de onde vem o endereço de quem chamou. */
  remoteAddressOf?: (req: http.IncomingMessage) => string | undefined;
}

const SCOPE_CHAT = 'llm:chat';

/** Normaliza o formato IPv4-mapeado ("::ffff:127.0.0.1") e compara com a lista. */
export function isInternal(address: string | undefined, trusted: string[]): boolean {
  if (!address) return false;
  const normalized = address.startsWith('::ffff:') ? address.slice(7) : address;
  return trusted.includes(normalized);
}

class BodyTooLarge extends Error {}

function readBody(req: http.IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new BodyTooLarge());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res: http.ServerResponse, status: number, body: object | string): void {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json',
    'cache-control': 'no-store',
  });
  res.end(text);
}

function parseChat(body: string): { model: string; messages: ChatMessage[] } | null {
  try {
    const data = JSON.parse(body) as { model?: unknown; messages?: unknown };
    if (typeof data.model !== 'string' || !Array.isArray(data.messages) || data.messages.length === 0) return null;
    const messages: ChatMessage[] = [];
    for (const m of data.messages as Array<{ role?: unknown; content?: unknown }>) {
      if (
        (m.role !== 'system' && m.role !== 'user' && m.role !== 'assistant') ||
        typeof m.content !== 'string'
      ) {
        return null;
      }
      messages.push({ role: m.role, content: m.content });
    }
    return { model: data.model, messages };
  } catch {
    return null;
  }
}

export function createGateway(options: GatewayOptions) {
  if (options.jwtSecret.length < 32) {
    throw new Error('jwtSecret precisa ter pelo menos 32 caracteres.');
  }
  const now = options.now ?? Date.now;
  const trusted = options.trustedNetworks ?? ['127.0.0.1', '::1'];
  const maxBody = options.maxBodyBytes ?? 16 * 1024;
  const maxSkew = options.maxSkewMs ?? 60_000;
  const failMode = options.onSessionStoreError ?? 'closed';
  const sessions = new CachedSessionChecker(options.sessions, options.sessionCacheTtlMs ?? 30_000, now);
  const counters = new Map<string, number>();
  const count = (key: string) => counters.set(key, (counters.get(key) ?? 0) + 1);

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const requestId = randomUUID();
    const route = `${req.method} ${req.url}`;
    const base = (): Pick<AuditEvent, 'ts' | 'requestId' | 'route'> => ({ ts: now(), requestId, route });
    const deny = (status: number, reason: string, extra: Partial<AuditEvent> = {}) => {
      options.audit.record({ ...base(), decision: 'deny', reason, ...extra });
      count(`deny:${reason}`);
      send(res, status, { error: reason });
    };

    // Superfície mínima: /metrics só para a rede interna. Para fora, finge que não existe.
    if (req.method === 'GET' && req.url === '/metrics') {
      const address = (options.remoteAddressOf ?? ((r) => r.socket.remoteAddress))(req);
      if (!isInternal(address, trusted)) return deny(404, 'metrics_externo');
      const lines = [...counters.entries()].map(([k, v]) => `${k} ${v}`).sort();
      return send(res, 200, lines.join('\n') + '\n');
    }

    if (!(req.method === 'POST' && req.url === '/v1/chat')) return deny(404, 'rota_inexistente');

    let body: string;
    try {
      body = await readBody(req, maxBody);
    } catch (error) {
      if (error instanceof BodyTooLarge) return deny(413, 'corpo_grande_demais');
      return deny(400, 'corpo_ilegivel');
    }

    // 1. Quem é você? Token com algoritmo fixo e expiração.
    const authorization = req.headers.authorization ?? '';
    if (!authorization.startsWith('Bearer ')) return deny(401, 'token_ausente');
    let claims;
    try {
      claims = verifyToken(authorization.slice(7), options.jwtSecret, Math.floor(now() / 1000));
    } catch (error) {
      return deny(401, error instanceof TokenError ? error.reason : 'token_invalido');
    }
    const who = { sub: claims.sub, sid: claims.sid };

    // 2. A sessão continua ativa? Assinatura válida não basta.
    const status = await sessions.check(claims.sid);
    if (status === 'revoked') return deny(401, 'sessao_revogada', who);
    if (status === 'unavailable') {
      if (failMode === 'closed') return deny(503, 'verificacao_indisponivel', who);
      options.audit.record({ ...base(), decision: 'observe', reason: 'fail_open_sessao', ...who });
    }

    // 3. Este chamador tem escopo para usar o modelo?
    if (!claims.scope.includes(SCOPE_CHAT)) return deny(403, 'escopo_insuficiente', who);

    // 4. Este serviço fala mesmo em nome de quem diz? Assinatura HMAC.
    const serviceId = String(req.headers['x-service-id'] ?? '');
    const service = options.services[serviceId];
    if (!service) return deny(403, 'servico_desconhecido', who);
    const signature = verifySignature({
      secret: service.hmacSecret,
      timestampHeader: req.headers['x-timestamp']?.toString(),
      signatureHeader: req.headers['x-signature']?.toString(),
      body,
      nowMs: now(),
      maxSkewMs: maxSkew,
    });
    if (!signature.ok) {
      if (options.signatureMode === 'enforce') return deny(401, signature.reason, { ...who, service: serviceId });
      options.audit.record({
        ...base(),
        decision: 'observe',
        reason: `bloquearia:${signature.reason}`,
        ...who,
        service: serviceId,
      });
      count(`observe:${signature.reason}`);
    }

    // 5. O pedido é válido e o serviço pode usar este modelo?
    const chat = parseChat(body);
    if (!chat) return deny(400, 'pedido_invalido', { ...who, service: serviceId });
    if (!service.allowedModels.includes(chat.model)) {
      return deny(403, 'modelo_nao_permitido', { ...who, service: serviceId, model: chat.model });
    }

    const prompt = chat.messages.map((m) => m.content).join('\n');
    try {
      const output = await options.llm.complete(chat);
      options.audit.record({
        ...base(),
        decision: 'allow',
        reason: 'ok',
        ...who,
        service: serviceId,
        model: chat.model,
        promptSha256: createHash('sha256').update(prompt).digest('hex'),
        promptChars: prompt.length,
      });
      count('allow');
      return send(res, 200, { output, model: chat.model });
    } catch {
      return deny(502, 'modelo_indisponivel', { ...who, service: serviceId, model: chat.model });
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: 'erro_interno' });
    });
  });

  return { server, handle };
}
