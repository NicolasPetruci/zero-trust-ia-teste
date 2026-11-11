import type { AddressInfo } from 'node:net';
import { MemoryAudit } from '../src/audit.js';
import { createGateway, type GatewayOptions } from '../src/gateway.js';
import { signBody } from '../src/hmac.js';
import { signToken } from '../src/jwt.js';
import { FakeLlm } from '../src/llm.js';
import { InMemorySessionStore } from '../src/sessions.js';

export const JWT_SECRET = 'segredo-de-teste-com-mais-de-32-caracteres!';
export const SERVICE_SECRET = 'segredo-do-servico-prontuario';

export async function startGateway(overrides: Partial<GatewayOptions> = {}) {
  const clock = { now: 1_700_000_000_000 };
  const sessions = new InMemorySessionStore();
  sessions.create('sess-1');
  const audit = new MemoryAudit();
  const llm = new FakeLlm();
  const { server } = createGateway({
    jwtSecret: JWT_SECRET,
    sessions,
    llm,
    audit,
    services: { resumos: { hmacSecret: SERVICE_SECRET, allowedModels: ['local-pequeno'] } },
    signatureMode: 'enforce',
    now: () => clock.now,
    ...overrides,
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const token = (claims: Partial<{ sub: string; sid: string; scope: string[]; exp: number }> = {}) =>
    signToken(
      { sub: 'ana', sid: 'sess-1', scope: ['llm:chat'], exp: Math.floor(clock.now / 1000) + 600, ...claims },
      JWT_SECRET,
    );

  /** Chamada padrão e correta; cada teste estraga uma coisa de cada vez. */
  const chat = async (
    init: {
      token?: string | null;
      service?: string | null;
      body?: object | string;
      sign?: boolean;
      signatureOverride?: string;
      timestamp?: number;
    } = {},
  ) => {
    const body =
      typeof init.body === 'string'
        ? init.body
        : JSON.stringify(init.body ?? { model: 'local-pequeno', messages: [{ role: 'user', content: 'Resuma o texto.' }] });
    const timestamp = init.timestamp ?? clock.now;
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    const tk = init.token === undefined ? token() : init.token;
    if (tk) headers.authorization = `Bearer ${tk}`;
    if (init.service !== null) headers['x-service-id'] = init.service ?? 'resumos';
    if (init.sign !== false) {
      headers['x-timestamp'] = String(timestamp);
      headers['x-signature'] = init.signatureOverride ?? signBody(SERVICE_SECRET, timestamp, body);
    }
    const response = await fetch(`${url}/v1/chat`, { method: 'POST', headers, body });
    return { status: response.status, json: (await response.json()) as Record<string, unknown> };
  };

  return { server, url, clock, sessions, audit, llm, token, chat, close: () => new Promise((r) => server.close(r)) };
}
