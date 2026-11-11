import { afterEach, describe, expect, it } from 'vitest';
import { createGateway, isInternal } from '../src/gateway.js';
import { signBody } from '../src/hmac.js';
import { signToken, verifyToken } from '../src/jwt.js';
import { FakeLlm } from '../src/llm.js';
import { InMemorySessionStore } from '../src/sessions.js';
import { MemoryAudit } from '../src/audit.js';
import { JWT_SECRET, SERVICE_SECRET, startGateway } from './helpers.js';

let closers: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  await Promise.all(closers.map((close) => close()));
  closers = [];
});
const start = async (...args: Parameters<typeof startGateway>) => {
  const gw = await startGateway(...args);
  closers.push(gw.close);
  return gw;
};

describe('1. Quem é você? (token)', () => {
  it('aceita uma chamada legítima', async () => {
    const gw = await start();
    const r = await gw.chat();
    expect(r.status).toBe(200);
    expect(gw.llm.calls).toBe(1);
  });

  it('recusa sem token (401)', async () => {
    const gw = await start();
    expect((await gw.chat({ token: null })).status).toBe(401);
    expect(gw.llm.calls).toBe(0);
  });

  it('recusa token adulterado (401)', async () => {
    const gw = await start();
    const bom = gw.token();
    const adulterado = bom.slice(0, -3) + (bom.endsWith('AAA') ? 'BBB' : 'AAA');
    const r = await gw.chat({ token: adulterado });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('assinatura_invalida');
  });

  it('recusa alg "none" (401): o cabeçalho não escolhe o algoritmo', async () => {
    const gw = await start();
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const exp = Math.floor(gw.clock.now / 1000) + 600;
    const sem = `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ sub: 'ana', sid: 'sess-1', scope: ['llm:chat'], exp })}.`;
    const r = await gw.chat({ token: sem });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('algoritmo_nao_permitido');
  });

  it('recusa token expirado (401)', async () => {
    const gw = await start();
    const r = await gw.chat({ token: gw.token({ exp: Math.floor(gw.clock.now / 1000) - 1 }) });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('token_expirado');
  });
});

describe('2. A sessão continua ativa? (revogação)', () => {
  it('sessão revogada deixa de valer depois da janela do cache (30 s), sem esperar o exp', async () => {
    const gw = await start();
    expect((await gw.chat()).status).toBe(200); // preenche o cache
    gw.sessions.revoke('sess-1');
    expect((await gw.chat()).status).toBe(200); // ainda dentro da janela: limite assumido
    gw.clock.now += 31_000;
    const r = await gw.chat();
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('sessao_revogada');
  });

  it('sessão nunca registrada é recusada de primeira', async () => {
    const gw = await start();
    const r = await gw.chat({ token: gw.token({ sid: 'sess-fantasma' }) });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('sessao_revogada');
  });

  it('armazenamento fora do ar: por padrão recusa (fail-closed, 503)', async () => {
    const gw = await start();
    gw.sessions.failing = true;
    const r = await gw.chat();
    expect(r.status).toBe(503);
    expect(gw.llm.calls).toBe(0);
  });

  it('armazenamento fora do ar com fail-open: deixa passar e registra a decisão na auditoria', async () => {
    const gw = await start({ onSessionStoreError: 'open' });
    gw.sessions.failing = true;
    expect((await gw.chat()).status).toBe(200);
    expect(gw.audit.events.some((e) => e.reason === 'fail_open_sessao')).toBe(true);
  });
});

describe('3. Escopo e menor privilégio', () => {
  it('sem o escopo llm:chat (403)', async () => {
    const gw = await start();
    const r = await gw.chat({ token: gw.token({ scope: ['outra:coisa'] }) });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe('escopo_insuficiente');
  });

  it('modelo fora da lista do serviço (403)', async () => {
    const gw = await start();
    const r = await gw.chat({ body: { model: 'modelo-grande', messages: [{ role: 'user', content: 'oi' }] } });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe('modelo_nao_permitido');
    expect(gw.llm.calls).toBe(0);
  });

  it('serviço desconhecido (403)', async () => {
    const gw = await start();
    const r = await gw.chat({ service: 'intruso' });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe('servico_desconhecido');
  });
});

describe('4. Serviço a serviço: assinatura HMAC em duas fases', () => {
  it('enforce: sem assinatura (401)', async () => {
    const gw = await start();
    const r = await gw.chat({ sign: false });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('assinatura_ausente');
  });

  it('enforce: assinatura inválida (401)', async () => {
    const gw = await start();
    const r = await gw.chat({ signatureOverride: 'ab'.repeat(32) });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('assinatura_invalida');
  });

  it('enforce: corpo alterado depois de assinado (401)', async () => {
    const gw = await start();
    const original = JSON.stringify({ model: 'local-pequeno', messages: [{ role: 'user', content: 'A' }] });
    const trocado = JSON.stringify({ model: 'local-pequeno', messages: [{ role: 'user', content: 'B' }] });
    const r = await gw.chat({ body: trocado, signatureOverride: signBody(SERVICE_SECRET, gw.clock.now, original) });
    expect(r.status).toBe(401);
  });

  it('enforce: timestamp velho demais (401)', async () => {
    const gw = await start();
    const r = await gw.chat({ timestamp: gw.clock.now - 5 * 60_000 });
    expect(r.status).toBe(401);
    expect(r.json.error).toBe('timestamp_fora_da_janela');
  });

  it('observe: assinatura inválida passa, mas a auditoria registra "bloquearia"', async () => {
    const gw = await start({ signatureMode: 'observe' });
    const r = await gw.chat({ sign: false });
    expect(r.status).toBe(200);
    expect(gw.audit.events.some((e) => e.decision === 'observe' && e.reason === 'bloquearia:assinatura_ausente')).toBe(true);
  });
});

describe('5. Superfície mínima', () => {
  it('isInternal reconhece loopback, inclusive IPv4-mapeado, e recusa o resto', () => {
    const trusted = ['127.0.0.1', '::1'];
    expect(isInternal('127.0.0.1', trusted)).toBe(true);
    expect(isInternal('::ffff:127.0.0.1', trusted)).toBe(true);
    expect(isInternal('::1', trusted)).toBe(true);
    expect(isInternal('203.0.113.9', trusted)).toBe(false);
    expect(isInternal(undefined, trusted)).toBe(false);
  });

  it('/metrics responde para a rede interna', async () => {
    const gw = await start();
    await gw.chat();
    const r = await fetch(`${gw.url}/metrics`);
    expect(r.status).toBe(200);
    expect(await r.text()).toContain('allow 1');
  });

  it('/metrics some (404) para quem vem de fora', async () => {
    const gw = await start({ remoteAddressOf: () => '203.0.113.9' });
    expect((await fetch(`${gw.url}/metrics`)).status).toBe(404);
  });

  it('corpo grande demais (413)', async () => {
    const gw = await start({ maxBodyBytes: 200 });
    const r = await gw.chat({ body: { model: 'local-pequeno', messages: [{ role: 'user', content: 'x'.repeat(500) }] }, sign: false });
    expect(r.status).toBe(413);
  });

  it('o gateway não sobe com segredo JWT curto', () => {
    expect(() =>
      createGateway({
        jwtSecret: 'curto',
        sessions: new InMemorySessionStore(),
        llm: new FakeLlm(),
        audit: new MemoryAudit(),
        services: {},
        signatureMode: 'enforce',
      }),
    ).toThrow(/32 caracteres/);
  });
});

describe('6. Auditoria', () => {
  it('registra a decisão sem guardar o texto do prompt (só hash e tamanho)', async () => {
    const gw = await start();
    const segredo = 'CPF 123.456.789-09 do paciente de exemplo';
    await gw.chat({ body: { model: 'local-pequeno', messages: [{ role: 'user', content: segredo }] } });
    const evento = gw.audit.events.at(-1)!;
    expect(evento.decision).toBe('allow');
    expect(evento.promptSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(evento.promptChars).toBe(segredo.length);
    expect(JSON.stringify(gw.audit.events)).not.toContain('123.456.789-09');
  });

  it('toda recusa vira um evento com o motivo', async () => {
    const gw = await start();
    await gw.chat({ token: null });
    await gw.chat({ service: 'intruso' });
    expect(gw.audit.events.map((e) => e.reason)).toEqual(['token_ausente', 'servico_desconhecido']);
  });
});

describe('jwt', () => {
  it('ida e volta', () => {
    const t = signToken({ sub: 'a', sid: 's', scope: ['x'], exp: 2_000_000_000 }, JWT_SECRET);
    expect(verifyToken(t, JWT_SECRET, 1_000_000_000).sub).toBe('a');
  });
});
