/**
 * Roda 8 cenários contra o gateway (modelo simulado, relógio controlado) e
 * imprime a decisão de cada um. É a "prova visual" do README.
 */
import type { AddressInfo } from 'node:net';
import { MemoryAudit } from './audit.js';
import { createGateway } from './gateway.js';
import { signBody } from './hmac.js';
import { signToken } from './jwt.js';
import { FakeLlm } from './llm.js';
import { InMemorySessionStore } from './sessions.js';

const JWT_SECRET = 'segredo-de-demonstracao-com-mais-de-32-caracteres';
const SERVICE_SECRET = 'segredo-do-servico-resumos';
const clock = { now: 1_700_000_000_000 };
const sessions = new InMemorySessionStore();
sessions.create('sessao-1');

const { server } = createGateway({
  jwtSecret: JWT_SECRET,
  sessions,
  llm: new FakeLlm(),
  audit: new MemoryAudit(),
  services: { resumos: { hmacSecret: SERVICE_SECRET, allowedModels: ['local-pequeno'] } },
  signatureMode: 'enforce',
  now: () => clock.now,
  remoteAddressOf: (req) => (req.headers['x-demo-origem'] as string | undefined) ?? req.socket.remoteAddress,
});
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const token = (c: Partial<{ scope: string[]; sid: string }> = {}) =>
  signToken({ sub: 'ana', sid: 'sessao-1', scope: ['llm:chat'], exp: Math.floor(clock.now / 1000) + 600, ...c }, JWT_SECRET);
const goodBody = JSON.stringify({ model: 'local-pequeno', messages: [{ role: 'user', content: 'Resuma o texto.' }] });

async function chat(o: { token?: string | null; model?: string; signature?: string | null } = {}) {
  const body = o.model ? JSON.stringify({ model: o.model, messages: [{ role: 'user', content: 'oi' }] }) : goodBody;
  const headers: Record<string, string> = { 'content-type': 'application/json', 'x-service-id': 'resumos' };
  const t = o.token === undefined ? token() : o.token;
  if (t) headers.authorization = `Bearer ${t}`;
  if (o.signature !== null) {
    headers['x-timestamp'] = String(clock.now);
    headers['x-signature'] = o.signature ?? signBody(SERVICE_SECRET, clock.now, body);
  }
  return (await fetch(`${url}/v1/chat`, { method: 'POST', headers, body })).status;
}

const rows: Array<[string, number]> = [];
rows.push(['Chamada legítima', await chat()]);
rows.push(['Sem token', await chat({ token: null })]);
const bom = token();
rows.push(['Token adulterado', await chat({ token: bom.slice(0, -3) + (bom.endsWith('AAA') ? 'BBB' : 'AAA') })]);
rows.push(['Sem o escopo llm:chat', await chat({ token: token({ scope: ['outro'] }) })]);
rows.push(['Modelo fora da allowlist', await chat({ model: 'modelo-grande' })]);
rows.push(['Assinatura HMAC inválida', await chat({ signature: 'ab'.repeat(32) })]);
rows.push(['/metrics vindo de fora', (await fetch(`${url}/metrics`, { headers: { 'x-demo-origem': '203.0.113.9' } })).status]);
sessions.revoke('sessao-1');
clock.now += 31_000;
rows.push(['Sessão revogada (após 30 s)', await chat({ token: token() })]);

console.log('\ncenário'.padEnd(34) + 'HTTP');
console.log('-'.repeat(40));
for (const [name, status] of rows) console.log(name.padEnd(34) + status);
server.close();
