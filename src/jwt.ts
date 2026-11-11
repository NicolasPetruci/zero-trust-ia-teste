import { createHmac, timingSafeEqual } from 'node:crypto';

export interface TokenClaims {
  /** Quem é o usuário ou serviço. */
  sub: string;
  /** Identificador da sessão: é ele que permite revogar antes do exp. */
  sid: string;
  scope: string[];
  /** Expiração, em segundos desde a época. */
  exp: number;
}

export class TokenError extends Error {
  constructor(public readonly reason: string) {
    super(reason);
  }
}

const encode = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');

export function signToken(claims: TokenClaims, secret: string): string {
  const head = encode({ alg: 'HS256', typ: 'JWT' });
  const body = encode(claims);
  const signature = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${signature}`;
}

/**
 * Verifica assinatura e claims. O algoritmo é fixado em HS256: o cabeçalho do
 * token não escolhe como ele será validado (isso barra "alg: none").
 */
export function verifyToken(token: string, secret: string, nowSeconds: number): TokenClaims {
  const parts = token.split('.');
  if (parts.length !== 3) throw new TokenError('token_malformado');
  const [head, body, signature] = parts as [string, string, string];

  let header: unknown;
  let claims: unknown;
  try {
    header = JSON.parse(Buffer.from(head, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    throw new TokenError('token_malformado');
  }
  if ((header as { alg?: unknown } | null)?.alg !== 'HS256') throw new TokenError('algoritmo_nao_permitido');

  const expected = createHmac('sha256', secret).update(`${head}.${body}`).digest();
  const given = Buffer.from(signature, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new TokenError('assinatura_invalida');
  }

  const c = claims as Partial<TokenClaims> | null;
  if (
    !c ||
    typeof c.sub !== 'string' ||
    typeof c.sid !== 'string' ||
    typeof c.exp !== 'number' ||
    !Array.isArray(c.scope) ||
    !c.scope.every((s) => typeof s === 'string')
  ) {
    throw new TokenError('claims_invalidas');
  }
  if (c.exp <= nowSeconds) throw new TokenError('token_expirado');
  return { sub: c.sub, sid: c.sid, scope: c.scope, exp: c.exp };
}
