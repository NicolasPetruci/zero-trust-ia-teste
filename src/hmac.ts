import { createHmac, timingSafeEqual } from 'node:crypto';

/** Assina `timestamp.corpo`. O timestamp entra na assinatura para limitar reuso. */
export function signBody(secret: string, timestampMs: number, body: string): string {
  return createHmac('sha256', secret).update(`${timestampMs}.${body}`).digest('hex');
}

export type SignatureResult = { ok: true } | { ok: false; reason: string };

export function verifySignature(params: {
  secret: string | undefined;
  timestampHeader: string | undefined;
  signatureHeader: string | undefined;
  body: string;
  nowMs: number;
  maxSkewMs: number;
}): SignatureResult {
  const { secret, timestampHeader, signatureHeader, body, nowMs, maxSkewMs } = params;
  if (!secret) return { ok: false, reason: 'servico_desconhecido' };
  if (!timestampHeader || !signatureHeader) return { ok: false, reason: 'assinatura_ausente' };

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp)) return { ok: false, reason: 'timestamp_invalido' };
  if (Math.abs(nowMs - timestamp) > maxSkewMs) return { ok: false, reason: 'timestamp_fora_da_janela' };

  const expected = Buffer.from(signBody(secret, timestamp, body), 'hex');
  const given = Buffer.from(signatureHeader, 'hex');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return { ok: false, reason: 'assinatura_invalida' };
  }
  return { ok: true };
}
