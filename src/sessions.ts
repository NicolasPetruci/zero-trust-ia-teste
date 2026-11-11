/** Onde a sessão "mora". Em produção seria Redis ou o banco de identidade. */
export interface SessionStore {
  isActive(sid: string): Promise<boolean>;
}

export class InMemorySessionStore implements SessionStore {
  private readonly active = new Set<string>();
  /** Para simular uma queda do armazenamento nos testes. */
  public failing = false;

  create(sid: string): void {
    this.active.add(sid);
  }
  revoke(sid: string): void {
    this.active.delete(sid);
  }
  async isActive(sid: string): Promise<boolean> {
    if (this.failing) throw new Error('armazenamento de sessões indisponível');
    return this.active.has(sid);
  }
}

export type SessionStatus = 'active' | 'revoked' | 'unavailable';

/**
 * Consulta a sessão com cache curto. A assinatura do token valer não basta:
 * logout, desligamento ou troca de senha revogam a sessão, e a revogação passa
 * a valer em, no máximo, `ttlMs` (a janela do cache). Falhas não são cacheadas.
 */
export class CachedSessionChecker {
  private readonly cache = new Map<string, { status: 'active' | 'revoked'; expiresAt: number }>();

  constructor(
    private readonly store: SessionStore,
    private readonly ttlMs: number,
    private readonly now: () => number,
  ) {}

  async check(sid: string): Promise<SessionStatus> {
    const hit = this.cache.get(sid);
    if (hit && hit.expiresAt > this.now()) return hit.status;
    try {
      const status = (await this.store.isActive(sid)) ? 'active' : 'revoked';
      this.cache.set(sid, { status, expiresAt: this.now() + this.ttlMs });
      return status;
    } catch {
      return 'unavailable';
    }
  }
}
