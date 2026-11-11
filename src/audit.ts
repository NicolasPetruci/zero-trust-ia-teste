export interface AuditEvent {
  ts: number;
  requestId: string;
  route: string;
  decision: 'allow' | 'deny' | 'observe';
  reason: string;
  sub?: string;
  sid?: string;
  service?: string;
  model?: string;
  /** Hash e tamanho do prompt: dá para correlacionar sem guardar o texto (que pode ter dado sensível). */
  promptSha256?: string;
  promptChars?: number;
}

export interface AuditSink {
  record(event: AuditEvent): void;
}

export class MemoryAudit implements AuditSink {
  public readonly events: AuditEvent[] = [];
  record(event: AuditEvent): void {
    this.events.push(event);
  }
}

export class ConsoleAudit implements AuditSink {
  record(event: AuditEvent): void {
    console.log(JSON.stringify(event));
  }
}
