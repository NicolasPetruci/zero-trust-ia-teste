export interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LlmClient {
  complete(request: { model: string; messages: ChatMessage[] }): Promise<string>;
}

/** Modelo de mentira para testes e demonstração. Não chama rede. */
export class FakeLlm implements LlmClient {
  public calls = 0;
  async complete(request: { model: string; messages: ChatMessage[] }): Promise<string> {
    this.calls += 1;
    return `[simulado:${request.model}] ${request.messages.length} mensagem(ns) recebida(s).`;
  }
}

/**
 * Adaptador para o Ollama rodando na própria máquina (porta padrão 11434).
 * NÃO foi testado neste repositório: o ambiente de desenvolvimento não tinha Ollama.
 */
export class OllamaLlm implements LlmClient {
  constructor(private readonly baseUrl = 'http://127.0.0.1:11434') {}

  async complete(request: { model: string; messages: ChatMessage[] }): Promise<string> {
    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: request.model, messages: request.messages, stream: false }),
    });
    if (!response.ok) throw new Error(`Ollama respondeu ${response.status}`);
    const data = (await response.json()) as { message?: { content?: string } };
    return data.message?.content ?? '';
  }
}
