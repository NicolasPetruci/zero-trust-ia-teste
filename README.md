# zt-llm-gateway

Um gateway pequeno que fica na frente de um modelo de linguagem local e aplica ideias de **Zero Trust**
(NIST SP 800-207): nenhuma chamada é confiável só por vir de dentro da rede. Cada requisição prova quem é,
a cada vez.

Projeto de estudo, com dados fictícios. O modelo é simulado nos testes. O adaptador do Ollama existe
(`src/llm.ts`), mas **não foi testado aqui**.

## O que ele verifica, em ordem

| # | Pergunta | Onde | Se falhar |
|---|---|---|---|
| 1 | Quem é você? | JWT HS256 com algoritmo fixo, `exp` obrigatório | 401 |
| 2 | A sessão continua ativa? | `sid` do token consultado no armazenamento, com cache de 30 s | 401 |
| 3 | Você tem escopo? | claim `scope` precisa conter `llm:chat` | 403 |
| 4 | Este serviço é quem diz ser? | assinatura HMAC-SHA256 de `timestamp.corpo`, janela de 60 s | 401 |
| 5 | Este serviço pode usar este modelo? | allowlist por serviço (menor privilégio) | 403 |

Também: `/metrics` só responde a endereços internos (para fora, 404), corpo limitado a 16 KB e
**auditoria sem o texto do prompt** (só hash SHA-256 e tamanho, porque o prompt pode ter dado sensível).

## Como rodar

```bash
npm install
npm test        # 25 testes
npm run demo    # 8 cenários, cada um com a decisão do gateway
npm run typecheck
```

## Decisões que valem documentar

- **Cache de sessão de 30 s.** Logout, desligamento ou troca de senha revogam a sessão, e o token para de valer
  em até 30 s, sem esperar o `exp`. A janela existe de propósito: é o preço de não consultar o armazenamento a cada
  chamada. O teste mostra a janela (a chamada ainda passa antes dos 30 s e falha depois).
- **Se o armazenamento de sessões cair: fail-closed por padrão** (responde 503). Como o gateway protege acesso
  a um modelo que pode ver dado sensível, a escolha padrão aqui é não deixar passar o que não deu para verificar.
  `onSessionStoreError: 'open'` inverte isso (disponibilidade acima de verificação) e **registra a decisão na
  auditoria**. Qualquer das duas serve, desde que seja uma decisão escrita.
- **Assinatura HMAC em duas fases.** `signatureMode: 'observe'` só registra o que bloquearia
  (`bloquearia:assinatura_ausente`), para medir o impacto antes de quebrar alguém. Depois, `enforce`.

## Modelo de ameaças (resumido)

| Ameaça | Defesa | Coberta por teste |
|---|---|---|
| Token forjado ou com `alg: none` | algoritmo fixo + comparação em tempo constante | sim |
| Token roubado depois de um logout | verificação de sessão em toda chamada | sim |
| Serviço comprometido pedindo modelo que não deveria | allowlist de modelos por serviço | sim |
| Corpo alterado depois de assinado | HMAC cobre o corpo | sim |
| Descoberta de `/metrics` por fora | 404 para endereço não confiável | sim |
| Vazamento de dado pessoal pelo log | auditoria guarda hash e tamanho | sim |

## O que NÃO está coberto

- **Replay dentro da janela de 60 s**: não há registro de nonces. Quem capturar uma chamada assinada pode repeti-la
  por até um minuto.
- **Armazenamento de sessões em memória**: serve para estudo. Em produção seria Redis ou o banco de identidade.
- **Segredos em código de teste**: em produção, em variável de ambiente ou cofre, com rotação.
- **TLS**: o gateway fala HTTP simples; a termination de TLS fica à frente dele.
- **Limite de taxa** por usuário.
- **Adaptador do Ollama**: não testado neste repositório.
- O gancho `remoteAddressOf` e o cabeçalho `x-demo-origem` existem só para teste e demonstração: **não** use em produção.

## Base

Material da disciplina Fundamentos de IA e LLMs para Programadores (UNIPDS), módulo 9 (modelos abertos,
privacidade e Ollama), somado ao padrão Zero Trust do NIST SP 800-207.
