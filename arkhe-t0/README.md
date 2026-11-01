# Arkhe T0 — 2026-10-31

Este repositório congela, com data e assinatura verificável, a formulação
específica do método Arkhe: τ classification, T0 discipline, IntentBinding
campo-a-campo, ContainmentGate fail-closed com quatro estados, e o conjunto
de invariantes INV-BB-*.

## O que este T0 afirma
- A formulação específica descrita em specs/ e method/ existia nesta data.
- Os claims em T0.json são os que o autor considera atribuíveis.
- O método é falsificável: cada claim tem um falsificador quando aplicável.

## O que este T0 NÃO afirma
- Não afirma prioridade sobre a ideia de "verificação de execução de IA".
- Não afirma que o Arkhe está implementado ou que os testes correram.
- Não afirma que outros não chegaram a formulações semelhantes.
- Não substitui patente, trademark, ou proteção legal.

## Como verificar
1. `sha256sum` de cada ficheiro contra T0.json.
2. `cosign verify-blob` contra T0.json.bundle.
3. `git verify-commit` do commit assinado.

## Como comparar uma reivindicação posterior
Ver §8 deste README.