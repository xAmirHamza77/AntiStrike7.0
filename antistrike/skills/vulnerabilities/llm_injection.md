# LLM Prompt Injection Testing

## Attack Types
1. **Direct injection** — Override system instructions via user input
2. **Indirect injection** — Poison data sources the LLM reads
3. **Jailbreak** — Bypass safety filters via role-play
4. **Extraction** — Leak system prompts or training data

## Test Payloads
- "Ignore all previous instructions..."
- Delimiter confusion with code blocks
- Multi-language injection
- Encoding and obfuscation variants

## Assessment Criteria
- Can the model be made to ignore safety guidelines?
- Does it reveal system prompts or internal instructions?
- Can it access tools/APIs beyond intended scope?
- Is there data leakage from other users' sessions?