# GraphQL Security Testing

## Discovery
- Common endpoints: `/graphql`, `/api/graphql`, `/v1/graphql`
- Introspection query: `{__schema{types{name,fields{name}}}}`

## Attack Vectors
1. **Introspection enabled** — Full schema disclosure
2. **Batching attacks** — Rate limit bypass via array queries
3. **Deep nesting** — DoS via recursive queries (if in scope)
4. **Field suggestions** — Enumerate hidden fields
5. **Mutation abuse** — Unauthorized data modification
6. **Alias overloading** — Bypass query cost limits

## Testing Approach
- Run introspection query first
- Map all mutations and sensitive queries
- Test authorization on each resolver
- Check for IDOR in node/global ID patterns
- Test batch query rate limit bypass