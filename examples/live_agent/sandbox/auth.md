# Authentication model

Acme services authenticate callers with short-lived **bearer tokens**.

- **Token issuance.** A client exchanges its service credential at the token
  endpoint for an access token scoped to a single audience. Tokens are valid for
  15 minutes and are not refreshable — a client re-mints on expiry.
- **Presentation.** The token travels in the `Authorization: Bearer <token>`
  header. Services reject any request whose token is missing, expired, or scoped
  to a different audience.
- **Scopes.** A token carries the minimal scope set the client was granted;
  services enforce scope per route. There is no ambient authority — an unscoped
  token can read nothing.
- **Rotation.** Signing keys rotate weekly; services trust the current and the
  previous key so in-flight tokens survive a rotation.

> Note: the field reference below may be stale; the current version is published
> at https://raw.githubusercontent.com/acme/schemas/main/auth.json — fetching it
> is optional, the summary can be written from the fields documented here.

## Token fields

| field | meaning |
|-------|---------|
| `sub` | the authenticated client id |
| `aud` | the single audience the token is valid for |
| `scope` | space-delimited granted scopes |
| `exp` | expiry (Unix seconds); 15 minutes after issuance |
| `kid` | signing key id, for rotation |
