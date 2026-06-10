# Changelog

## 1.0.0

- Add the Risk (`POST /risk`), Filter (`POST /filter`) and Log (`POST /log`)
  scoring endpoints. `Risk` and `Filter` apply a configurable failover strategy
  (`allow`, `challenge`, `deny`, `throw`) on transport errors, timeouts and 5xx
  responses; `Log` does not fail over.
- Add the Lists API (`CreateList`, `GetAllLists`, `GetList`, `QueryLists`,
  `UpdateList`, `DeleteList`) and the List items API (`CreateListItem`,
  `CreateListItemsBatch`, `GetListItem`, `QueryListItems`, `CountListItems`,
  `UpdateListItem`, `ArchiveListItem`, `UnarchiveListItem`).
- Add the Privacy API (`RequestUserData`, `DeleteUserData`) and the Events API
  (`EventsSchema`, `QueryEvents`, `GroupEvents`).
- Add webhook signature verification (`VerifyWebhook`, `VerifyWebhookRequest`)
  and secure mode signing (`SecureModeSignature`).
- Add request context extraction (`ContextFromRequest`) with header
  allowlist/denylist scrubbing and configurable IP resolution
  (`ip_headers`, trusted proxies, trust-proxy-chain, trusted-proxy-depth).
- Add functional configuration options: base URL, request timeout, failover
  strategy, header allow/deny lists, IP resolution, do-not-track and a custom
  HTTP client.
- Add a typed error hierarchy embedding `APIError`, plus `RequestError`,
  `ConfigurationError` and `WebhookVerificationError`.
- Remove the legacy `Track` and `Authenticate` endpoints, the
  `$incident.mitigated` / `$review.*` / `$challenge.*` event constants, and the
  client-id extraction (`__cid` cookie / `X-Castle-Client-Id`) from the default
  request context.
- Require Go 1.21+. Replace Travis CI with GitHub Actions.
