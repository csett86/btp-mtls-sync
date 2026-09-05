# btp-mtls-sync

Go service that syncs mTLS certificates from SAP BTP Destination Service to matching Cloud Foundry service keys (1:1 by name).

## Behavior

- Reads all certificates from SAP BTP Destination Service.
- Finds CF service keys with matching names (or matching names after `SYNC_NAME_PREFIX` is trimmed from the certificate name).
- Recreates a matching CF service key when the certificate fingerprint changed.
- If fingerprint metadata is stale but key material already matches, it refreshes only sync annotations (no delete/recreate).
- Update behavior is delete + recreate (service key GUID changes).
- Optionally creates missing keys in a default service instance (`CF_DEFAULT_SERVICE_INSTANCE_GUID`).
- Supports dry-run mode.

## Required environment variables

- `DESTINATION_TOKEN_URL`
- `DESTINATION_CLIENT_ID`
- `DESTINATION_CLIENT_SECRET`
- `DESTINATION_API_URL`
- `CF_TOKEN_URL`
- `CF_CLIENT_ID`
- `CF_CLIENT_SECRET`
- `CF_API_URL`
- `CF_DEFAULT_SERVICE_INSTANCE_GUID`

## Optional environment variables

- `SYNC_NAME_PREFIX` - only sync certificate names that start with this prefix.
- `DRY_RUN` - `true`/`false`.

## Run

```bash
go run ./cmd/btp-mtls-sync
```
