# btp-mtls-sync

> **Note:** This project was created with GitHub Copilot.

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
- `RUN_MODE` - `oneshot` (default) or `daemon`.
- `SYNC_INTERVAL` - Go duration string (for example `10m`, `1h`, `30s`), used for daemon mode. Default: `10m`.

## Run

One-shot (default):

```bash
go run ./cmd/btp-mtls-sync
```

Repetitive local run (daemon mode):

```bash
RUN_MODE=daemon SYNC_INTERVAL=10m go run ./cmd/btp-mtls-sync
```

## Deploy to SAP BTP Cloud Foundry

1. Log in to your SAP BTP Cloud Foundry org/space and target the space:

   ```bash
   cf login -a https://api.cf.<region>.hana.ondemand.com
   cf target -o <org> -s <space>
   ```

2. Set the required environment variables on the app (values from your Destination Service and CF API credentials):

   ```bash
   cf set-env btp-mtls-sync DESTINATION_TOKEN_URL <value>
   cf set-env btp-mtls-sync DESTINATION_CLIENT_ID <value>
   cf set-env btp-mtls-sync DESTINATION_CLIENT_SECRET <value>
   cf set-env btp-mtls-sync DESTINATION_API_URL <value>
   cf set-env btp-mtls-sync CF_TOKEN_URL <value>
   cf set-env btp-mtls-sync CF_CLIENT_ID <value>
   cf set-env btp-mtls-sync CF_CLIENT_SECRET <value>
   cf set-env btp-mtls-sync CF_API_URL <value>
   cf set-env btp-mtls-sync CF_DEFAULT_SERVICE_INSTANCE_GUID <value>
   ```

3. (Optional) Set optional sync flags:

   ```bash
   cf set-env btp-mtls-sync SYNC_NAME_PREFIX <prefix>
   cf set-env btp-mtls-sync DRY_RUN true
   ```

4. Configure repetitive background execution as a worker:

   ```bash
   cf set-env btp-mtls-sync RUN_MODE daemon
   cf set-env btp-mtls-sync SYNC_INTERVAL 10m
   ```

5. Push the app with the Go buildpack as a no-route background process:

   ```bash
   cf push btp-mtls-sync -b go_buildpack --no-route --health-check-type process
   ```

6. Restage or restart after changing environment variables:

   ```bash
   cf restart btp-mtls-sync
   ```

## Operations guidance

- `RUN_MODE=oneshot` runs one sync cycle and exits (good for ad-hoc/manual runs).
- `RUN_MODE=daemon` runs one sync cycle immediately on startup, then starts each next cycle after waiting `SYNC_INTERVAL` from the previous cycle completion.
- In daemon mode, a failed cycle is logged and the process still waits `SYNC_INTERVAL` before retrying.
- In dry-run mode (`DRY_RUN=true`), changes are logged but not applied.
- Use CF logs to monitor cycle start/completion/failure and rely on CF restarts for process recovery.

## Future extension: SAP Job Scheduler

For strict cron-based windows and centralized schedule governance, add SAP Job Scheduler integration in a later phase. This repository now supports the simpler worker-based repetitive mode first.
