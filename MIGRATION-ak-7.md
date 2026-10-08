# Remote watch recovery in ak-7

Both the core and remote module require Go 1.27.1. Use core `v1.21.0-ak-7` with `remote/v1.21.0-ak-7`; the remote module pins crypt `v0.31.0-ak-4`.

`WatchRemoteConfigWithChannel` now forwards an error if a provider closes its response channel. Cancel the old context before restarting a watch; the receiver belongs to the caller and must remain open until its watchers exit. A canceled watcher cannot publish subsequently decoded values. A synchronous provider Get during setup still uses the provider's own timeout, since that interface has no context parameter.

Remote reads (`Get`, `AllKeys`, `AllSettings`, `Unmarshal` and their variants) may run concurrently with remote watch updates. Each document read uses one remote snapshot. This does not make other Viper mutations concurrent-safe: configure defaults, aliases, flags, file configuration and providers before starting readers/watchers, or synchronize those operations yourself. Treat returned maps/slices as read-only.

Restarting a watch refreshes each provider. A temporarily missing key, failed Get or invalid document retains that provider's last valid snapshot when one exists. Initial loading still fails if no valid snapshot is available. Mixing either legacy watch API with the context-based API invalidates the per-provider cache; a failed refresh then returns an error and preserves the current effective configuration. A valid document replaces the provider contribution, so removed fields fall back to lower-priority providers; an empty document clears that provider's contribution. Registration order remains low to high priority. For etcd3, crypt re-establishes a snapshot and resumes at its next revision after a watch interruption. Recovery converges to the latest valid state, not every intermediate value while disconnected.

Public method signatures and provider key formats are unchanged. Reverting requires downgrading both modules together; it does not change remote data.
