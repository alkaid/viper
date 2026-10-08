# Consistent remote decoding in ak-8

Core `v1.21.0-ak-8` and `remote/v1.21.0-ak-8` retain the [ak-7 recovery behavior](MIGRATION-ak-7.md) and Go 1.27.1 requirement. No existing signatures or data formats change.

`SnapshotRemoteConfig` returns a read-only view with `Unmarshal`, `UnmarshalKey` and `SameConfig`. Use one view for a batch of loader callbacks and compare that view to the previous one when suppressing unchanged remote updates. This prevents comparing one document but decoding a newer one. The view keeps the original Viper delimiter, environment binding and decoder options; `UnmarshalKey` preserves literal map keys such as hostnames.

Only the remote document is frozen. Flags, environment and non-remote sources retain their usual semantics, and non-remote configuration writes still require external synchronization. `SameConfig` compares the complete merged remote document, including fields hidden by local overrides; changing such a field may therefore cause a redundant reload. No writer or watch methods are exposed on the view.
