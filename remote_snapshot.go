package viper

import "reflect"

// RemoteSnapshot is a read-only view pinned to one remote configuration. It
// retains the original Viper options and other sources. As with ordinary remote
// reads, configure non-remote sources before use; concurrent Set, flag mutations
// and other configuration writes require external synchronization.
type RemoteSnapshot struct {
	v      *Viper
	remote map[string]any
}

// SnapshotRemoteConfig pins the current remote document for a batch of reads.
// Environment and flag values are still evaluated using the original options.
func (v *Viper) SnapshotRemoteConfig() *RemoteSnapshot {
	return &RemoteSnapshot{v: v, remote: v.remoteSnapshot()}
}

// SameConfig reports whether two views of the same Viper have equal remote
// documents, including literal keys that cannot be represented by AllKeys.
func (s *RemoteSnapshot) SameConfig(other *RemoteSnapshot) bool {
	return other != nil && s.v == other.v && reflect.DeepEqual(s.remote, other.remote)
}

// Unmarshal decodes using the pinned remote document and original Viper options.
func (s *RemoteSnapshot) Unmarshal(rawVal any, opts ...DecoderConfigOption) error {
	return s.v.unmarshalSnapshot(rawVal, s.remote, opts...)
}

// UnmarshalKey decodes a subtree without flattening its literal map keys.
func (s *RemoteSnapshot) UnmarshalKey(key string, rawVal any, opts ...DecoderConfigOption) error {
	return decode(s.v.get(key, s.remote), s.v.defaultDecoderConfig(rawVal, opts...))
}
