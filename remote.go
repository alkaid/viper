package viper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"

	"dario.cat/mergo"
)

// SupportedRemoteProviders are universally supported remote providers.
var SupportedRemoteProviders = []string{"etcd", "etcd3", "consul", "firestore", "nats"}

func resetRemote() {
	SupportedRemoteProviders = []string{"etcd", "etcd3", "consul", "firestore", "nats"}
}

type remoteConfigFactory interface {
	Get(rp RemoteProvider) (io.Reader, error)
	Watch(rp RemoteProvider) (io.Reader, error)
	WatchChannel(rp RemoteProvider) (<-chan *RemoteResponse, chan bool)
}

// RemoteResponse represents a response from a remote configuration provider.
type RemoteResponse struct {
	Value []byte
	Error error
}

// RemoteConfig is optional, see the remote package.
var RemoteConfig remoteConfigFactory

// UnsupportedRemoteProviderError denotes encountering an unsupported remote
// provider. Currently only etcd and Consul are supported.
type UnsupportedRemoteProviderError string

// Error returns the formatted remote provider error.
func (str UnsupportedRemoteProviderError) Error() string {
	return fmt.Sprintf("Unsupported Remote Provider Type %q", string(str))
}

// RemoteConfigError denotes encountering an error while trying to
// pull the configuration from the remote provider.
type RemoteConfigError string

// Error returns the formatted remote provider error.
func (rce RemoteConfigError) Error() string {
	return fmt.Sprintf("Remote Configurations Error: %s", string(rce))
}

type defaultRemoteProvider struct {
	provider      string
	endpoint      string
	endpoints     []string
	path          string
	secretKeyring string
}

func (rp defaultRemoteProvider) Provider() string {
	return rp.provider
}

func (rp defaultRemoteProvider) Endpoint() string {
	return rp.endpoint
}

func (rp defaultRemoteProvider) Endpoints() []string {
	return slices.Clone(rp.endpoints)
}

func (rp defaultRemoteProvider) Path() string {
	return rp.path
}

func (rp defaultRemoteProvider) SecretKeyring() string {
	return rp.secretKeyring
}

// RemoteProvider stores the configuration necessary
// to connect to a remote key/value store.
// Optional secretKeyring to unencrypt encrypted values
// can be provided.
type RemoteProvider interface {
	Provider() string
	Endpoint() string
	Endpoints() []string
	Path() string
	SecretKeyring() string
}

// AddRemoteProvider adds a remote configuration source.
// Remote providers are merged in the order they are added. Providers added
// later have higher priority.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port, consul requires ip:port, nats requires nats://ip:port
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
func AddRemoteProvider(provider, endpoint, path string) error {
	return v.AddRemoteProvider(provider, endpoint, path)
}

// AddRemoteProvider adds a remote configuration source.
// Remote providers are merged in the order they are added. Providers added
// later have higher priority.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port, consul requires ip:port, nats requires nats://ip:port
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
func (v *Viper) AddRemoteProvider(provider, endpoint, path string) error {
	if !slices.Contains(SupportedRemoteProviders, provider) {
		return UnsupportedRemoteProviderError(provider)
	}
	if provider != "" && endpoint != "" {
		v.logger.Info("adding remote provider", "provider", provider, "endpoint", endpoint)

		rp := &defaultRemoteProvider{
			endpoint: endpoint,
			provider: provider,
			path:     path,
		}
		if !v.providerPathExists(rp) {
			v.remoteProviders = append(v.remoteProviders, rp)
		}
	}
	return nil
}

// AddRemoteProviderCluster adds a remote configuration source with multiple endpoints.
// Providers added later have higher priority.
func (v *Viper) AddRemoteProviderCluster(provider string, endpoints []string, path string) error {
	if !slices.Contains(SupportedRemoteProviders, provider) {
		return UnsupportedRemoteProviderError(provider)
	}
	if provider != "" && len(endpoints) != 0 {
		v.logger.Info("adding remote provider", "provider", provider, "endpoints", endpoints)

		rp := &defaultRemoteProvider{
			endpoints: slices.Clone(endpoints),
			provider:  provider,
			path:      path,
		}
		if !v.providerPathExists(rp) {
			v.remoteProviders = append(v.remoteProviders, rp)
		}
	}
	return nil
}

// AddSecureRemoteProvider adds a remote configuration source.
// Secure remote providers are merged in the order they are added. Providers
// added later have higher priority.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port  consul requires ip:port
// secretkeyring is the filepath to your openpgp secret keyring.  e.g. /etc/secrets/myring.gpg
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
// Secure Remote Providers are implemented with github.com/alkaid/crypt.
func AddSecureRemoteProvider(provider, endpoint, path, secretkeyring string) error {
	return v.AddSecureRemoteProvider(provider, endpoint, path, secretkeyring)
}

// AddSecureRemoteProvider adds a remote configuration source.
// Secure remote providers are merged in the order they are added. Providers
// added later have higher priority.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port  consul requires ip:port
// secretkeyring is the filepath to your openpgp secret keyring.  e.g. /etc/secrets/myring.gpg
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
// Secure Remote Providers are implemented with github.com/alkaid/crypt.
func (v *Viper) AddSecureRemoteProvider(provider, endpoint, path, secretkeyring string) error {
	if !slices.Contains(SupportedRemoteProviders, provider) {
		return UnsupportedRemoteProviderError(provider)
	}
	if provider != "" && endpoint != "" {
		v.logger.Info("adding remote provider", "provider", provider, "endpoint", endpoint)

		rp := &defaultRemoteProvider{
			endpoint:      endpoint,
			provider:      provider,
			path:          path,
			secretKeyring: secretkeyring,
		}
		if !v.providerPathExists(rp) {
			v.remoteProviders = append(v.remoteProviders, rp)
		}
	}
	return nil
}

func (v *Viper) providerPathExists(p *defaultRemoteProvider) bool {
	for _, y := range v.remoteProviders {
		if reflect.DeepEqual(y, p) {
			return true
		}
	}
	return false
}

// ReadRemoteConfig reads and merges all registered remote configuration
// sources. Providers added later override earlier providers.
func ReadRemoteConfig() error {
	return v.getKeyValueConfig(false)
}

// ReadRemoteConfigWithMerged reads and optionally deep-merges all remote configuration sources.
func ReadRemoteConfigWithMerged(merged bool) error {
	return v.getKeyValueConfig(merged)
}

// ReadRemoteConfig reads and merges all registered remote configuration
// sources. Providers added later override earlier providers.
func (v *Viper) ReadRemoteConfig() error {
	return v.getKeyValueConfig(false)
}

// ReadRemoteConfigWithMerged reads and optionally deep-merges all remote configuration sources.
func (v *Viper) ReadRemoteConfigWithMerged(merged bool) error {
	return v.getKeyValueConfig(merged)
}

// WatchRemoteConfig updates configuration from available remote providers.
func WatchRemoteConfig() error { return v.WatchRemoteConfig() }

// WatchRemoteConfig updates configuration from available remote providers.
func (v *Viper) WatchRemoteConfig() error {
	return v.watchKeyValueConfig()
}

// WatchRemoteConfigOnChannel updates configuration from available remote providers.
func (v *Viper) WatchRemoteConfigOnChannel() error {
	return v.watchKeyValueConfigOnChannel()
}

// WatchRemoteConfigWithChannel watches every registered remote provider and
// forwards changes to receiver. The initial snapshot and watch startup are not
// atomic, so an update can occur between those operations.
func (v *Viper) WatchRemoteConfigWithChannel(ctx context.Context, receiver chan *RemoteResponse, deepMerge bool) error {
	if receiver == nil {
		return RemoteConfigError("Response receiver must not be nil")
	}
	return v.watchKeyValueConfigWithChannel(ctx, receiver, deepMerge)
}

// Retrieve and merge all remote configurations transactionally.
func (v *Viper) getKeyValueConfig(deepMerge bool) error {
	if RemoteConfig == nil {
		return RemoteConfigError("Enable the remote features by doing a blank import of the viper/remote package: '_ github.com/alkaid/viper/remote'")
	}

	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}

	snapshots := make([]map[string]any, len(v.remoteProviders))
	var providerErrors []error
	successfulProviders := 0
	for i, rp := range v.remoteProviders {
		val, err := v.getRemoteConfig(rp)
		if err != nil {
			providerErr := fmt.Errorf("remote provider %s %s: %w", rp.Provider(), rp.Path(), err)
			v.logger.Error(providerErr.Error())
			providerErrors = append(providerErrors, providerErr)
			continue
		}
		snapshots[i] = val
		successfulProviders++
	}
	if len(providerErrors) != 0 {
		if successfulProviders == 0 {
			providerErrors = append(providerErrors, RemoteConfigError("No Files Found"))
		}
		return errors.Join(providerErrors...)
	}

	v.remoteMu.Lock()
	if v.remoteSnapshots == nil {
		v.remoteSnapshots = make(map[*defaultRemoteProvider]map[string]any)
	}
	for i, rp := range v.remoteProviders {
		v.remoteSnapshots[rp] = snapshots[i]
	}
	v.kvstore = v.mergeRemoteConfigSnapshots(snapshots, deepMerge)
	v.remoteMu.Unlock()
	return nil
}

func (v *Viper) getRemoteConfig(provider RemoteProvider) (map[string]any, error) {
	reader, err := RemoteConfig.Get(provider)
	if err != nil {
		return nil, err
	}
	val := map[string]any{}
	err = v.unmarshalReader(reader, val)
	return val, err
}

// mergeRemoteConfigSnapshots rebuilds the effective remote configuration from
// all known provider snapshots.
//
// remoteProviders are registered from low priority to high priority, so this
// function intentionally merges snapshots in slice order. Later snapshots
// overwrite earlier snapshots for the same key, while lower-priority snapshots
// still contribute fields that no higher-priority snapshot defines.
func (v *Viper) mergeRemoteConfigSnapshots(snapshots []map[string]any, deepMerge bool) map[string]any {
	merged := make(map[string]any)

	for _, snapshot := range snapshots {
		if snapshot == nil {
			continue
		}
		v.mergeRemoteConfigSnapshot(merged, snapshot, deepMerge)
	}

	return merged
}

func (v *Viper) mergeRemoteConfigSnapshot(dst, snapshot map[string]any, deepMerge bool) {
	if deepMerge {
		// mergo merges nested maps by mutating the destination map in place.
		// Copy the source snapshot first so the effective kvstore never shares
		// nested map or slice values with a provider snapshot. The watch path
		// later replaces individual snapshots and then rebuilds kvstore from
		// scratch, so keeping those two data sets independent avoids stale
		// references between generations of the merged config.
		if err := mergo.Merge(&dst, copyRemoteConfigMap(snapshot), mergo.WithOverride); err != nil {
			v.logger.Error(fmt.Errorf("remote config merge error: %w", err).Error())
			for key, value := range snapshot {
				dst[key] = copyRemoteConfigValue(value)
			}
		}
		return
	}

	for key, value := range snapshot {
		dst[key] = copyRemoteConfigValue(value)
	}
}

func copyRemoteConfigMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = copyRemoteConfigValue(v)
	}
	return dst
}

func copyRemoteConfigValue(src any) any {
	switch v := src.(type) {
	case map[string]any:
		return copyRemoteConfigMap(v)
	case []any:
		dst := make([]any, len(v))
		for i, item := range v {
			dst[i] = copyRemoteConfigValue(item)
		}
		return dst
	default:
		return v
	}
}

func sendRemoteResponse(ctx context.Context, receiver chan<- *RemoteResponse, response *RemoteResponse) bool {
	select {
	case receiver <- response:
		return true
	case <-ctx.Done():
		return false
	}
}

// Retrieve the first found remote configuration.
func (v *Viper) watchKeyValueConfigOnChannel() error {
	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}

	for _, rp := range v.remoteProviders {
		respc, _ := RemoteConfig.WatchChannel(rp)
		// Todo: Add quit channel
		go func(rc <-chan *RemoteResponse) {
			for {
				b, ok := <-rc
				// 校验异常
				if !ok {
					break
				}
				if b.Error != nil {
					v.logger.Error(fmt.Errorf("viper watchKeyValueConfigWithChannel watch remote config: %w", b.Error).Error())
					break
				}
				reader := bytes.NewReader(b.Value)
				value := copyRemoteConfigMap(v.remoteSnapshot())
				err := v.unmarshalReader(reader, value)
				if err == nil {
					v.remoteMu.Lock()
					v.kvstore = value
					// Legacy watches merge into the effective map, so their provider
					// contributions cannot be recovered from it. Invalidate the cache
					// rather than roll back to an older provider snapshot on restart.
					clear(v.remoteSnapshots)
					v.remoteMu.Unlock()
				}
				if err != nil {
					v.logger.Error(fmt.Errorf("failed to unmarshal remote config: %w", err).Error())
				}
			}
		}(respc)
		return nil
	}
	return RemoteConfigError("No Files Found")
}

// watchKeyValueConfigWithChannel Retrieve the first found remote configuration.
//
//	比 watchKeyValueConfigOnChannel 多了channel回调
func (v *Viper) watchKeyValueConfigWithChannel(ctx context.Context, receiver chan *RemoteResponse, deepMerge bool) error {
	if RemoteConfig == nil {
		return RemoteConfigError("Enable the remote features by doing a blank import of the viper/remote package: '_ github.com/alkaid/viper/remote'")
	}

	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}
	providers := append([]*defaultRemoteProvider(nil), v.remoteProviders...)
	snapshots := make([]map[string]any, len(providers))

	for i, rp := range providers {
		val, err := v.getRemoteConfig(rp)
		if err != nil {
			v.remoteMu.RLock()
			cached, ok := v.remoteSnapshots[rp]
			v.remoteMu.RUnlock()
			if !ok {
				return fmt.Errorf("viper watch get %s %s: %w", rp.Provider(), rp.Path(), err)
			}
			v.logger.Error("remote snapshot unavailable; retaining previous value", "path", rp.Path(), "error", err)
			val = cached
		}
		snapshots[i] = val
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	v.remoteMu.Lock()
	if v.remoteSnapshots == nil {
		v.remoteSnapshots = make(map[*defaultRemoteProvider]map[string]any)
	}
	for i, rp := range providers {
		v.remoteSnapshots[rp] = snapshots[i]
	}
	v.kvstore = v.mergeRemoteConfigSnapshots(snapshots, deepMerge)
	v.remoteMu.Unlock()

	responseChans := make([]<-chan *RemoteResponse, len(providers))
	quitChans := make([]chan bool, len(providers))
	for i, rp := range providers {
		respc, quit := RemoteConfig.WatchChannel(rp)
		if respc == nil || quit == nil {
			if quit != nil {
				close(quit)
			}
			for _, startedQuit := range quitChans[:i] {
				if startedQuit != nil {
					close(startedQuit)
				}
			}
			return fmt.Errorf("viper watchKeyValueConfigWithChannel watch channel unavailable for %s %s", rp.Provider(), rp.Path())
		}
		responseChans[i] = respc
		quitChans[i] = quit
	}

	for i := range providers {
		go func(index int) {
			defer close(quitChans[index])
			for {
				select {
				case <-ctx.Done():
					return
				case response, ok := <-responseChans[index]:
					if !ok || response == nil {
						sendRemoteResponse(ctx, receiver, &RemoteResponse{Error: fmt.Errorf("remote watch closed: %s", providers[index].Path())})
						return
					}
					if response.Error != nil {
						sendRemoteResponse(ctx, receiver, response)
						return
					}
					snapshot := map[string]any{}
					if err := v.unmarshalReader(bytes.NewReader(response.Value), snapshot); err != nil {
						v.logger.Error("invalid remote configuration; retaining previous snapshot", "path", providers[index].Path(), "error", err)
						continue
					}
					v.remoteMu.Lock()
					if ctx.Err() != nil {
						v.remoteMu.Unlock()
						return
					}
					snapshots[index] = snapshot
					for j, rp := range providers {
						v.remoteSnapshots[rp] = snapshots[j]
					}
					v.kvstore = v.mergeRemoteConfigSnapshots(snapshots, deepMerge)
					v.remoteMu.Unlock()
					if !sendRemoteResponse(ctx, receiver, response) {
						return
					}
				}
			}
		}(i)
	}

	return nil
}

// Retrieve the first found remote configuration.
func (v *Viper) watchKeyValueConfig() error {
	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}

	for _, rp := range v.remoteProviders {
		val, err := v.watchRemoteConfig(rp)
		if err != nil {
			v.logger.Error(fmt.Errorf("watch remote config: %w", err).Error())

			continue
		}
		v.remoteMu.Lock()
		v.kvstore = val
		clear(v.remoteSnapshots) // see the legacy channel watch above
		v.remoteMu.Unlock()
		return nil
	}
	return RemoteConfigError("No Files Found")
}

func (v *Viper) watchRemoteConfig(provider RemoteProvider) (map[string]any, error) {
	reader, err := RemoteConfig.Watch(provider)
	if err != nil {
		return nil, err
	}
	value := copyRemoteConfigMap(v.remoteSnapshot())
	err = v.unmarshalReader(reader, value)
	return value, err
}
