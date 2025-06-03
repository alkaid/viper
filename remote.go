package viper

import (
	"bytes"
	"context"
	"dario.cat/mergo"
	"fmt"
	"io"
	"reflect"
	"slices"
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
	return rp.endpoints
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
// Remote Providers are searched in the order they are added.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port, consul requires ip:port, nats requires nats://ip:port
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
func AddRemoteProvider(provider, endpoint, path string) error {
	return v.AddRemoteProvider(provider, endpoint, path)
}

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

func (v *Viper) AddRemoteProviderCluster(provider string, endpoints []string, path string) error {
	if !slices.Contains(SupportedRemoteProviders, provider) {
		return UnsupportedRemoteProviderError(provider)
	}
	if provider != "" && len(endpoints) != 0 {
		v.logger.Info("adding remote provider", "provider", provider, "endpoints", endpoints)

		rp := &defaultRemoteProvider{
			endpoints: endpoints,
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
// Secure Remote Providers are searched in the order they are added.
// provider is a string value: "etcd", "etcd3", "consul", "firestore" or "nats" are currently supported.
// endpoint is the url.  etcd requires http://ip:port  consul requires ip:port
// secretkeyring is the filepath to your openpgp secret keyring.  e.g. /etc/secrets/myring.gpg
// path is the path in the k/v store to retrieve configuration
// To retrieve a config file called myapp.json from /configs/myapp.json
// you should set path to /configs and set config name (SetConfigName()) to
// "myapp".
// Secure Remote Providers are implemented with github.com/sagikazarmark/crypt.
func AddSecureRemoteProvider(provider, endpoint, path, secretkeyring string) error {
	return v.AddSecureRemoteProvider(provider, endpoint, path, secretkeyring)
}

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

// ReadRemoteConfig attempts to get configuration from a remote source
// and read it in the remote configuration registry.
func ReadRemoteConfig() error {
	return v.getKeyValueConfig(false)
}
func ReadRemoteConfigWithMerged(merged bool) error {
	return v.getKeyValueConfig(merged)
}

func (v *Viper) ReadRemoteConfig() error {
	return v.getKeyValueConfig(false)
}
func (v *Viper) ReadRemoteConfigWithMerged(merged bool) error {
	return v.getKeyValueConfig(merged)
}

func WatchRemoteConfig() error { return v.WatchRemoteConfig() }
func (v *Viper) WatchRemoteConfig() error {
	return v.watchKeyValueConfig()
}

func (v *Viper) WatchRemoteConfigOnChannel() error {
	return v.watchKeyValueConfigOnChannel()
}

// WatchRemoteConfigWithChannel WatchRemoteConfigOnChannel 的增强实现,多了channel回调
//
//	@receiver v
//	@param ctx 要取消请传入 context.WithCancel
//	@param receiver
//	@param deepMerge
//	@return error
func (v *Viper) WatchRemoteConfigWithChannel(ctx context.Context, receiver chan *RemoteResponse, deepMerge bool) error {
	return v.watchKeyValueConfigWithChannel(ctx, receiver, deepMerge)
}

// Retrieve the first found remote configuration.
func (v *Viper) getKeyValueConfig(deepMerge bool) error {
	if RemoteConfig == nil {
		return RemoteConfigError("Enable the remote features by doing a blank import of the viper/remote package: '_ github.com/spf13/viper/remote'")
	}

	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}

	var found = false
	for _, rp := range v.remoteProviders {
		val, err := v.getRemoteConfig(rp)
		if err != nil {
			v.logger.Error(fmt.Errorf("get remote config: %w", err).Error())

			continue
		}
		found = true
		// 允许多个远程文件合并
		if deepMerge {
			// 允许深度合并
			if err = mergo.Merge(&v.kvstore, val, mergo.WithOverride); err != nil {
				v.logger.Error(fmt.Errorf("get remote config merge error: %w", err).Error())
				for k, v_ := range val {
					v.kvstore[k] = v_
				}
			}
		} else {
			// 只合并第一层
			for k, v_ := range val {
				v.kvstore[k] = v_
			}
		}
	}
	if found {
		return nil
	}
	return RemoteConfigError("No Files Found")
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
				v.unmarshalReader(reader, v.kvstore)
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
	if len(v.remoteProviders) == 0 {
		return RemoteConfigError("No Remote Providers")
	}
	for _, rp := range v.remoteProviders {
		respc, quit := RemoteConfig.WatchChannel(rp)
		// 去掉todo 已经加上quit channel
		go func(rc <-chan *RemoteResponse, quit chan<- bool) {
			// 关闭quit避免crypt库里goroutine泄漏,TODO 更好的方式是使用传入CancelContext来控制退出,这里受限于接口定义,不好改动
			defer close(quit)
			for {
				select {
				case <-ctx.Done():
					quit <- true
					return
				case b, ok := <-rc:
					if !ok {
						return
					}
					if b.Error != nil {
						v.logger.Error(fmt.Errorf("viper watchKeyValueConfigWithChannel watch remote config: %w", b.Error).Error())
						receiver <- b
						return
					}
					reader := bytes.NewReader(b.Value)
					val := map[string]any{}
					err := v.unmarshalReader(reader, val)
					if err != nil {
						v.logger.Error(fmt.Errorf("viper watchKeyValueConfigWithChannel watch remote config: %w", err).Error())
						continue
					}
					// 允许多个远程文件合并
					if deepMerge {
						// 允许深度合并
						if err = mergo.Merge(&v.kvstore, val, mergo.WithOverride); err != nil {
							v.logger.Error(fmt.Errorf("viper watchKeyValueConfigWithChannel merge error: %w", err).Error())
							for k, v_ := range val {
								v.kvstore[k] = v_
							}
						}
					} else {
						// 只合并第一层
						for k, v_ := range val {
							v.kvstore[k] = v_
						}
					}
					receiver <- b
				}
			}
		}(respc, quit)
		// 官方bug 造成只监听一个 provider
		// return nil
	}
	if len(v.remoteProviders) > 0 {
		return nil
	}
	return RemoteConfigError("No Files Found")
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
		v.kvstore = val
		return nil
	}
	return RemoteConfigError("No Files Found")
}

func (v *Viper) watchRemoteConfig(provider RemoteProvider) (map[string]any, error) {
	reader, err := RemoteConfig.Watch(provider)
	if err != nil {
		return nil, err
	}
	err = v.unmarshalReader(reader, v.kvstore)
	return v.kvstore, err
}
