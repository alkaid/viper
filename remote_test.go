package viper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchRemoteConfigWithChannelRespectsProviderPriority(t *testing.T) {
	v := New()
	v.SetConfigType("json")

	remoteConfig := newTestRemoteConfigFactory(map[string][]byte{
		"/low":  []byte(`{"shared":{"value":"low","low_only":"low-initial"},"only_low":"low-initial"}`),
		"/high": []byte(`{"shared":{"value":"high","high_only":"high-initial"},"only_high":"high-initial"}`),
	})

	oldRemoteConfig := RemoteConfig
	RemoteConfig = remoteConfig
	t.Cleanup(func() {
		RemoteConfig = oldRemoteConfig
	})

	// Providers are registered from low priority to high priority. The high
	// priority provider should own shared.value even if the low priority provider
	// is the one that later sends a watch event for the same field.
	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/low"))
	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/high"))
	require.NoError(t, v.ReadRemoteConfigWithMerged(true))
	assert.Equal(t, "high", v.GetString("shared.value"))
	assert.Equal(t, "low-initial", v.GetString("shared.low_only"))
	assert.Equal(t, "high-initial", v.GetString("shared.high_only"))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	receiver := make(chan *RemoteResponse, 2)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, receiver, true))

	require.NoError(t, remoteConfig.Send("/low", []byte(`{"shared":{"value":"low-updated","low_only":"low-updated"},"only_low":"low-updated"}`)))
	requireRemoteResponse(t, receiver)

	assert.Equal(t, "high", v.GetString("shared.value"))
	assert.Equal(t, "low-updated", v.GetString("shared.low_only"))
	assert.Equal(t, "high-initial", v.GetString("shared.high_only"))
	assert.Equal(t, "low-updated", v.GetString("only_low"))

	require.NoError(t, remoteConfig.Send("/high", []byte(`{"shared":{"value":"high-updated","high_only":"high-updated"},"only_high":"high-updated"}`)))
	requireRemoteResponse(t, receiver)

	assert.Equal(t, "high-updated", v.GetString("shared.value"))
	assert.Equal(t, "low-updated", v.GetString("shared.low_only"))
	assert.Equal(t, "high-updated", v.GetString("shared.high_only"))
	assert.Equal(t, "high-updated", v.GetString("only_high"))
}

func TestReadRemoteConfigReplacesPreviousSnapshot(t *testing.T) {
	for _, deepMerge := range []bool{false, true} {
		t.Run(fmt.Sprintf("deepMerge=%t", deepMerge), func(t *testing.T) {
			v := New()
			v.SetConfigType("json")

			remoteConfig := newTestRemoteConfigFactory(map[string][]byte{
				"/config": []byte(`{"keep":"before","removed":"stale","nested":{"keep":"before","removed":"stale"}}`),
			})
			installTestRemoteConfig(t, remoteConfig)

			require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/config"))
			require.NoError(t, v.ReadRemoteConfigWithMerged(deepMerge))
			assert.Equal(t, "stale", v.GetString("removed"))
			assert.Equal(t, "stale", v.GetString("nested.removed"))

			remoteConfig.SetValue("/config", []byte(`{"keep":"after","nested":{"keep":"after"}}`))
			require.NoError(t, v.ReadRemoteConfigWithMerged(deepMerge))

			assert.Equal(t, "after", v.GetString("keep"))
			assert.Equal(t, "after", v.GetString("nested.keep"))
			assert.False(t, v.IsSet("removed"))
			assert.False(t, v.IsSet("nested.removed"))
		})
	}
}

func TestReadRemoteConfigFailurePreservesPreviousConfig(t *testing.T) {
	v := New()
	v.SetConfigType("json")

	remoteConfig := newTestRemoteConfigFactory(map[string][]byte{
		"/low":  []byte(`{"low":"initial"}`),
		"/high": []byte(`{"high":"initial"}`),
	})
	installTestRemoteConfig(t, remoteConfig)

	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/low"))
	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/high"))
	require.NoError(t, v.ReadRemoteConfigWithMerged(true))
	previous := copyRemoteConfigMap(v.kvstore)

	remoteConfig.SetValue("/low", []byte(`{"low":"updated"}`))
	remoteConfig.SetError("/high", errors.New("high failed"))
	err := v.ReadRemoteConfigWithMerged(true)

	require.ErrorContains(t, err, "consul /high")
	assert.Equal(t, previous, v.kvstore)
}

func TestReadRemoteConfigJoinsProviderErrors(t *testing.T) {
	v := New()
	v.SetConfigType("json")

	remoteConfig := newTestRemoteConfigFactory(map[string][]byte{})
	remoteConfig.SetError("/low", errors.New("low failed"))
	remoteConfig.SetError("/high", errors.New("high failed"))
	installTestRemoteConfig(t, remoteConfig)

	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/low"))
	require.NoError(t, v.AddRemoteProvider("etcd3", "127.0.0.1:2379", "/high"))
	err := v.ReadRemoteConfig()

	require.ErrorContains(t, err, "remote provider consul /low: low failed")
	require.ErrorContains(t, err, "remote provider etcd3 /high: high failed")
	var remoteConfigError RemoteConfigError
	require.ErrorAs(t, err, &remoteConfigError)
	assert.Equal(t, RemoteConfigError("No Files Found"), remoteConfigError)
}

func TestAddRemoteProviderClusterClonesEndpoints(t *testing.T) {
	v := New()
	endpoints := []string{"first", "second"}

	require.NoError(t, v.AddRemoteProviderCluster("etcd3", endpoints, "/config"))
	endpoints[0] = "modified by caller"

	provider := v.remoteProviders[0]
	assert.Equal(t, []string{"first", "second"}, provider.Endpoints())

	returned := provider.Endpoints()
	returned[1] = "modified getter result"
	assert.Equal(t, []string{"first", "second"}, provider.Endpoints())
}

func TestWatchRemoteConfigWithChannelRejectsNilReceiver(t *testing.T) {
	v := New()
	err := v.WatchRemoteConfigWithChannel(context.Background(), nil, false)
	require.ErrorContains(t, err, "receiver must not be nil")
}

func TestWatchRemoteConfigWithChannelClosesStartedWatchersOnSetupFailure(t *testing.T) {
	v := New()
	v.SetConfigType("json")

	remoteConfig := newTestRemoteConfigFactory(map[string][]byte{
		"/low":  []byte(`{"low":true}`),
		"/high": []byte(`{"high":true}`),
	})
	remoteConfig.SetWatchUnavailable("/high")
	installTestRemoteConfig(t, remoteConfig)

	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/low"))
	require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/high"))
	err := v.WatchRemoteConfigWithChannel(context.Background(), make(chan *RemoteResponse, 1), true)
	require.ErrorContains(t, err, "watch channel unavailable for consul /high")

	quit, ok := remoteConfig.Quit("/low")
	require.True(t, ok)
	requireChannelClosed(t, quit, "started provider quit")
	failedQuit, ok := remoteConfig.Quit("/high")
	require.True(t, ok)
	requireChannelClosed(t, failedQuit, "failed provider quit")
}

func TestWatchRemoteConfigWithChannelCancellationInterruptsBlockedReceiver(t *testing.T) {
	for _, receiverState := range []string{"unconsumed", "full"} {
		t.Run(receiverState, func(t *testing.T) {
			v := New()
			v.SetConfigType("json")

			remoteConfig := newTestRemoteConfigFactory(map[string][]byte{
				"/config": []byte(`{"value":"initial"}`),
			})
			remoteConfig.SetWatchBuffer(0)
			installTestRemoteConfig(t, remoteConfig)

			require.NoError(t, v.AddRemoteProvider("consul", "127.0.0.1:8500", "/config"))
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			var receiver chan *RemoteResponse
			if receiverState == "full" {
				receiver = make(chan *RemoteResponse, 1)
				receiver <- &RemoteResponse{}
			} else {
				receiver = make(chan *RemoteResponse)
			}
			require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, receiver, true))

			sendDone := make(chan error, 1)
			go func() {
				sendDone <- remoteConfig.Send("/config", []byte(`{"value":"updated"}`))
			}()
			select {
			case err := <-sendDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for watcher to receive remote response")
			}

			cancel()
			quit, ok := remoteConfig.Quit("/config")
			require.True(t, ok)
			requireChannelClosed(t, quit, "provider quit")
		})
	}
}

type testRemoteConfigFactory struct {
	mu               sync.Mutex
	values           map[string][]byte
	getErrors        map[string]error
	watchers         map[string]chan *RemoteResponse
	quits            map[string]chan bool
	watchUnavailable map[string]bool
	watchBuffer      int
}

func newTestRemoteConfigFactory(values map[string][]byte) *testRemoteConfigFactory {
	copiedValues := make(map[string][]byte, len(values))
	for path, value := range values {
		copiedValues[path] = append([]byte(nil), value...)
	}

	return &testRemoteConfigFactory{
		values:           copiedValues,
		getErrors:        make(map[string]error),
		watchers:         make(map[string]chan *RemoteResponse),
		quits:            make(map[string]chan bool),
		watchUnavailable: make(map[string]bool),
		watchBuffer:      2,
	}
}

func installTestRemoteConfig(t *testing.T, remoteConfig remoteConfigFactory) {
	t.Helper()

	oldRemoteConfig := RemoteConfig
	RemoteConfig = remoteConfig
	t.Cleanup(func() {
		RemoteConfig = oldRemoteConfig
	})
}

func (f *testRemoteConfigFactory) Get(rp RemoteProvider) (io.Reader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := rp.Path()
	if err := f.getErrors[path]; err != nil {
		return nil, err
	}
	value, ok := f.values[path]
	if !ok {
		return nil, fmt.Errorf("missing remote config for path %q", path)
	}
	return bytes.NewReader(append([]byte(nil), value...)), nil
}

func (f *testRemoteConfigFactory) Watch(rp RemoteProvider) (io.Reader, error) {
	return f.Get(rp)
}

func (f *testRemoteConfigFactory) WatchChannel(rp RemoteProvider) (<-chan *RemoteResponse, chan bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := rp.Path()
	quit := make(chan bool)
	f.quits[path] = quit
	if f.watchUnavailable[path] {
		return nil, quit
	}
	responses := make(chan *RemoteResponse, f.watchBuffer)
	f.watchers[path] = responses
	return responses, quit
}

func (f *testRemoteConfigFactory) Send(path string, value []byte) error {
	f.mu.Lock()
	responses, ok := f.watchers[path]
	if ok {
		f.values[path] = append([]byte(nil), value...)
	}
	f.mu.Unlock()
	if !ok {
		return fmt.Errorf("missing watcher for path %q", path)
	}

	responses <- &RemoteResponse{Value: append([]byte(nil), value...)}
	return nil
}

func (f *testRemoteConfigFactory) SetValue(path string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[path] = append([]byte(nil), value...)
}

func (f *testRemoteConfigFactory) SetError(path string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getErrors[path] = err
}

func (f *testRemoteConfigFactory) SetWatchUnavailable(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchUnavailable[path] = true
}

func (f *testRemoteConfigFactory) SetWatchBuffer(size int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchBuffer = size
}

func (f *testRemoteConfigFactory) Quit(path string) (<-chan bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	quit, ok := f.quits[path]
	return quit, ok
}

func requireRemoteResponse(t *testing.T, receiver <-chan *RemoteResponse) {
	t.Helper()

	select {
	case response := <-receiver:
		require.NotNil(t, response)
		require.NoError(t, response.Error)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for remote response")
	}
}

func requireChannelClosed[T any](t *testing.T, channel <-chan T, name string) {
	t.Helper()

	select {
	case _, ok := <-channel:
		if ok {
			t.Fatalf("%s channel sent an unexpected value", name)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s channel to close", name)
	}
}
