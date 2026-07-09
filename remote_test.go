package viper

import (
	"bytes"
	"context"
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

type testRemoteConfigFactory struct {
	mu       sync.Mutex
	values   map[string][]byte
	watchers map[string]chan *RemoteResponse
}

func newTestRemoteConfigFactory(values map[string][]byte) *testRemoteConfigFactory {
	copiedValues := make(map[string][]byte, len(values))
	for path, value := range values {
		copiedValues[path] = append([]byte(nil), value...)
	}

	return &testRemoteConfigFactory{
		values:   copiedValues,
		watchers: make(map[string]chan *RemoteResponse),
	}
}

func (f *testRemoteConfigFactory) Get(rp RemoteProvider) (io.Reader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	value, ok := f.values[rp.Path()]
	if !ok {
		return nil, fmt.Errorf("missing remote config for path %q", rp.Path())
	}
	return bytes.NewReader(append([]byte(nil), value...)), nil
}

func (f *testRemoteConfigFactory) Watch(rp RemoteProvider) (io.Reader, error) {
	return f.Get(rp)
}

func (f *testRemoteConfigFactory) WatchChannel(rp RemoteProvider) (<-chan *RemoteResponse, chan bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	responses := make(chan *RemoteResponse, 2)
	f.watchers[rp.Path()] = responses
	return responses, make(chan bool, 1)
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
