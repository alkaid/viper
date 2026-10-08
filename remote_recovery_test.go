package viper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWatchCloseReachesSupervisor(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/config": []byte(`{"v":1}`)})
	installTestRemoteConfig(t, f)
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/config"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *RemoteResponse, 1)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	f.mu.Lock()
	close(f.watchers["/config"])
	f.mu.Unlock()
	select {
	case r := <-out:
		require.Error(t, r.Error)
	case <-time.After(time.Second):
		t.Fatal("provider close was swallowed")
	}
}

func TestConcurrentRemoteReadsAndWholeSnapshots(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/config": []byte(`{"a":0,"b":0}`)})
	installTestRemoteConfig(t, f)
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/config"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *RemoteResponse, 1000)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 300 {
			f.Send("/config", []byte(fmt.Sprintf(`{"a":%d,"b":%d}`, i, i)))
		}
	}()
	for range 300 {
		v.Get("a")
		v.IsSet("b")
		v.AllKeys()
		settings := v.AllSettings()
		require.Equal(t, settings["a"], settings["b"])
		var decoded struct{ A, B int }
		require.NoError(t, v.Unmarshal(&decoded))
		require.Equal(t, decoded.A, decoded.B)
	}
	<-done
	quit, _ := f.Quit("/config")
	cancel()
	select {
	case <-quit:
	case <-time.After(time.Second):
		t.Fatal("watch not stopped")
	}
}

func TestWatchRestartRetainsProviderContributionAndRemovedFields(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/low": []byte(`{"shared":"low"}`), "/high": []byte(`{"shared":"high","removed":true}`)})
	installTestRemoteConfig(t, f)
	v := New()
	v.SetConfigType("json")
	for _, key := range []string{"/low", "/high"} {
		require.NoError(t, v.AddRemoteProvider("etcd3", "test", key))
	}
	require.NoError(t, v.ReadRemoteConfigWithMerged(true))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *RemoteResponse, 2)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	require.NoError(t, f.Send("/high", []byte(`{}`)))
	requireRemoteResponse(t, out)
	require.Equal(t, "low", v.GetString("shared"))
	require.False(t, v.IsSet("removed"))
	lowQuit, _ := f.Quit("/low")
	highQuit, _ := f.Quit("/high")
	cancel()
	<-lowQuit
	<-highQuit
	f.SetError("/high", fmt.Errorf("key missing"))
	f.SetValue("/low", []byte(`{"shared":"latest-low"}`))
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	require.Equal(t, "latest-low", v.GetString("shared"))
	require.False(t, v.IsSet("removed"))
	require.NoError(t, f.Send("/high", []byte(`{"shared":"restored"}`)))
	requireRemoteResponse(t, out)
	require.Equal(t, "restored", v.GetString("shared"))
	lowQuit, _ = f.Quit("/low")
	highQuit, _ = f.Quit("/high")
	cancel()
	<-lowQuit
	<-highQuit
}

func TestLegacyRefreshKeepsOtherProvider(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/low": []byte(`{"low":1}`), "/high": []byte(`{"high":1}`)})
	installTestRemoteConfig(t, f)
	v := New()
	v.SetConfigType("json")
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/low"))
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/high"))
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		for _, key := range []string{"/low", "/high"} {
			quit, _ := f.Quit(key)
			select {
			case <-quit:
			case <-time.After(time.Second):
				t.Errorf("watch %s did not stop", key)
			}
		}
	}()
	out := make(chan *RemoteResponse, 1)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	require.NoError(t, v.WatchRemoteConfig())
	require.Equal(t, 1, v.GetInt("high"))
	require.NoError(t, f.Send("/low", []byte(`{"low":2}`)))
	requireRemoteResponse(t, out)
	require.Equal(t, 2, v.GetInt("low"))
	require.Equal(t, 1, v.GetInt("high"))
}
