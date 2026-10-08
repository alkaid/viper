package viper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type readingDecoderRegistry struct{ decoder Decoder }

func (r readingDecoderRegistry) Decoder(string) (Decoder, error) { return r.decoder, nil }

type readingDecoderFunc func([]byte, map[string]any) error

func (f readingDecoderFunc) Decode(b []byte, m map[string]any) error { return f(b, m) }

func TestLegacyRemoteDecoderCanReadDefaults(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/config": []byte(`{"v":1}`)})
	installTestRemoteConfig(t, f)
	var v *Viper
	done := make(chan struct{})
	v = NewWithOptions(WithDecoderRegistry(readingDecoderRegistry{readingDecoderFunc(func(b []byte, m map[string]any) error {
		_ = v.GetString("decoder-default")
		defer close(done)
		return json.Unmarshal(b, &m)
	})}))
	v.SetDefault("decoder-default", "value")
	v.SetConfigType("json")
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/config"))
	require.NoError(t, v.WatchRemoteConfigOnChannel())
	require.NoError(t, f.Send("/config", []byte(`{"v":2}`)))
	select {
	case <-done:
		f.mu.Lock()
		close(f.watchers["/config"])
		f.mu.Unlock()
	case <-time.After(200 * time.Millisecond):
		t.Fatal("custom decoder's public Get deadlocked inside remote update")
	}
}

func TestRestartAfterLegacyWatchRetainsLatestValue(t *testing.T) {
	for _, channel := range []bool{false, true} {
		t.Run(fmt.Sprint(channel), func(t *testing.T) {
			f := newTestRemoteConfigFactory(map[string][]byte{"/config": []byte(`{"version":1}`)})
			installTestRemoteConfig(t, f)
			v := New()
			v.SetConfigType("json")
			require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/config"))
			require.NoError(t, v.ReadRemoteConfig())
			f.SetValue("/config", []byte(`{"version":2}`))
			if channel {
				require.NoError(t, v.WatchRemoteConfigOnChannel())
				require.NoError(t, f.Send("/config", []byte(`{"version":2}`)))
				require.Eventually(t, func() bool { return v.GetInt("version") == 2 }, time.Second, time.Millisecond)
				f.mu.Lock()
				close(f.watchers["/config"])
				f.mu.Unlock()
			} else {
				require.NoError(t, v.WatchRemoteConfig())
			}
			require.Equal(t, 2, v.GetInt("version"))
			f.SetError("/config", errors.New("temporarily unavailable"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.Error(t, v.WatchRemoteConfigWithChannel(ctx, make(chan *RemoteResponse, 1), true))
			require.Equal(t, 2, v.GetInt("version"))
		})
	}
}
