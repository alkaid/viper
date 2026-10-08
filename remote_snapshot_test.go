package viper

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRemoteSnapshotPinsDocumentAndOptions(t *testing.T) {
	f := newTestRemoteConfigFactory(map[string][]byte{"/config": []byte(`{"feature":{"nested":{"value":"one","labels":{"host.example.com":"enabled"}}}}`)})
	installTestRemoteConfig(t, f)
	v := NewWithOptions(KeyDelimiter("::"), ExperimentalBindStruct())
	v.SetConfigType("json")
	v.AutomaticEnv()
	t.Setenv("CUSTOM_LABEL", "from-env")
	require.NoError(t, v.AddRemoteProvider("etcd3", "test", "/config"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan *RemoteResponse, 1)
	require.NoError(t, v.WatchRemoteConfigWithChannel(ctx, out, true))
	first := v.SnapshotRemoteConfig()
	require.True(t, first.SameConfig(v.SnapshotRemoteConfig()))
	require.NoError(t, f.Send("/config", []byte(`{"feature":{"nested":{"value":"two"}}}`)))
	requireRemoteResponse(t, out)
	second := v.SnapshotRemoteConfig()
	require.False(t, first.SameConfig(second))
	var decoded struct {
		Value  string
		Labels map[string]string
	}
	require.NoError(t, first.UnmarshalKey("feature::nested", &decoded))
	require.Equal(t, "one", decoded.Value)
	require.Equal(t, map[string]string{"host.example.com": "enabled"}, decoded.Labels)
	var current struct{ Value string }
	require.NoError(t, second.UnmarshalKey("feature::nested", &current))
	require.Equal(t, "two", current.Value)
	var environment struct {
		CustomLabel string `mapstructure:"custom_label"`
	}
	require.NoError(t, first.Unmarshal(&environment))
	require.Equal(t, "from-env", environment.CustomLabel)
	quit, _ := f.Quit("/config")
	cancel()
	select {
	case <-quit:
	case <-time.After(time.Second):
		t.Fatal("watch did not stop")
	}
}
