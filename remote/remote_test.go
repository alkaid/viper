package remote

import (
	"sync/atomic"
	"testing"
	"time"

	crypt "github.com/alkaid/crypt/config"
	"github.com/alkaid/viper"
)

type fakeConfigManager struct {
	responses <-chan *crypt.Response
	stop      chan bool
}

func (m *fakeConfigManager) Get(string) ([]byte, error) {
	return nil, nil
}

func (m *fakeConfigManager) List(string) (crypt.KVPairs, error) {
	return nil, nil
}

func (m *fakeConfigManager) Set(string, []byte) error {
	return nil
}

func (m *fakeConfigManager) Watch(_ string, stop chan bool) <-chan *crypt.Response {
	m.stop = stop
	return m.responses
}

func TestWatchConfigManagerQuitInterruptsBlockedResponse(t *testing.T) {
	cryptResponses := make(chan *crypt.Response)
	manager := &fakeConfigManager{responses: cryptResponses}
	viperResponses, quit := watchConfigManager(manager, "/config")
	responseReceived := make(chan struct{})

	go func() {
		cryptResponses <- &crypt.Response{Value: []byte("value")}
		close(responseReceived)
	}()

	requireClosed(t, responseReceived, "crypt response handoff")
	close(quit)
	requireClosed(t, manager.stop, "crypt stop")
	requireClosed(t, viperResponses, "Viper response")
}

type countingRemoteProvider struct {
	endpointCalls atomic.Int32
}

func (p *countingRemoteProvider) Provider() string {
	return "consul"
}

func (p *countingRemoteProvider) Endpoint() string {
	return "unused"
}

func (p *countingRemoteProvider) Endpoints() []string {
	p.endpointCalls.Add(1)
	return []string{"127.0.0.1:8500"}
}

func (p *countingRemoteProvider) Path() string {
	return "/config"
}

func (p *countingRemoteProvider) SecretKeyring() string {
	return ""
}

func TestGetConfigManagerReadsEndpointsOnce(t *testing.T) {
	provider := &countingRemoteProvider{}

	manager, err := getConfigManager(provider)
	if err != nil {
		t.Fatalf("getConfigManager returned an error: %v", err)
	}
	if manager == nil {
		t.Fatal("getConfigManager returned a nil manager")
	}
	if got := provider.endpointCalls.Load(); got != 1 {
		t.Fatalf("Endpoints was called %d times, want 1", got)
	}
}

func requireClosed[T any](t *testing.T, channel <-chan T, name string) {
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

var _ viper.RemoteProvider = (*countingRemoteProvider)(nil)
