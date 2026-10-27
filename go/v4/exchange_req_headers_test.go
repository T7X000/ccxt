package ccxt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Only scalar pointers are dereferenced; maps, map pointers, slices and nils must keep the
// formatting FetchAsync always used (coinbase can pass a map through the header path).
func TestHeaderValueToString(t *testing.T) {
	token := "my-session-token"
	if got := headerValueToString(&token); got != token {
		t.Fatalf("*string header formatted as %q, want %q", got, token)
	}
	m := map[string]any{"a": 1}
	var nilMap map[string]any
	var nilString *string
	unchanged := map[string]any{
		"string":      "plain",
		"map":         m,
		"*map":        &m,
		"nil map":     nilMap,
		"nil *string": nilString,
		"[]any":       []any{1, "x"},
		"nil":         nil,
	}
	for name, value := range unchanged {
		if got, want := headerValueToString(value), fmt.Sprintf("%v", value); got != want {
			t.Errorf("%s header formatted as %q, want %q", name, got, want)
		}
	}
}

// Header values produced by a transpiled sign() can be *string (SafeString returns a pointer),
// e.g. ndax's "APToken": sessionToken. FetchAsync must send the string, not the pointer address.
func TestFetchAsyncDereferencesPointerHeaders(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("APToken")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":true}`))
	}))
	defer server.Close()

	exchange := NewNdax(map[string]any{
		"apiKey":   "key",
		"secret":   "secret",
		"uid":      "1",
		"login":    "login",
		"password": "password",
		"urls": map[string]any{
			"api": map[string]any{
				"public":  server.URL,
				"private": server.URL,
			},
		},
		"options": map[string]any{
			"sessionToken": "my-session-token",
		},
	})

	signed := exchange.Sign("GetAccountInfo", []any{"private"}, "GET", map[string]any{}).(map[string]any)
	headers := signed["headers"].(map[string]any)
	if _, isPointer := headers["APToken"].(*string); !isPointer {
		t.Fatalf("expected the transpiled Sign to put a *string in APToken, got %T", headers["APToken"])
	}

	result := <-exchange.FetchAsync(signed["url"], signed["method"], headers, signed["body"])
	if result.Err != nil {
		t.Fatalf("FetchAsync failed: %v", result.Err)
	}

	got := <-received
	if got != "my-session-token" {
		t.Fatalf("APToken header sent as %q, want %q", got, "my-session-token")
	}
}
