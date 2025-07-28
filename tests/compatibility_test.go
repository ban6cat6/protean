// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protean_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	protean "github.com/ban6cat6/protean"

	"golang.org/x/net/http2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp/fasthttputil"
)

type clientPublicKeyStore struct {
	sync.Map
}

func (c *clientPublicKeyStore) Get(fp protean.Fingerprint) (ed25519.PublicKey, bool) {
	v, ok := c.Load(fp)
	if !ok {
		return nil, false
	}
	return v.(ed25519.PublicKey), true
}

func (c *clientPublicKeyStore) Put(fp protean.Fingerprint, pk ed25519.PublicKey) {
	c.Store(fp, pk)
}

func testCompatibility(t *testing.T, target string) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()
	expectedResponse := "Compatibility test successful"
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	fpA := protean.GetFingerprint(pkA)
	fpB := protean.GetFingerprint(pkB)

	parts := strings.Split(target, ":")
	require.True(t, len(parts) == 1 || len(parts) == 2)
	if len(parts) == 1 {
		target += ":443"
	}
	serverName := parts[0]

	upstreamConn, err := net.Dial("tcp", target)
	require.Nil(t, err)
	defer upstreamConn.Close()

	pipe := fasthttputil.NewPipeConns()
	clientConn, serverConn := pipe.Conn1(), pipe.Conn2()
	wg.Add(1)
	go func() {
		defer wg.Done()
		pconfig := &protean.PConfig{
			ClientFp:         fpB,
			ServerFp:         fpA,
			ClientPrivateKey: skB,
			ServerPublicKey:  pkA,
		}
		tr := http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return protean.PClient(clientConn, pconfig, &protean.Config{
					ServerName: serverName,
					NextProtos: cfg.NextProtos,
				}, protean.HelloChrome_Auto)
			},
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "https://"+target, nil)
		if !assert.Nil(t, err) {
			return
		}
		resp, err := tr.RoundTrip(req)
		if !assert.Nil(t, err) {
			return
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if !assert.Nil(t, err) {
			return
		}
		if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
			return
		}
		if !assert.Equal(t, expectedResponse, string(data)) {
			return
		}
	}()

	cpkStore := &clientPublicKeyStore{}
	cpkStore.Put(fpB, pkB)
	pconn, err := protean.PServer(serverConn, upstreamConn, &protean.PConfig{
		ServerFp:         fpA,
		ClientFp:         fpB,
		ServerPrivateKey: skA,
		ClientPublicKeys: cpkStore,
	})
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	srv := http2.Server{}
	srv.ServeConn(pconn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(expectedResponse))
			if !assert.Nil(t, err) {
				return
			}
		}),
	})
}

func TestCompatibility(t *testing.T) {
	t.Parallel()
	targets := []string{
		"nginx.org",                  // TLS 1.2?
		"tls-v1-2.badssl.com:1012",   // TLS 1.2 for sure
		"aws.amazon.com",             // TLS 1.3 with X25519
		"cdn.onenote.net",            // TLS 1.3 with X25519
		"pages.github.com",           // TLS 1.3 with X25519MLKEM768
		"publicassets.cdn-apple.com", // TLS 1.3 with X25519
		"www.google.com",             // TLS 1.3 with X25519
		"www.gstatic.com",            // TLS 1.3 with X25519
		"www.cloudflare.com",         // TLS 1.3 with X25519MLKEM768 and aggregated handshake packages
		// TLS 1.3 with X25519, but might return two session tickets with different lengths
		"yahoo.com",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) { testCompatibility(t, target) })
	}
}
