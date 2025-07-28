// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp/fasthttputil"
)

type clientPublicKeyStore struct {
	sync.Map
}

func (c *clientPublicKeyStore) Get(fp Fingerprint) (ed25519.PublicKey, bool) {
	v, ok := c.Load(fp)
	if !ok {
		return nil, false
	}
	return v.(ed25519.PublicKey), true
}

func (c *clientPublicKeyStore) Put(fp Fingerprint, pk ed25519.PublicKey) {
	c.Store(fp, pk)
}

func generateTestCertTemplate(isCA bool) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-12 * time.Hour)
	notAfter := time.Now().Add(12 * time.Hour)
	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}, nil
}

type testUpstreamServer struct {
	t         *testing.T
	tlsConfig *Config
	rootCA    *x509.CertPool
}

func newTestUpstreamServer(
	t *testing.T,
	serverName string,
	curvePrefs []CurveID,
	ticketsDisabled bool,
	version uint16,
) (*testUpstreamServer, error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	caCert, err := generateTestCertTemplate(true)
	if err != nil {
		return nil, err
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, caPriv.Public(), caPriv)
	if err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, err := generateTestCertTemplate(false)
	if err != nil {
		return nil, err
	}

	cert.DNSNames = []string{serverName}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, priv.Public(), caPriv)
	if err != nil {
		return nil, err
	}

	certs := []Certificate{{Certificate: [][]byte{certBytes}, PrivateKey: priv}}
	tlsConfig := &Config{
		ServerName:             serverName,
		MaxVersion:             version,
		MinVersion:             version,
		CurvePreferences:       curvePrefs,
		SessionTicketsDisabled: ticketsDisabled,
		NextProtos:             []string{"h2", "http/1.1"},
		CipherSuites:           []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		Certificates:           certs,
	}

	issuer, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	return &testUpstreamServer{
		t:         t,
		tlsConfig: tlsConfig,
		rootCA:    rootCAs,
	}, nil
}

func (s *testUpstreamServer) rootCAs() *x509.CertPool {
	return s.rootCA
}

const upstreamServerResponse = "Hello from the upstream server"

func (s *testUpstreamServer) serveConn(conn net.Conn) error {
	t := s.t
	tlsConn := Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	srv := http2.Server{}
	srv.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(upstreamServerResponse))
			if !assert.NoError(t, err) {
				return
			}
		}),
	})
	return nil
}

func testProteanHandshake(t *testing.T, curvePrefs []CurveID, version uint16) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	testServerName := "example.com"
	// Create a TLS server
	upstreamServer, err := newTestUpstreamServer(t, testServerName, curvePrefs, false, version)
	require.NoError(t, err)

	pc := fasthttputil.NewPipeConns()
	upstreamConn, serverConn := pc.Conn1(), pc.Conn2()
	defer upstreamConn.Close()
	wg.Add(1)
	go func(conn net.Conn) {
		defer wg.Done()
		if !assert.NoError(t, upstreamServer.serveConn(conn)) {
			return
		}
	}(serverConn)

	// Server long term key pair
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	// Client long term key pair
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	fpA := GetFingerprint(pkA)
	fpB := GetFingerprint(pkB)

	testResponse := "Protean server test response"

	pc = fasthttputil.NewPipeConns()
	clientConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsConfig := &Config{
			ServerName:         testServerName,
			ClientSessionCache: NewLRUClientSessionCache(0),
			RootCAs:            upstreamServer.rootCAs(),
		}
		pconfig := &PConfig{
			ClientFp:         fpB,
			ServerFp:         fpA,
			ClientPrivateKey: skB,
			ServerPublicKey:  pkA,
		}
		tr := http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				tlsCfg := tlsConfig.Clone()
				tlsCfg.NextProtos = cfg.NextProtos
				pconn, err := PClient(clientConn, pconfig, tlsCfg, HelloChrome_Auto)
				if err != nil {
					_ = clientConn.Close()
					return nil, err
				}
				if err := pconn.Handshake(); err != nil {
					_ = clientConn.Close()
					return nil, err
				}
				return pconn, nil
			},
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
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
		if !assert.Equal(t, testResponse, string(data)) {
			return
		}
		fmt.Println("Acquired response:", string(data))
	}()

	cpkStore := &clientPublicKeyStore{}
	cpkStore.Put(fpB, pkB)
	pconn, err := PServer(serverConn, upstreamConn, &PConfig{
		ServerPrivateKey: skA,
		ServerFp:         fpA,
		ClientPublicKeys: cpkStore,
	})
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	srv := http2.Server{}
	srv.ServeConn(pconn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !assert.Equal(t, testServerName, request.Host) {
				return
			}
			if !assert.Equal(t, http.MethodGet, request.Method) {
				return
			}
			if !assert.Equal(t, "/", request.URL.Path) {
				return
			}
			fmt.Println("Received request:", request.Method, request.URL)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(testResponse))
			if !assert.NoError(t, err) {
				return
			}
		}),
	})
}

func TestProteanHandshake(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testProteanHandshake(t, nil, tls.VersionTLS12) })
	t.Run("TLSv13_PQ", func(t *testing.T) { testProteanHandshake(t, []CurveID{X25519MLKEM768, X25519}, tls.VersionTLS13) })
	t.Run("TLSv13", func(t *testing.T) { testProteanHandshake(t, []CurveID{X25519}, tls.VersionTLS13) })
}

func testActiveProbe(t *testing.T, version uint16) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	testServerName := "example.com"
	// Create a TLS server
	upstreamServer, err := newTestUpstreamServer(t, testServerName, nil, false, version)
	require.NoError(t, err)

	pc := fasthttputil.NewPipeConns()
	upstreamConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func(conn net.Conn) {
		defer wg.Done()
		if !assert.NoError(t, upstreamServer.serveConn(conn)) {
			return
		}
	}(serverConn)

	pc = fasthttputil.NewPipeConns()
	clientConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return UClient(clientConn, &Config{
					ServerName: testServerName,
					RootCAs:    upstreamServer.rootCAs(),
					NextProtos: []string{"h2", "http/1.1"},
				}, HelloChrome_Auto), nil
			},
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
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
		if !assert.Equal(t, upstreamServerResponse, string(data)) {
			return
		}
		fmt.Println("Acquired response:", string(data))
	}()

	// Server long term key pair
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	fpA := GetFingerprint(pkA)
	pconn, err := PServer(serverConn, upstreamConn, &PConfig{
		ServerPrivateKey: skA,
		ServerFp:         fpA,
		ClientPublicKeys: &clientPublicKeyStore{},
	})
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	require.False(t, pconn.Authed())

	wg.Add(2)
	go func(conn net.Conn) {
		defer wg.Done()
		io.Copy(conn, serverConn)
		if c, ok := conn.(closeWriter); ok {
			_ = c.CloseWrite()
		}
	}(pconn)

	go func() {
		defer wg.Done()
		io.Copy(serverConn, pconn)
		if c, ok := serverConn.(closeWriter); ok {
			_ = c.CloseWrite()
		}
	}()
}

func TestActiveProbe(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testActiveProbe(t, tls.VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testActiveProbe(t, tls.VersionTLS13) })
}

func testUnauthedProteanServer(t *testing.T, version uint16) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	testServerName := "example.com"
	// Create a TLS server
	upstreamServer, err := newTestUpstreamServer(t, testServerName, nil, false, version)
	require.NoError(t, err)

	pc := fasthttputil.NewPipeConns()
	clientConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func(conn net.Conn) {
		defer wg.Done()
		if !assert.NoError(t, upstreamServer.serveConn(conn)) {
			return
		}
	}(serverConn)

	// Server long term key pair
	pkA, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	// Client long term key pair
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	fpA := GetFingerprint(pkA)
	fpB := GetFingerprint(pkB)

	pconfig := &PConfig{
		ClientFp:         fpB,
		ServerFp:         fpA,
		ClientPrivateKey: skB,
		ServerPublicKey:  pkA,
	}

	pconn, err := PClient(clientConn, pconfig, &Config{
		ServerName: testServerName,
		RootCAs:    upstreamServer.rootCAs(),
		NextProtos: []string{"h2", "http/1.1"},
	}, HelloChrome_Auto)
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	require.False(t, pconn.Authed())
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return pconn, nil
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
	require.Nil(t, err)
	resp, err := tr.RoundTrip(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, upstreamServerResponse, string(data))
}

func TestUnauthedProteanServer(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testUnauthedProteanServer(t, tls.VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testUnauthedProteanServer(t, tls.VersionTLS13) })
}

func TestUnqualifiedUpstreamServer12(t *testing.T) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	testServerName := "example.com"
	// Create a TLS server
	upstreamServer, err := newTestUpstreamServer(t, testServerName, nil, true, VersionTLS12)
	require.NoError(t, err)

	pc := fasthttputil.NewPipeConns()
	upstreamConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func(conn net.Conn) {
		defer wg.Done()
		if !assert.NoError(t, upstreamServer.serveConn(conn)) {
			return
		}
	}(serverConn)

	// Server long term key pair
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	// Client long term key pair
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	fpA := GetFingerprint(pkA)
	fpB := GetFingerprint(pkB)

	pc = fasthttputil.NewPipeConns()
	clientConn, serverConn := pc.Conn1(), pc.Conn2()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsConfig := &Config{
			ServerName:         testServerName,
			ClientSessionCache: NewLRUClientSessionCache(0),
			RootCAs:            upstreamServer.rootCAs(),
		}
		pconfig := &PConfig{
			ClientFp:         fpB,
			ServerFp:         fpA,
			ClientPrivateKey: skB,
			ServerPublicKey:  pkA,
		}
		pconn, err := PClient(clientConn, pconfig, tlsConfig, HelloChrome_Auto)
		if !assert.Nil(t, err) {
			return
		}
		err = pconn.Handshake()
		if !assert.Nil(t, err) {
			return
		}
		if !assert.False(t, pconn.Authed()) {
			return
		}
		tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return pconn, nil
			},
		}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
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
		if !assert.Equal(t, upstreamServerResponse, string(data)) {
			return
		}
	}()

	cpkStore := &clientPublicKeyStore{}
	cpkStore.Put(fpB, pkB)
	pconn, err := PServer(serverConn, upstreamConn, &PConfig{
		ServerPrivateKey: skA,
		ServerFp:         fpA,
		ClientPublicKeys: cpkStore,
	})
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	require.False(t, pconn.Authed())

	wg.Add(2)
	go func(conn net.Conn) {
		defer wg.Done()
		io.Copy(conn, serverConn)
		if c, ok := conn.(closeWriter); ok {
			_ = c.CloseWrite()
		}
	}(pconn)

	go func() {
		defer wg.Done()
		io.Copy(serverConn, pconn)
		if c, ok := serverConn.(closeWriter); ok {
			_ = c.CloseWrite()
		}
	}()
}

func TestCachedHandshakeMessage(t *testing.T) {
	hexStr := "02000076030371073de22dcba1cc65cd1d817a6abe3491895b45eee28f383f4d34f89281c01820e0f5fb16acf08e8c1c097eb28dc4ef834c2924e42ed559f5eb0a174123d58def130200002e00330024001d002054bfdc6acc6db5a269918ca165a9795778b0e398be76396c0431f3e3c373dd77002b00020304"
	data, err := hex.DecodeString(hexStr)
	require.Nil(t, err)
	sh := &serverHelloMsg{}
	ok := sh.unmarshal(data)
	require.True(t, ok)
	cachedSH := &cachedHandshakeMessage{
		raw:   data,
		inner: sh,
	}
	out, err := cachedSH.marshal()
	require.Nil(t, err)
	require.Equal(t, &data, &out)
}

func testDocking(t *testing.T, version uint16) {
	wg := &sync.WaitGroup{}
	defer wg.Wait()

	testServerName := "example.com"
	// Create a TLS server
	upstreamServer, err := newTestUpstreamServer(t, testServerName, nil, false, version)
	require.NoError(t, err)

	pc := fasthttputil.NewPipeConns()
	upstreamConn, serverConn := pc.Conn1(), pc.Conn2()
	defer upstreamConn.Close()
	wg.Add(1)
	go func(conn net.Conn) {
		defer wg.Done()
		if !assert.NoError(t, upstreamServer.serveConn(conn)) {
			return
		}
	}(serverConn)

	// Server long term key pair
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	// Client long term key pair
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	fpA := GetFingerprint(pkA)
	fpB := GetFingerprint(pkB)

	testResponse := "Protean server test response"

	pc = fasthttputil.NewPipeConns()
	clientConn, serverConn := pc.Conn1(), pc.Conn2()
	// Uncomment the following lines to test with a real TCP listener
	// l, err := net.Listen("tcp", "127.0.0.1:10443")
	// require.Nil(t, err)
	// clientConn, err := net.Dial("tcp", "127.0.0.1:10443")
	// require.Nil(t, err)
	// serverConn, err = l.Accept()
	require.Nil(t, err)
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsConfig := &Config{
			ServerName:         testServerName,
			RootCAs:            upstreamServer.rootCAs(),
			ClientSessionCache: NewLRUClientSessionCache(0),
		}
		pconfig := &PConfig{
			ClientFp:           fpB,
			ServerFp:           fpA,
			ClientPrivateKey:   skB,
			ServerPublicKey:    pkA,
			DockingModeEnabled: true,
		}
		pconn, err := PClient(clientConn, pconfig, tlsConfig, HelloChrome_Auto)
		if !assert.Nil(t, err) {
			return
		}
		if !assert.Nil(t, pconn.Handshake()) {
			clientConn.Close()
			return
		}
		tr := http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return pconn, nil
			},
		}
		defer tr.CloseIdleConnections()
		// Test traffic between client and upstream
		req, err := http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
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
		if !assert.Equal(t, upstreamServerResponse, string(data)) {
			return
		}

		// Test protean stream between client and server
		pstream, err := pconn.PStream()
		if !assert.Nil(t, err) {
			return
		}
		trp := http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return pstream, nil
			},
		}
		req, err = http.NewRequest(http.MethodGet, "https://"+testServerName, nil)
		if !assert.Nil(t, err) {
			return
		}
		resp, err = trp.RoundTrip(req)
		if !assert.Nil(t, err) {
			return
		}
		defer resp.Body.Close()
		data, err = io.ReadAll(resp.Body)
		if !assert.Nil(t, err) {
			return
		}
		if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
			return
		}
		if !assert.Equal(t, testResponse, string(data)) {
			return
		}
	}()

	cpkStore := &clientPublicKeyStore{}
	cpkStore.Put(fpB, pkB)
	pconn, err := PServer(serverConn, upstreamConn, &PConfig{
		ServerPrivateKey:   skA,
		ServerFp:           fpA,
		ClientPublicKeys:   cpkStore,
		DockingModeEnabled: true,
	})
	require.Nil(t, err)
	err = pconn.Handshake()
	require.Nil(t, err)
	pstream, err := pconn.PStream()
	require.Nil(t, err)
	srv := http2.Server{}
	srv.ServeConn(pstream, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if !assert.Equal(t, testServerName, request.Host) {
				return
			}
			if !assert.Equal(t, http.MethodGet, request.Method) {
				return
			}
			if !assert.Equal(t, "/", request.URL.Path) {
				return
			}
			fmt.Println("Received request:", request.Method, request.URL)
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(testResponse))
			if !assert.NoError(t, err) {
				return
			}
		}),
	})
	require.Nil(t, pconn.Wait())
}

func TestDockingMode(t *testing.T) {
	t.Run("TLSv12", func(t *testing.T) { testDocking(t, VersionTLS12) })
	t.Run("TLSv13", func(t *testing.T) { testDocking(t, VersionTLS13) })
}
