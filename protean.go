// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"

	"github.com/ban6cat6/protean/hmqv"
	"github.com/cloudflare/circl/kem"
)

type delegateState struct {
	handshakeMessageCache      map[uint8]*cachedHandshakeMessage
	handshakeDataLens          []int
	sessionTickets13           []*cachedHandshakeMessage
	randomExplicitNonceEnabled bool
}

func newDelegateState() *delegateState {
	return &delegateState{
		handshakeMessageCache: make(map[uint8]*cachedHandshakeMessage),
	}
}

func (s *delegateState) getHandshakeMessage(typ uint8) *cachedHandshakeMessage {
	if msg, ok := s.handshakeMessageCache[typ]; ok {
		return msg
	}
	return nil
}

func (s *delegateState) getSessionTickets13() []*cachedHandshakeMessage {
	return s.sessionTickets13
}

func (s *delegateState) consumeHandshakeDataLen(l int) bool {
	lens := s.handshakeDataLens
	if len(lens) > 0 {
		lens[0] -= l
		if lens[0] > 0 {
			return true
		}
		s.handshakeDataLens = lens[1:]
	}
	return false
}

func (s *delegateState) putHandshakeMessage(typ uint8, msg handshakeMessage, raw []byte) {
	cachedMsg := &cachedHandshakeMessage{
		raw:   raw,
		inner: msg,
	}
	if typ == typeNewSessionTicket {
		if _, ok := msg.(*newSessionTicketMsgTLS13); ok {
			s.sessionTickets13 = append(s.sessionTickets13, cachedMsg)
			return
		}
	}
	s.handshakeMessageCache[typ] = cachedMsg
}

func (s *delegateState) putHandshakeDataLen(l int) {
	s.handshakeDataLens = append(s.handshakeDataLens, l)
}

func (s *delegateState) checkExplicitNonce(record []byte, explicitNonceLen int, seq [8]byte) {
	if s.randomExplicitNonceEnabled {
		return
	}
	if len(record) < recordHeaderLen+explicitNonceLen {
		return
	}

	nonce := record[recordHeaderLen : recordHeaderLen+explicitNonceLen]
	if !s.randomExplicitNonceEnabled && subtle.ConstantTimeCompare(nonce, seq[:]) == 0 {
		s.randomExplicitNonceEnabled = true
	}
}

type cachedHandshakeMessage struct {
	raw   []byte
	inner handshakeMessage
}

func (c *cachedHandshakeMessage) get() handshakeMessage {
	return c.inner
}

func (c *cachedHandshakeMessage) unmarshal(data []byte) bool {
	panic("unreachable")
}

func (c *cachedHandshakeMessage) marshal() (x []byte, err error) {
	if c.raw != nil {
		return c.raw, nil
	}
	return c.inner.marshal()
}

type PConn struct {
	*Conn

	// Client
	uconn *UConn
	// Server
	upstream    net.Conn
	upstreamBuf *bytes.Buffer

	cfg *PConfig
	wg  sync.WaitGroup
}

func (p *PConn) Authed() bool {
	return p.pauthed.Load()
}

type PConfig struct {
	// PServer Config
	ServerPrivateKey ed25519.PrivateKey
	ClientPublicKeys PublicKeyStore

	// PClient Config
	ClientPrivateKey ed25519.PrivateKey
	ServerPublicKey  ed25519.PublicKey

	// Common Config
	ServerFp Fingerprint
	ClientFp Fingerprint

	DockingModeEnabled bool

	once sync.Once

	fpBox  *fpBox
	xKemSK kem.PrivateKey
	sk     *hmqv.PrivateKey
	srvPK  *hmqv.PublicKey

	// TLS 1.3 self-signed certificate
	cert []byte
}

func (c *PConfig) init(rand io.Reader, isClient bool) (err error) {
	c.once.Do(func() {
		err = c.doInit(rand, isClient)
	})
	return
}

func (c *PConfig) doInit(rnd io.Reader, isClient bool) (err error) {
	var sk ed25519.PrivateKey
	if !isClient {
		if len(c.ServerPrivateKey) == 0 {
			return errors.New("protean: server private key missing")
		}
		if c.ClientPublicKeys == nil {
			return errors.New("protean: client public keys missing")
		}
		sk = c.ServerPrivateKey

		cert := &x509.Certificate{SerialNumber: big.NewInt(0xdeadbeef)}
		c.cert, err = x509.CreateCertificate(rnd, cert, cert, sk.Public(), sk)
		if err != nil {
			return err
		}
	} else {
		if len(c.ClientPrivateKey) == 0 {
			return errors.New("protean: client private key missing")
		}
		if len(c.ServerPublicKey) == 0 {
			return errors.New("protean: server public key missing")
		}
		c.srvPK, err = hmqv.NewPublicKey(c.ServerPublicKey)
		if err != nil {
			return fmt.Errorf("protean: invalid server public key: %w", err)
		}
		sk = c.ClientPrivateKey
	}

	c.fpBox = newFpBox()
	c.xKemSK, err = c.fpBox.UnmarshalBinaryPrivateKey(
		ed25519SKToX25519(sk),
	)
	if err != nil {
		return err
	}

	c.sk, err = hmqv.NewPrivateKey(sk)
	return
}

type Fingerprint [16]byte

func GetFingerprint(pk ed25519.PublicKey) Fingerprint {
	h := sha256.New()
	h.Write(pk)
	return Fingerprint(h.Sum(nil)[:16])
}

func (f Fingerprint) Bytes() []byte {
	return f[:]
}

type PublicKeyStore interface {
	Get(fp Fingerprint) (ed25519.PublicKey, bool)
	Put(fp Fingerprint, pk ed25519.PublicKey)
}

// delegate the session between the client and upstream
type delegate struct {
	*Conn
	dc *delegateConn
}

func (d *delegate) setTLSVersion(v uint16) {
	d.vers = v
	d.haveVers = true
	d.in.version = v
	d.out.version = v

	d.dc.version = v
}

type delegateConn struct {
	net.Conn
	readBuf *bytes.Buffer
	version uint16
}

func (dc *delegateConn) Read(b []byte) (int, error) {
	n, err := dc.Conn.Read(b)
	// Save the upstream data to the input buffer,
	// replay the buffer to the client while the session could not be established.
	dc.readBuf.Write(b[:n])
	return n, err
}

func (dc *delegateConn) Write(b []byte) (int, error) {
	if dc.version == VersionTLS12 {
		return io.Discard.Write(b)
	}
	return dc.Conn.Write(b)
}

func newDelegate(pconn *PConn, cfg *Config) *delegate {
	conn := &delegateConn{
		Conn:    pconn.upstream,
		readBuf: pconn.upstreamBuf,
	}
	dlgState := newDelegateState()
	d := &delegate{
		Conn: &Conn{
			conn:          conn,
			isClient:      true,
			config:        cfg,
			delegateState: dlgState,
		},
		dc: conn,
	}
	return d
}

type replayConn struct {
	net.Conn
	upstream    net.Conn
	upstreamBuf *bytes.Buffer
}

func (rc *replayConn) Read(b []byte) (int, error) {
	n, err := rc.Conn.Read(b)
	if err != nil {
		return n, err
	}

	if n > 0 {
		_, err = rc.upstream.Write(b[:n])
		if err != nil {
			return n, err
		}
	}

	return n, err
}

func (rc *replayConn) Write(b []byte) (int, error) {
	if rc.upstreamBuf.Len() > 0 {
		rc.upstreamBuf.Next(len(b))
	}
	return rc.Conn.Write(b)
}

func PClient(conn net.Conn, pconfig *PConfig, tlsConfig *Config, clientHelloID ClientHelloID) (*PConn, error) {
	if tlsConfig == nil {
		tlsConfig = defaultConfig()
	}
	tlsConfig = tlsConfig.Clone()
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	}
	err := pconfig.init(tlsConfig.rand(), true)
	if err != nil {
		return nil, err
	}
	uconn := UClient(conn, tlsConfig, clientHelloID)
	pconn := &PConn{
		Conn:  uconn.Conn,
		uconn: uconn,
		cfg:   pconfig,
	}
	pconn.isPClient = true
	pconn.handshakeFn = pconn.clientHandshake
	return pconn, nil
}

func PServer(conn net.Conn, upstream net.Conn, config *PConfig) (*PConn, error) {
	tlsConfig := &Config{}
	tlsConfig.SessionTicketsDisabled = true
	err := config.init(tlsConfig.rand(), false)
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	c := &replayConn{
		Conn:        conn,
		upstream:    upstream,
		upstreamBuf: buf,
	}
	pconn := &PConn{
		Conn:        Server(c, tlsConfig),
		cfg:         config,
		upstream:    upstream,
		upstreamBuf: buf,
	}
	pconn.handshakeFn = pconn.serverHandshake
	return pconn, nil
}

type clientCred struct {
	hmqv         *hmqv.HMQV
	onepass      *hmqv.ReceiverOnePassAgreement
	keyShareKeys *keySharePrivateKeys
	// Export ClientKeyExchange Key
	ckxKDF func(curve ecdh.Curve) (*ecdh.PrivateKey, error)
	// Stream cipher that obfuscates the public key
	pkBox func(pk []byte)
}

type bufConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (bc *bufConn) Read(b []byte) (int, error) {
	if bc.buf.Len() > 0 {
		n, _ := bc.buf.Read(b)
		m, err := bc.Conn.Read(b[n:])
		return n + m, err
	}
	return bc.Conn.Read(b)
}

type closeWriter interface {
	CloseWrite() error
}

func (p *PConn) Read(b []byte) (int, error) {
	bc, ok := p.upstream.(*bufConn)
	// In relay mode, the upstream is a bufConn
	if ok {
		return bc.Read(b)
	}
	return p.Conn.Read(b)
}

type pstream struct {
	*Conn
}

func (p *pstream) Read(b []byte) (int, error) {
	if err := p.Handshake(); err != nil {
		return 0, err
	}

	if len(b) == 0 {
		return 0, nil
	}

	p.pcond.L.Lock()
	defer p.pcond.L.Unlock()

	for p.pinput.Len() == 0 {
		if p.eof {
			return 0, io.EOF
		}
		p.pcond.Wait()
	}

	return p.pinput.Read(b)
}

func (p *pstream) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := p.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if p.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer p.activeCall.Add(-2)

	if err := p.Handshake(); err != nil {
		return 0, err
	}

	p.out.Lock()
	defer p.out.Unlock()

	if err := p.out.err; err != nil {
		return 0, err
	}

	if !p.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if p.closeNotifySent {
		return 0, errShutdown
	}

	// TLS 1.0 is susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && p.vers == VersionTLS10 {
		if _, ok := p.out.cipher.(cipher.BlockMode); ok {
			n, err := p.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, p.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := p.writeRecordLocked(recordTypeApplicationData, b, withPayloadDataPrefix(proteanDataPrefix))
	return n + m, p.out.setErrorLocked(err)
}

func (p *PConn) PStream() (net.Conn, error) {
	if !p.cfg.DockingModeEnabled {
		return nil, errors.New("protean: docking mode is not enabled")
	}
	return &pstream{
		Conn: p.Conn,
	}, nil
}

func (p *PConn) Write(b []byte) (int, error) {
	bc, ok := p.upstream.(*bufConn)
	// In relay mode, the upstream is a bufConn
	if ok {
		return bc.Write(b)
	}
	return p.Conn.Write(b)
}

func (p *PConn) CloseWrite() error {
	bc, ok := p.upstream.(*bufConn)
	// In relay mode, the upstream is a bufConn
	if ok {
		if cw, ok := bc.Conn.(closeWriter); ok {
			return cw.CloseWrite()
		}
		return nil
	}
	return p.Conn.CloseWrite()
}

func (p *PConn) serverHandshake(ctx context.Context) error {
	p.ponce.Do(func() {
		p.pcond = sync.NewCond(&sync.Mutex{})
	})
	err := p.tryServerHandshake(ctx)
	if err != nil {
		if errors.Is(err, ErrAbortHandshake) {
			return err
		}
		fmt.Printf("protean: server handshake failed, entering relay mode, cause: %v\n", err)
		p.upstream = &bufConn{p.upstream, p.upstreamBuf}
		p.isHandshakeComplete.Store(true)
	} else {
		p.pauthed.Store(true)
	}

	if p.cfg.DockingModeEnabled {
		// Recover the delegate connection
		if dc, ok := p.delegateConn.conn.(*delegateConn); ok {
			p.delegateConn.conn = dc.Conn
		}
		p.docking()
	}

	return nil
}
