// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/ban6cat6/protean/hmqv"
	"github.com/cloudflare/circl/dh/x25519"
)

var (
	proteanDataPrefix, _ = hex.DecodeString("ee59bc4ffd6db6c1c97974454f3f4e5d") // md5sum("protean data")
)

var (
	errAbortHandshake = errors.New("protean: abort handshake")
	errInvalidWrite   = errors.New("protean: invalid write result")
)

type delegateClientHandshakeState struct {
	*clientHandshakeState
}
type pServerHandshakeState struct {
	*serverHandshakeState
	dchs       *delegateClientHandshakeState
	clientCred *clientCred
	cfg        *PConfig
}

func (hs *delegateClientHandshakeState) handshake() error {
	c := hs.c

	_, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()

	if err := transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err := transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	if err := hs.doFullHandshake(); err != nil {
		return err
	}

	if err := hs.establishKeys(); err != nil {
		return err
	}

	if err := hs.sendFinished(c.clientFinished[:]); err != nil {
		return err
	}

	return nil
}

func (hs *pServerHandshakeState) handshake() (err error) {
	c := hs.c
	dc := hs.dchs.c
	abortWhenError := false
	defer func() {
		if err != nil && abortWhenError {
			c.sendAlert(alertInternalError)
			err = fmt.Errorf("%w, cause: %w", errAbortHandshake, err)
		}
	}()

	if !hs.clientHello.ticketSupported {
		return errors.New("protean: client doesn't request a session tickets")
	}
	if !hs.hello.ticketSupported {
		return errors.New("protean: upstream server doesn't support session tickets")
	}

	// Check if the cipher suite is supported.
	suite := cipherSuiteByID(hs.hello.cipherSuite)
	if suite == nil {
		return errors.New("protean: unsupported upstream cipher suite")
	}
	hs.suite = suite

	if err := hs.dchs.handshake(); err != nil {
		return err
	}

	// Check if the upstream server requested a client certificate.
	// The client authentication is accomplished by verifying the ClientKeyExchange message.
	// Verifying the client certificate is unnecessary.
	if certReq := dc.delegateState.getHandshakeMessage(typeCertificateRequest); certReq != nil {
		return errors.New("protean: upstream server requested client certificate")
	}

	c.buffering = true

	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}

	// Continue the delegate handshake. acquire the session tickets
	if err := hs.readFinished(c.clientFinished[:]); err != nil {
		return err
	}

	if err := hs.dchs.readSessionTicket(); err != nil {
		return err
	}
	if err := hs.dchs.readFinished(dc.serverFinished[:]); err != nil {
		return err
	}
	dc.isHandshakeComplete.Store(true)

	if dc.delegateState.randomExplicitNonceEnabled {
		if err := c.out.initExplicitNonce(c.config.rand()); err != nil {
			return err
		}
	}

	c.clientFinishedIsFirst = true
	c.buffering = true

	sessionTicket := dc.delegateState.getHandshakeMessage(typeNewSessionTicket)
	data := sessionTicket.get().(*newSessionTicketMsg).ticket
	if len(data) < 64 {
		return errors.New("protean: upstream session ticket too short, expected at least 64 bytes")
	}

	twopass, err := hs.clientCred.hmqv.ReceiverTwoPassAgree(rand.Reader, hs.cfg.sk, hs.clientCred.onepass)
	if err != nil {
		return err
	}
	epk := twopass.Epk.Bytes()
	sigma := twopass.Sigma.Bytes()
	psecret := NewPSecret(sha512.New, sigma)

	salt := append([]byte{}, epk...)
	salt = append(salt, c.clientFinished[:]...)
	finishedKey := psecret.TicketFinishedKey(salt, 32)
	fh := hmac.New(sha256.New, finishedKey)
	ll := len(data)
	fh.Write(c.clientFinished[:])
	fh.Write(data[:ll-64])
	salt = fh.Sum(data[ll-32:][:0])
	hs.clientCred.pkBox(epk)
	copy(data[ll-64:ll-32], epk)

	if _, err := c.writeHandshakeRecord(sessionTicket, &hs.finishedHash); err != nil {
		return err
	}

	if err := hs.sendFinished(c.serverFinished[:]); err != nil {
		return err
	}

	// If any error is encountered after the c.flush, there is no way to resume the handshake process
	// between the client and the upstream. In this case, we should abort the handshake if error occurs.
	abortWhenError = true
	if _, err := c.flush(); err != nil {
		return err
	}

	// Apply the traffic key
	sharedKey := psecret.TrafficSecret(salt, masterSecretLength)
	hs.masterSecret = sharedKey
	if err := hs.establishTrafficKeys(); err != nil {
		return err
	}

	c.ekm = ekmFromMasterSecret(
		c.vers,
		hs.suite,
		hs.masterSecret,
		hs.clientHello.random,
		hs.hello.random,
	)

	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *pServerHandshakeState) doFullHandshake() error {
	c := hs.c
	dc := hs.dchs.c

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}

	// NOTE: we should use the cached handshake message from the delegate
	// It preserves every byte from the upstream server, otherwise re-marshaling
	// might break the finishedHash of the client.
	hello := dc.delegateState.getHandshakeMessage(typeServerHello)
	if _, err := hs.c.writeHandshakeRecord(hello, &hs.finishedHash); err != nil {
		return err
	}

	certMsg := dc.delegateState.getHandshakeMessage(typeCertificate)
	if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
		return err
	}

	certStatus := dc.delegateState.getHandshakeMessage(typeCertificateStatus)
	if certStatus != nil {
		if _, err := hs.c.writeHandshakeRecord(certStatus, &hs.finishedHash); err != nil {
			return err
		}
	}

	skxMsg := dc.delegateState.getHandshakeMessage(typeServerKeyExchange)
	if skxMsg == nil {
		return errors.New("protean: missing upstream message ServerKeyExchange")
	}
	if _, err := hs.c.writeHandshakeRecord(skxMsg, &hs.finishedHash); err != nil {
		return err
	}

	helloDone := dc.delegateState.getHandshakeMessage(typeServerHelloDone)
	if helloDone == nil {
		return errors.New("protean: missing upstream message ServerHelloDone")
	}
	if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}

	_, ok = hs.suite.ka(c.vers).(*ecdheKeyAgreement)
	if !ok {
		return errors.New("protean: unsupported key agreement")
	}
	skx := skxMsg.get().(*serverKeyExchangeMsg)
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return errors.New("protean: upstream unsupported curve")
	}

	csk, err := hs.clientCred.ckxKDF(curve)
	if err != nil {
		return err
	}

	// Check the client key confirmation.
	if !bytes.Equal(csk.PublicKey().Bytes(), ckx.ciphertext[1:]) {
		return errors.New("protean: client unauthenticated")
	}

	publicLen := int(skx.key[3])
	serverECDHEParams := skx.key[:4+publicLen]
	spk, err := curve.NewPublicKey(serverECDHEParams[4:])
	if err != nil {
		return errors.New("protean: invalid upstream server public key")
	}

	preMasterSecret, err := csk.ECDH(spk)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("protean: ECDH error")
	}

	if hs.hello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.clientHello.random, hs.hello.random)
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *pServerHandshakeState) establishTrafficKeys() error {
	c := hs.c
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := c.out.changeCipherSpec(); err != nil {
		return err
	}
	if err := c.in.changeCipherSpec(); err != nil {
		return err
	}
	// Have sent ServerFinished
	c.out.incSeq()
	// Have read ClientFinished
	c.in.incSeq()
	return nil
}

func (p *PConn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
	// clientHelloMsg is included in the transcript, but we haven't initialized
	// it yet. The respective handshake functions will record it themselves.
	msg, err := p.readHandshake(nil)
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		return nil, unexpectedMessageError(clientHello, msg)
	}

	if clientHello.earlyData {
		return nil, errors.New("protean: early data not supported")
	}

	return clientHello, nil
}

func (p *PConn) clientAuth(clientHello *clientHelloMsg) (cred *clientCred, err error) {
	var (
		xpk           *ecdh.PublicKey
		mlkemEncapKey *mlkem.EncapsulationKey768
		mlkemXPK      *ecdh.PublicKey
	)

	for _, ks := range clientHello.keyShares {
		if ks.group == X25519 {
			xpk, err = ecdh.X25519().NewPublicKey(ks.data)
			if err != nil {
				return
			}
		}
		if ks.group == X25519MLKEM768 {
			if len(ks.data) != mlkem.EncapsulationKeySize768+x25519PublicKeySize {
				return nil, errors.New("protean: invalid mlkem encapsulation key size")
			}
			mlkemEncapKey, err = mlkem.NewEncapsulationKey768(ks.data[:mlkem.EncapsulationKeySize768])
			if err != nil {
				return
			}
			mlkemXPK, err = ecdh.X25519().NewPublicKey(ks.data[mlkem.EncapsulationKeySize768:])
			if err != nil {
				return
			}
		}
	}

	if xpk == nil {
		return nil, errors.New("protean: no X25519 key share found")
	}

	aad := aadFromClientHello(clientHello)
	aad = append(aad, p.cfg.ServerFp.Bytes()...)
	aad = append(aad, p.cfg.ServerPrivateKey.Public().(ed25519.PublicKey)...)

	box := p.cfg.fpBox
	recv, err := box.NewReceiver(p.cfg.xKemSK, aad)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(xpk.Bytes())
	if err != nil {
		return nil, err
	}
	clientFp, err := opener.Open(clientHello.sessionId, aad)
	if err != nil {
		return nil, err
	}

	//// ClientRandom: OBFS(Y)
	//// SessionID: Enc(K0, idB)
	aad = append(aad, clientHello.sessionId...)
	epk := make([]byte, x25519.Size)
	copy(epk, clientHello.random)
	pkBox := func(pk []byte) {
		box.encodePublicKey(opener, pk, aad)
	}
	pkBox(epk)

	clientPK, ok := p.cfg.ClientPublicKeys.Get(Fingerprint(clientFp))
	if !ok {
		return nil, fmt.Errorf("protean: unknown client id %s", string(clientFp))
	}

	cpk, err := hmqv.NewPublicKey(clientPK)
	if err != nil {
		return
	}

	Y, err := hmqv.NewPublicKey(epk)
	if err != nil {
		return
	}

	mqv := hmqv.New(clientFp, p.cfg.ServerFp.Bytes())
	onepass, err := mqv.ReceiverOnePassAgree(Y, p.cfg.sk, cpk)
	if err != nil {
		return
	}
	sigma := onepass.Sigma.Bytes()
	psecret := NewPSecret(sha512.New, sigma)

	_, xKemSK := box.DeriveKeyPair(sigma)
	xsk := xKemSKToX25519(xKemSK)

	if subtle.ConstantTimeCompare(xsk.PublicKey().Bytes(), xpk.Bytes()) == 0 {
		return nil, errors.New("protean: client unauthenticated, x25519 key share not match")
	}

	var (
		mlkemDecapKey *mlkem.DecapsulationKey768
		mlkemXSK      = xsk
	)
	if mlkemEncapKey != nil {
		mlkemSeed := psecret.KeyShareSeed(X25519MLKEM768, Y.Bytes(), mlkem.SeedSize)
		mlkemDecapKey, err = mlkem.NewDecapsulationKey768(mlkemSeed)
		if err != nil {
			return
		}

		if subtle.ConstantTimeCompare(mlkemEncapKey.Bytes(), mlkemDecapKey.EncapsulationKey().Bytes()) == 0 {
			return nil, errors.New("protean: client unauthenticated, mlkem key share not match")
		}

		// If the client generate an independent X25519 key share for mlkem.
		if !mlkemXPK.Equal(xpk) {
			mlkemXSKSeed := psecret.KeyShareSeed(X25519, Y.Bytes(), x25519.Size)
			mlkemXSK, err = ecdh.X25519().NewPrivateKey(mlkemXSKSeed)
			if err != nil {
				return
			}
			if subtle.ConstantTimeCompare(mlkemXPK.Bytes(), mlkemXSK.PublicKey().Bytes()) == 0 {
				return nil, errors.New("protean: client unauthenticated, mlkem x25519 key share not match")
			}
		}
	}

	cred = &clientCred{
		keyShareKeys: &keySharePrivateKeys{
			ecdhe:      xsk,
			mlkem:      mlkemDecapKey,
			mlkemEcdhe: mlkemXSK,
		},
		ckxKDF: func(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
			return psecret.ClientKeyExchangePrivateKey(curve, Y.Bytes())
		},
		hmqv:    mqv,
		onepass: onepass,
		pkBox:   pkBox,
	}

	return
}

func (p *PConn) tryServerHandshake(ctx context.Context) (err error) {
	// After the handshake process, we need to restore the original connection
	defer func() {
		rc, ok := p.conn.(*replayConn)
		if ok {
			p.conn = rc.Conn
		}
	}()

	clientHello, err := p.readClientHello(ctx)
	if err != nil {
		return err
	}

	cred, err := p.clientAuth(clientHello)
	if err != nil {
		return err
	}

	dlgCfg := &Config{}
	dlgCfg.InsecureSkipVerify = true
	dlgCfg.generateClientKeyExchange = cred.ckxKDF
	dlg := newDelegate(p, dlgCfg)
	p.delegateConn = dlg.Conn

	// Read the server hello from the upstream server
	msg, err := dlg.readHandshake(nil)
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		return unexpectedMessageError(serverHello, msg)
	}

	// Check if the upstream server hello is supported.
	// Check if the TLS version is supported.
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}
	p.vers, ok = p.config.mutualVersion(roleServer, []uint16{peerVersion})
	if !ok {
		return errors.New("protean: unsupported upstream protocol version")
	}

	p.cipherSuite = serverHello.cipherSuite

	// inherit the cipher suite and tls version from the upstream server
	p.haveVers = true
	p.in.version = p.vers
	p.out.version = p.vers

	dlg.setTLSVersion(p.vers)

	if p.vers == VersionTLS13 {
		chs := &clientHandshakeStateTLS13{
			c:            dlg.Conn,
			ctx:          ctx,
			serverHello:  serverHello,
			hello:        clientHello,
			keyShareKeys: cred.keyShareKeys,
		}

		uconn := &UConn{Conn: chs.c}
		// If the upstream server supports X25519MLKEM768,
		// and the client generate an "independent" X25519 key share for mlkem,
		// then we consider it as a uTLS connection.
		if serverHello.serverShare.group == X25519MLKEM768 &&
			!cred.keyShareKeys.mlkemEcdhe.Equal(cred.keyShareKeys.ecdhe) {
			uconn.clientHelloBuildStatus = BuildByUtls
		}
		if algos := clientHello.supportedCertCompressionAlgorithms; len(algos) > 0 {
			uconn.Extensions = append(uconn.Extensions, &UtlsCompressCertExtension{
				Algorithms: algos,
			})
		}
		err := uconn.ApplyConfig()
		if err != nil {
			return err
		}
		chs.uconn = uconn

		hs := &pServerHandshakeState13{
			dchs: &delegateClientHandshakeState13{chs},
			serverHandshakeStateTLS13: &serverHandshakeStateTLS13{
				c:           p.Conn,
				ctx:         ctx,
				clientHello: clientHello,
				hello:       serverHello,
				cert: &Certificate{
					Certificate: [][]byte{p.cfg.cert},
					PrivateKey:  p.cfg.ServerPrivateKey,
				},
				sigAlg: Ed25519,
			},
			clientCred: cred,
			cfg:        p.cfg,
		}
		hs.c.pstate13 = hs

		return hs.handshake()
	}

	chs := &clientHandshakeState{
		c:           dlg.Conn,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       clientHello,
	}
	hs := &pServerHandshakeState{
		dchs: &delegateClientHandshakeState{chs},
		serverHandshakeState: &serverHandshakeState{
			c:           p.Conn,
			ctx:         ctx,
			clientHello: clientHello,
			hello:       serverHello,
		},
		clientCred: cred,
		cfg:        p.cfg,
	}

	return hs.handshake()
}

func (p *PConn) docking() {
	c := p.Conn
	dc := p.delegateConn
	p.wg.Add(2)
	// Copy delegate connection to protean connection
	go func() {
		defer p.wg.Done()
		pcopy(c, dc)
		p.CloseWrite()
	}()

	// Copy protean connection to delegate connection
	go func() {
		defer p.wg.Done()
		pcopy(dc, c)
		dc.CloseWrite()
	}()
}

// pcopy copies data from src to dst until EOF is reached on src.
// port from io.copyBuffer
func pcopy(dst *Conn, src *Conn) (written int, err error) {
	buf := make([]byte, 32*1024) // 32KB buffer
	// Only in TLS 1.3 and the src is a delegate connection needs to send session tickets.
	requireTickets := src.vers == VersionTLS13 && src.delegateState != nil && dst.pstate13 != nil
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if requireTickets {
				if err := dst.pstate13.sendSessionTickets(); err != nil {
					return written, err
				}
				requireTickets = false
			}
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += nw
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

func (p *PConn) Wait() error {
	if !p.cfg.DockingModeEnabled {
		return errors.New("protean: docking mode is not enabled")
	}
	p.wg.Wait()
	return nil
}
