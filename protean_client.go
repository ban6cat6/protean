// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"

	"github.com/ban6cat6/protean/hmqv"
	"github.com/cloudflare/circl/dh/x25519"
)

var (
	errServerNotAuthed = errors.New("protean: server not authenticated")
)

func (p *PConn) clientHandshake(ctx context.Context) (err error) {
	var handshakeError bool
	defer func() {
		if !handshakeError && err != nil {
			fmt.Printf("%v, cause: %v\n", errServerNotAuthed, err)
			p.isHandshakeComplete.Store(true)
			err = nil
		}
	}()

	uconn := p.uconn
	A := p.cfg.srvPK
	b := p.cfg.sk
	clientFp := p.cfg.ClientFp.Bytes()
	serverFp := p.cfg.ServerFp.Bytes()

	if err := uconn.BuildHandshakeState(); err != nil {
		return err
	}
	if uconn.HandshakeState.State13.KeyShareKeys.Ecdhe.Curve() != ecdh.X25519() {
		return errors.New("protean: unsupported client hello fingerprint: only X25519 is supported")
	}

	// fpA || A
	ch := uconn.HandshakeState.Hello.getPrivatePtr()
	aad := aadFromClientHello(ch)
	aad = append(aad, serverFp...)
	aad = append(aad, A.Bytes()...)

	// HOMQV
	mqv := hmqv.New(clientFp, serverFp)
	onepass, err := mqv.SenderOnePassAgree(p.config.rand(), b, A)
	if err != nil {
		return err
	}
	sigma := onepass.Sigma.Bytes()
	epk := onepass.Epk.Bytes()
	psecret := NewPSecret(sha512.New, sigma)

	// Fingerprint Concealment
	box := p.cfg.fpBox
	xpkA, _ := box.UnmarshalBinaryPublicKey(A.BytesMontgomery())
	sender, _ := box.NewSender(xpkA, aad)
	xpk, sealer, err := sender.Setup(bytes.NewReader(sigma))
	if err != nil {
		return err
	}
	ct, err := sealer.Seal(clientFp, aad)
	if err != nil {
		return err
	}
	aad = append(aad, ct...)
	obfsEPK := make([]byte, len(epk))
	copy(obfsEPK, epk)
	pkBox := func(pk []byte) {
		box.encodePublicKey(sealer, pk, aad)
	}
	pkBox(obfsEPK)

	// TLS 1.2 Verification
	p.config.generateClientKeyExchange = func(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
		return psecret.ClientKeyExchangePrivateKey(curve, epk)
	}

	// TLS 1.3 Verification
	p.config.establishHandshakeKeys = func(hs *clientHandshakeStateTLS13) ([]byte, error) {
		selectedGroup := hs.serverHello.serverShare.group
		ecdhData := hs.serverHello.serverShare.data
		switch selectedGroup {
		case X25519MLKEM768:
			if len(ecdhData) != mlkem.CiphertextSize768+x25519PublicKeySize {
				return nil, errors.New("protean: invalid upstream X25519MLKEM768 server share")
			}
		case X25519:
			if len(ecdhData) != x25519PublicKeySize {
				return nil, errors.New("protean: invalid upstream X25519 server share")
			}
		default:
			return nil, fmt.Errorf("protean: unsupported keyshare group %s", selectedGroup)
		}
		obfsX := append([]byte{}, hs.serverHello.random...)
		// Recover the ephemeral public key X.
		pkBox(obfsX)
		X, err := hmqv.NewPublicKey(obfsX)
		if err != nil {
			return nil, fmt.Errorf("protean: invalid public key in the server hello: %w", err)
		}
		twopass, err := mqv.SenderTwoPassAgree(X, onepass)
		if err != nil {
			return nil, err
		}
		sigma := twopass.Sigma.Bytes()
		psecret := NewPSecret(sha512.New, sigma)
		salt := append([]byte{}, hs.hello.random...)
		salt = append(salt, hs.serverHello.random...)
		keyShareSeed := psecret.KeyShareSeed(X25519, salt, x25519PublicKeySize)
		sk, err := ecdh.X25519().NewPrivateKey(keyShareSeed)
		if err != nil {
			return nil, err
		}
		serverXPK := ecdhData[len(ecdhData)-x25519PublicKeySize:]
		if subtle.ConstantTimeCompare(sk.PublicKey().Bytes(), serverXPK) == 0 {
			return nil, errServerNotAuthed
		}

		sharedKey := psecret.HandshakeSecret(salt, 64)
		p.authed.Store(true)
		return sharedKey, nil
	}

	_, xKemSK := box.DeriveKeyPair(sigma)
	xsk := xKemSKToX25519(xKemSK)

	uconn.HandshakeState.Hello.Random = obfsEPK
	uconn.HandshakeState.Hello.SessionId = ct
	keyShareKeys := uconn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys.mlkem != nil {
		mlkemGenSeed := psecret.KeyShareSeed(X25519MLKEM768, epk, mlkem.SeedSize)
		mlkemKey, err := mlkem.NewDecapsulationKey768(mlkemGenSeed)
		if err != nil {
			return err
		}
		keyShareKeys.mlkem = mlkemKey
		if keyShareKeys.mlkemEcdhe != nil && !keyShareKeys.mlkemEcdhe.Equal(keyShareKeys.Ecdhe) {
			mlkemXGenSeed := psecret.KeyShareSeed(X25519, epk, x25519.Size)
			mlkemXSK, err := ecdh.X25519().NewPrivateKey(mlkemXGenSeed)
			if err != nil {
				return err
			}
			keyShareKeys.mlkemEcdhe = mlkemXSK
		} else {
			keyShareKeys.mlkemEcdhe = xsk
		}
	}
	keyShareKeys.Ecdhe = xsk

	keyShares := uconn.HandshakeState.Hello.KeyShares
	for i := 0; i < len(keyShares); i++ {
		switch group := keyShares[i].Group; group {
		case X25519:
			keyShares[i].Data = xpk
		case X25519MLKEM768:
			keyShares[i].Data = append(keyShareKeys.mlkem.EncapsulationKey().Bytes(), keyShareKeys.mlkemEcdhe.PublicKey().Bytes()...)
		}
	}

	if err := uconn.BuildHandshakeState(); err != nil {
		return err
	}
	if err = uconn.clientHandshake(ctx); err != nil {
		handshakeError = true
		return err
	}

	if uconn.vers == VersionTLS13 {
		uconn.isHandshakeComplete.Store(true)
		return nil
	}

	state, ok := p.config.ClientSessionCache.Get(p.config.ServerName)
	if !ok {
		return errors.New("protean: missing session state in client session cache")
	}
	sessionTicket := state.SessionTicket()
	l := len(sessionTicket)
	obfsEPK = sessionTicket[l-64 : l-32]
	pkBox(obfsEPK)
	X, err := hmqv.NewPublicKey(obfsEPK)
	if err != nil {
		return fmt.Errorf("protean: invalid public key in the session ticket: %w", err)
	}
	twopass, err := mqv.SenderTwoPassAgree(X, onepass)
	if err != nil {
		return err
	}
	sigma = twopass.Sigma.Bytes()
	psecret = NewPSecret(sha512.New, sigma)

	finished := uconn.clientFinished[:]
	salt := append([]byte{}, X.Bytes()...)
	salt = append(salt, finished...)
	finishedKey := psecret.TicketFinishedKey(salt, 32)
	fh := hmac.New(sha256.New, finishedKey)
	fh.Write(finished)
	fh.Write(sessionTicket[:l-64])
	expectedMAC := fh.Sum(nil)
	if subtle.ConstantTimeCompare(expectedMAC, sessionTicket[l-32:]) == 0 {
		return errors.New("protean: session ticket not authenticated")
	}

	// Change Cipher
	sharedKey := psecret.TrafficSecret(expectedMAC, masterSecretLength)
	if err := p.changeClientTrafficSecret(sharedKey); err != nil {
		return err
	}

	p.authed.Store(true)
	uconn.isHandshakeComplete.Store(true)
	return nil
}

func (p *PConn) changeClientTrafficSecret(newSecret []byte) error {
	if !p.isClient {
		return errors.New("tls: changeClientTrafficSecret called on TLS server connection")
	}
	if p.vers == VersionTLS13 {
		return errors.New("tls: changeClientTrafficSecret called on TLS 1.3 client connection")
	}
	suite := cipherSuiteByID(p.cipherSuite)
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(p.vers, suite, newSecret, p.clientRandom, p.serverRandom, suite.macLen, suite.keyLen, suite.ivLen)

	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash

	if suite.aead == nil {
		clientCipher = suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = suite.mac(clientMAC)
		serverCipher = suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = suite.mac(serverMAC)
	} else {
		clientCipher = suite.aead(clientKey, clientIV)
		serverCipher = suite.aead(serverKey, serverIV)
	}

	p.out.prepareCipherSpec(p.vers, clientCipher, clientHash)
	p.in.prepareCipherSpec(p.vers, serverCipher, serverHash)
	if err := p.out.changeCipherSpec(); err != nil {
		return err
	}
	if err := p.in.changeCipherSpec(); err != nil {
		return err
	}
	// Have sent ServerFinished
	p.out.incSeq()
	// Have read ClientFinished
	p.in.incSeq()
	return nil
}
