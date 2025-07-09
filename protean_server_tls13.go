// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ban6cat6/protean/internal/tls13"

	"golang.org/x/net/http2"
)

type delegateClientHandshakeState13 struct {
	*clientHandshakeStateTLS13
}

func (dhs *delegateClientHandshakeState13) readSessionTickets() error {
	c := dhs.c

	// Send some data to the upstream server to drain the post-handshake messages.
	if c.clientProtocol == "h2" {
		_, err := io.WriteString(c, http2.ClientPreface)
		if err != nil {
			return err
		}
		framer := http2.NewFramer(c, c)
		err = framer.WriteSettings()
		if err != nil {
			return err
		}
	} else {
		// If the upstream did not agree on a protocol, use HTTP/1.1
		req, err := http.NewRequest(http.MethodHead, "https://"+c.conn.RemoteAddr().String(), nil)
		if err != nil {
			return err
		}
		err = req.Write(c)
		if err != nil {
			return err
		}
	}

	for c.input.Len() == 0 {
		err := c.readRecord()
		if err != nil {
			return err
		}
		for c.hand.Len() > 0 {
			err := c.handlePostHandshakeMessage()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type pServerHandshakeState13 struct {
	*serverHandshakeStateTLS13
	dchs                *delegateClientHandshakeState13
	clientCred          *clientCred
	cfg                 *PConfig
	hand                bytes.Buffer
	handshakePaddingLen int
}

func (hs *pServerHandshakeState13) handshake() (err error) {
	c := hs.c
	dc := hs.dchs.c
	abortWhenError := false
	defer func() {
		if err != nil && abortWhenError {
			c.sendAlert(alertInternalError)
			err = fmt.Errorf("%w, cause: %w", ErrAbortHandshake, err)
		}
	}()

	c.buffering = true
	if err := hs.processHellos(); err != nil {
		return err
	}

	// The upstream TLS state machine will be changed by the delegate client because of sending an "honest" ClientFinished.
	// The TLS session between the client and the server will be not consistent with the one between the server and upstream.
	// We might abort the handshake with the client if anything goes wrong.
	abortWhenError = true
	if err := hs.dchs.handshake(); err != nil {
		return err
	}

	// Probe the upstream server for post-handshake messages.
	if err := hs.dchs.readSessionTickets(); err != nil {
		return err
	}

	// Check if the upstream server requested a client certificate.
	// The client authentication is accomplished by verifying the ClientKeyExchange message.
	// Verifying the client certificate is unnecessary.
	if certReq := dc.delegateState.getHandshakeMessage(typeCertificateRequest); certReq != nil {
		return errors.New("protean: upstream server requested client certificate")
	}

	// Recover the underlying connection.
	rc := c.conn.(*replayConn)
	c.conn = rc.Conn

	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	if err := hs.readClientFinished(); err != nil {
		return err
	}

	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *pServerHandshakeState13) processHellos() error {
	c := hs.c
	if bytes.Equal(hs.hello.random, helloRetryRequestRandom) {
		return errors.New("protean: HRR not supported")
	}

	if hs.hello.selectedIdentityPresent {
		return errors.New("protean: session resumption not supported")
	}

	selectedGroup := hs.hello.serverShare.group
	ecdhData := hs.hello.serverShare.data
	switch selectedGroup {
	case X25519MLKEM768:
		if len(ecdhData) != mlkem.CiphertextSize768+x25519PublicKeySize {
			return errors.New("protean: invalid upstream X25519MLKEM768 server share")
		}
	case X25519:
		if len(ecdhData) != x25519PublicKeySize {
			return errors.New("protean: invalid upstream X25519 server share")
		}
	default:
		return fmt.Errorf("protean: unsupported keyshare group %s", selectedGroup)
	}

	serverHelloData := hs.hello.originalBytes()
	hs.hello = new(serverHelloMsg)
	if !hs.hello.unmarshal(append([]byte{}, serverHelloData...)) {
		return errors.New("protean: failed to unmarshal upstream server hello")
	}
	ecdhData = hs.hello.serverShare.data
	twopass, err := hs.clientCred.hmqv.ReceiverTwoPassAgree(c.config.rand(), hs.cfg.sk, hs.clientCred.onepass)
	if err != nil {
		return err
	}

	sigma := twopass.Sigma.Bytes()
	epk := twopass.Epk.Bytes()

	copy(hs.hello.random[:], epk)
	// Obfuscate the ephemeral public key X.
	hs.clientCred.pkBox(hs.hello.random)
	psecret := NewPSecret(sha512.New, sigma)
	// Salt = client random || server random
	salt := append([]byte{}, hs.clientHello.random...)
	salt = append(salt, hs.hello.random...)
	// Rewrite the server X25519 key share as the key confirmation.
	keyShareSeed := psecret.KeyShareSeed(X25519, salt, x25519PublicKeySize)
	sk, err := ecdh.X25519().NewPrivateKey(keyShareSeed)
	if err != nil {
		return fmt.Errorf("protean: failed to create private key for curve %s: %w", selectedGroup, err)
	}
	copy(ecdhData[len(ecdhData)-x25519PublicKeySize:], sk.PublicKey().Bytes())

	// Check if the cipher suite is supported.
	suite := cipherSuiteTLS13ByID(hs.hello.cipherSuite)
	if suite == nil {
		return errors.New("protean: unsupported upstream cipher suite")
	}
	hs.suite = suite
	hs.transcript = hs.suite.hash.New()
	hs.sharedKey = psecret.HandshakeSecret(salt, 64)
	return nil
}

func (hs *pServerHandshakeState13) sendServerParameters() error {
	c := hs.c
	dc := hs.dchs.c

	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return err
	}

	if _, err := c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, nil)
	}
	hs.handshakeSecret = earlySecret.HandshakeSecret(hs.sharedKey)

	clientSecret := hs.handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)
	serverSecret := hs.handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := dc.delegateState.getHandshakeMessage(typeEncryptedExtensions)
	if encryptedExtensions == nil {
		return errors.New("protean: missing encrypted extensions message from upstream")
	}
	c.clientProtocol = encryptedExtensions.inner.(*encryptedExtensionsMsg).alpnProtocol
	if _, err := c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}
	return nil
}

func (hs *pServerHandshakeState13) sendSessionTickets() error {
	c := hs.c
	dc := hs.dchs.c

	sessionTickets := dc.delegateState.getSessionTickets13()
	for _, ticket := range sessionTickets {
		if _, err := c.writeHandshakeRecord(ticket, nil); err != nil {
			return err
		}
	}
	return nil
}

func (hs *pServerHandshakeState13) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c := hs.c
	dc := hs.dchs.c

	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	consumeLen := len(data)
	// Only Certificate and CertificateVerify should be padded.
	if typ := data[0]; typ == typeCertificate || typ == typeCertificateVerify {
		uMsg := dc.delegateState.getHandshakeMessage(typ)
		if uMsg == nil && typ == typeCertificate {
			uMsg = dc.delegateState.getHandshakeMessage(utlsTypeCompressedCertificate)
		}
		if uMsg == nil {
			return 0, fmt.Errorf("protean: missing upstream handshake message for type %d", data[0])
		}
		uMsgLen := len(uMsg.raw)
		padding := uMsgLen - len(data)
		if padding < 0 {
			return 0, fmt.Errorf("protean: upstream handshake message type %d has invalid length %d, expected at least %d", data[0], uMsgLen, len(data))
		}
		hs.handshakePaddingLen += padding
		consumeLen = uMsgLen
	}

	if !dc.delegateState.consumeHandshakeDataLen(consumeLen) {
		hs.hand.Write(data)
		data = hs.hand.Next(hs.hand.Len())
		n, err := c.writeRecordLocked(recordTypeHandshake, data, hs.handshakePaddingLen)
		hs.handshakePaddingLen = 0
		return n, err
	}

	return hs.hand.Write(data)
}
