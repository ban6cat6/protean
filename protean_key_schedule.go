// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	fips140 "hash"
	"io"

	"github.com/ban6cat6/protean/internal/tls13"
)

const (
	pTicketFinishedLabel  = "protean session ticket finished"
	pHandshakeSecretLabel = "protean handshake secret"
	pTrafficSecretLabel   = "protean traffic secret"
)

func mkPKeyShareLabel(curveID CurveID) string {
	return fmt.Sprintf("key share %d seed", curveID)
}

func mkPClientKeyExchangeLabel(curveID CurveID) string {
	return fmt.Sprintf("client key exchange %d", curveID)
}

// Get rid of randutil.MaybeReadByte(r)
type noDiceReader struct {
	io.Reader
}

func (r noDiceReader) Read(b []byte) (int, error) {
	if len(b) < 16 {
		return 0, nil
	}
	return r.Reader.Read(b)
}

type PSecret struct {
	secret []byte
	hash   func() fips140.Hash
}

func NewPSecret[H fips140.Hash](hash func() H, secret []byte) *PSecret {
	return &PSecret{
		secret: secret,
		hash:   func() fips140.Hash { return hash() },
	}
}

func (s *PSecret) KeyShareSeed(curve CurveID, context []byte, length int) []byte {
	return tls13.ExpandLabel(s.hash, s.secret, mkPKeyShareLabel(curve), context, length)
}

func (s *PSecret) ClientKeyExchangePrivateKey(curve ecdh.Curve, context []byte) (*ecdh.PrivateKey, error) {
	curveID, ok := curveIDForCurve(curve)
	if !ok {
		return nil, fmt.Errorf("unsupported curve %v", curve)
	}
	// Max private key size is 66 bytes
	seed := tls13.ExpandLabel(s.hash, s.secret, mkPClientKeyExchangeLabel(curveID), context, 66)
	buf := noDiceReader{bytes.NewBuffer(seed)}
	return curve.GenerateKey(buf)
}

func (s *PSecret) TicketFinishedKey(context []byte, length int) []byte {
	return tls13.ExpandLabel(s.hash, s.secret, pTicketFinishedLabel, context, length)
}

func (s *PSecret) TrafficSecret(context []byte, length int) []byte {
	return tls13.ExpandLabel(s.hash, s.secret, pTrafficSecretLabel, context, length)
}

func (s *PSecret) HandshakeSecret(context []byte, length int) []byte {
	return tls13.ExpandLabel(s.hash, s.secret, pHandshakeSecretLabel, context, length)
}
