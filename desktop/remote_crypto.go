package main

// CoreKit Remote: pairing and encryption.
//
// Two devices share only a short 6-digit code. SPAKE2 (RFC 9382 style, P-256)
// turns that code into strong session keys without ever sending it: someone on the
// same Wi-Fi who records the traffic cannot test codes offline, and an active
// attacker gets one guess per connection attempt (and the shared device must also
// press Allow). After pairing, every message is sealed with AES-256-GCM, one key per
// direction, with a counter nonce.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

var p256 = elliptic.P256()

// spakeM and spakeN are fixed points with no known discrete log: each is the first
// point whose x is SHA-256(seed||i) (try-and-increment), so anyone can re-derive them.
var spakeM, spakeN = derivePoint("CoreKit Remote SPAKE2 M"), derivePoint("CoreKit Remote SPAKE2 N")

type ecPoint struct{ x, y *big.Int }

func derivePoint(seed string) ecPoint {
	pr := p256.Params()
	exp := new(big.Int).Add(pr.P, big.NewInt(1))
	exp.Rsh(exp, 2) // p ≡ 3 (mod 4): sqrt(a) = a^((p+1)/4)
	three := big.NewInt(3)
	for i := uint32(0); ; i++ {
		h := sha256.New()
		h.Write([]byte(seed))
		binary.Write(h, binary.BigEndian, i)
		x := new(big.Int).SetBytes(h.Sum(nil))
		if x.Cmp(pr.P) >= 0 {
			continue
		}
		// y² = x³ - 3x + b
		y2 := new(big.Int).Exp(x, three, pr.P)
		y2.Sub(y2, new(big.Int).Mul(x, three))
		y2.Add(y2, pr.B)
		y2.Mod(y2, pr.P)
		y := new(big.Int).Exp(y2, exp, pr.P)
		if new(big.Int).Exp(y, big.NewInt(2), pr.P).Cmp(y2) != 0 {
			continue
		}
		if y.Bit(0) == 1 {
			y.Sub(pr.P, y)
		}
		if p256.IsOnCurve(x, y) {
			return ecPoint{x, y}
		}
	}
}

// codeScalar maps the code to the SPAKE2 password scalar w.
func codeScalar(code string) *big.Int {
	h := sha256.Sum256([]byte("CoreKit Remote code v1|" + code))
	w := new(big.Int).SetBytes(h[:])
	return w.Mod(w, p256.Params().N)
}

func randScalar() (*big.Int, error) {
	n := p256.Params().N
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}

func scalarMult(p ecPoint, k *big.Int) ecPoint {
	x, y := p256.ScalarMult(p.x, p.y, k.Bytes())
	return ecPoint{x, y}
}
func addPoints(a, b ecPoint) ecPoint { x, y := p256.Add(a.x, a.y, b.x, b.y); return ecPoint{x, y} }
func negPoint(a ecPoint) ecPoint {
	return ecPoint{new(big.Int).Set(a.x), new(big.Int).Sub(p256.Params().P, a.y)}
}
func encPoint(a ecPoint) []byte { return elliptic.Marshal(p256, a.x, a.y) }
func decPoint(b []byte) (ecPoint, error) {
	x, y := elliptic.Unmarshal(p256, b)
	if x == nil {
		return ecPoint{}, errors.New("bad point")
	}
	return ecPoint{x, y}, nil
}

// spakeParty is one side of the exchange. role 'A' connects (viewer), 'B' is the shared device.
type spakeParty struct {
	role byte
	w, x *big.Int
	msg  []byte // our public share
}

func newSpake(role byte, code string) (*spakeParty, error) {
	x, err := randScalar()
	if err != nil {
		return nil, err
	}
	w := codeScalar(code)
	gx := ecPoint{}
	gx.x, gx.y = p256.ScalarBaseMult(x.Bytes())
	blind := spakeM
	if role == 'B' {
		blind = spakeN
	}
	pub := addPoints(gx, scalarMult(blind, w))
	return &spakeParty{role: role, w: w, x: x, msg: encPoint(pub)}, nil
}

// sessionKeys is everything both sides derive from a finished exchange.
type sessionKeys struct {
	a2b, b2a     []byte // AES-256 keys: viewer→shared, shared→viewer
	confA, confB []byte // key-confirmation MACs each side must show
}

// finish combines the peer's share into keys. Both sides compute the same transcript;
// a wrong code gives different keys and the confirmation MACs won't match.
func (s *spakeParty) finish(peer []byte, idA, idB string) (*sessionKeys, error) {
	pp, err := decPoint(peer)
	if err != nil {
		return nil, err
	}
	unblind := spakeN
	if s.role == 'B' {
		unblind = spakeM
	}
	k := scalarMult(addPoints(pp, negPoint(scalarMult(unblind, s.w))), s.x)
	if k.x.Sign() == 0 && k.y.Sign() == 0 {
		return nil, errors.New("bad exchange")
	}
	pA, pB := s.msg, peer
	if s.role == 'B' {
		pA, pB = peer, s.msg
	}
	tt := sha256.New()
	for _, part := range [][]byte{[]byte(idA), []byte(idB), encPoint(spakeM), encPoint(spakeN), pA, pB, encPoint(k), s.w.Bytes()} {
		binary.Write(tt, binary.LittleEndian, uint64(len(part)))
		tt.Write(part)
	}
	sum := tt.Sum(nil)
	okm, err := hkdf.Key(sha256.New, sum, nil, "CoreKit Remote session v1", 128)
	if err != nil {
		return nil, err
	}
	mac := func(key []byte) []byte { m := hmac.New(sha256.New, key); m.Write(sum); return m.Sum(nil) }
	return &sessionKeys{a2b: okm[0:32], b2a: okm[32:64], confA: mac(okm[64:96]), confB: mac(okm[96:128])}, nil
}

// sealer encrypts one direction of the channel; opener decrypts the other.
type aeadDir struct {
	gcm cipher.AEAD
	ctr uint64
}

func newDir(key []byte) (*aeadDir, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &aeadDir{gcm: g}, nil
}

func (d *aeadDir) nonce() []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], d.ctr)
	d.ctr++
	return n
}
func (d *aeadDir) seal(p []byte) []byte { return d.gcm.Seal(nil, d.nonce(), p, nil) }
func (d *aeadDir) open(c []byte) ([]byte, error) {
	p, err := d.gcm.Open(nil, d.nonce(), c, nil)
	if err != nil {
		return nil, errors.New("message failed authentication")
	}
	return p, nil
}
