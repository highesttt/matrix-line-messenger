// Package ltsm implements LINE's Letter Sealing encryption protocol in pure Go,
// eliminating the need for the ltsm.wasm binary and wazero runtime.
package ltsm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Channel represents an E2EE channel between two parties.
// It holds the shared secret from X25519 ECDH.
type Channel struct {
	SharedSecret [32]byte
}

// NewChannel creates a new E2EE channel from our private key and the peer's public key.
// SharedSecret = X25519(myPrivateKey, peerPublicKey).
func NewChannel(myPrivateKey, peerPublicKey []byte) (*Channel, error) {
	if len(myPrivateKey) != 32 || len(peerPublicKey) != 32 {
		return nil, fmt.Errorf("ltsm: invalid key length (private=%d, public=%d)", len(myPrivateKey), len(peerPublicKey))
	}
	shared, err := curve25519.X25519(myPrivateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ltsm: X25519 failed: %w", err)
	}
	var ch Channel
	copy(ch.SharedSecret[:], shared)
	return &ch, nil
}

// --- V1 Encryption (AES-256-CBC + encrypt-then-MAC) ---

// EncryptV1 encrypts plaintext using the V1 Letter Sealing protocol.
//
// Algorithm:
//  1. Generate 8-byte random salt
//  2. Key = SHA-256(SharedSecret || salt || "Key")
//  3. IV = SHA-256(SharedSecret || salt || "IV"), XOR-folded to 16 bytes
//  4. AES-256-CBC encrypt with PKCS#7 padding
//  5. MAC = AES-ECB(Key, SHA-256(ciphertext) XOR-folded to 16 bytes)
//  6. Output: salt(8) || ciphertext || MAC(16)
func (ch *Channel) EncryptV1(plaintext []byte) ([]byte, error) {
	// 1. Generate 8-byte salt
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("ltsm: failed to generate salt: %w", err)
	}

	// 2. Derive AES-256 key
	key := deriveKeyV1(ch.SharedSecret[:], salt)

	// 3. Derive IV (XOR-folded SHA-256)
	iv := deriveIVV1(ch.SharedSecret[:], salt)

	// 4. AES-256-CBC encrypt with PKCS#7 padding
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ltsm: aes.NewCipher: %w", err)
	}
	cbc := cipher.NewCBCEncrypter(block, iv[:])
	encrypted := make([]byte, len(padded))
	cbc.CryptBlocks(encrypted, padded)

	// 5. Compute MAC: AES-ECB(Key, SHA-256(ciphertext) XOR-folded to 16 bytes)
	mac := computeMACv1(block, encrypted)

	// 6. Assemble: salt(8) || ciphertext || MAC(16)
	result := make([]byte, 0, 8+len(encrypted)+16)
	result = append(result, salt...)
	result = append(result, encrypted...)
	result = append(result, mac[:]...)
	return result, nil
}

// DecryptV1 decrypts a V1 Letter Sealing ciphertext.
func (ch *Channel) DecryptV1(data []byte) ([]byte, error) {
	if len(data) < 8+16+aes.BlockSize {
		return nil, fmt.Errorf("ltsm: V1 ciphertext too short (%d bytes)", len(data))
	}

	salt := data[:8]
	encrypted := data[8 : len(data)-16]
	receivedMAC := data[len(data)-16:]

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ltsm: V1 ciphertext not block-aligned (%d bytes)", len(encrypted))
	}

	// Derive key and IV
	key := deriveKeyV1(ch.SharedSecret[:], salt)
	iv := deriveIVV1(ch.SharedSecret[:], salt)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ltsm: aes.NewCipher: %w", err)
	}

	// Verify MAC
	expectedMAC := computeMACv1(block, encrypted)
	if !constantTimeEqual(receivedMAC, expectedMAC[:]) {
		return nil, fmt.Errorf("ltsm: V1 MAC verification failed")
	}

	// AES-256-CBC decrypt
	plaintext := make([]byte, len(encrypted))
	cbc := cipher.NewCBCDecrypter(block, iv[:])
	cbc.CryptBlocks(plaintext, encrypted)

	// Remove PKCS#7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("ltsm: %w", err)
	}

	return plaintext, nil
}

// --- V2 Encryption (AES-256-GCM with AAD) ---

// EncryptV2 encrypts plaintext using the V2 Letter Sealing protocol.
//
// Algorithm:
//  1. Generate 16-byte random salt
//  2. Key = SHA-256(SharedSecret || salt || "Key")
//  3. Nonce = BE(seq, 8 bytes) || random(4 bytes) = 12 bytes
//  4. AAD = buildAAD(to, from, senderKeyID, receiverKeyID, contentType)
//  5. AES-256-GCM encrypt with key, nonce, AAD
//  6. Output: salt(16) || nonce(12) || ciphertext || tag(16)
func (ch *Channel) EncryptV2(to, from string, senderKeyID, receiverKeyID, contentType int, seq int64, plaintext []byte) ([]byte, error) {
	// 1. Generate 16-byte salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("ltsm: failed to generate salt: %w", err)
	}

	// 2. Derive AES-256 key (same formula as V1 but with 16-byte salt)
	key := deriveKeyV2(ch.SharedSecret[:], salt)

	// 3. Construct 12-byte nonce: BE(seq, 8) || random(4)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[:8], uint64(seq))
	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nil, fmt.Errorf("ltsm: failed to generate nonce random: %w", err)
	}

	// 4. Build AAD
	aad := buildAADv2(to, from, senderKeyID, receiverKeyID, contentType)

	// 5. AES-256-GCM encrypt
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ltsm: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ltsm: cipher.NewGCM: %w", err)
	}
	// Seal appends ciphertext+tag to dst
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	// sealed = ciphertext || tag(16)

	// 6. Assemble: salt(16) || nonce(12) || ciphertext || tag(16)
	result := make([]byte, 0, 16+12+len(sealed))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, sealed...)
	return result, nil
}

// DecryptV2 decrypts a V2 Letter Sealing ciphertext.
func (ch *Channel) DecryptV2(to, from string, senderKeyID, receiverKeyID, contentType int, data []byte) ([]byte, error) {
	if len(data) < 16+12+16 { // salt + nonce + tag minimum
		return nil, fmt.Errorf("ltsm: V2 ciphertext too short (%d bytes)", len(data))
	}

	salt := data[:16]
	nonce := data[16:28]
	sealed := data[28:] // ciphertext || tag(16)

	// Derive key
	key := deriveKeyV2(ch.SharedSecret[:], salt)

	// Build AAD
	aad := buildAADv2(to, from, senderKeyID, receiverKeyID, contentType)

	// AES-256-GCM decrypt
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ltsm: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ltsm: cipher.NewGCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("ltsm: GCM authentication failed: %w", err)
	}

	return plaintext, nil
}

// --- Key Derivation ---

// deriveKeyV1 derives the AES-256 encryption key for V1.
// Key = SHA-256(SharedSecret || salt || "Key")
func deriveKeyV1(sharedSecret, salt []byte) [32]byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(salt)
	h.Write([]byte("Key"))
	var key [32]byte
	h.Sum(key[:0])
	return key
}

// deriveIVV1 derives the 16-byte IV for V1.
// IVpre = SHA-256(SharedSecret || salt || "IV"), XOR-folded to 16 bytes.
func deriveIVV1(sharedSecret, salt []byte) [16]byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(salt)
	h.Write([]byte("IV"))
	hash := h.Sum(nil)
	var iv [16]byte
	for i := 0; i < 16; i++ {
		iv[i] = hash[i] ^ hash[i+16]
	}
	return iv
}

// deriveKeyV2 derives the AES-256 encryption key for V2.
// Key = SHA-256(SharedSecret || salt || "Key")
// Same formula as V1, just different salt size (16 bytes vs 8).
func deriveKeyV2(sharedSecret, salt []byte) [32]byte {
	return deriveKeyV1(sharedSecret, salt) // same KDF formula
}

// --- V1 MAC ---

// computeMACv1 computes the V1 message authentication code.
// MAC = AES-ECB(Key, SHA-256(ciphertext) XOR-folded to 16 bytes)
func computeMACv1(block cipher.Block, ciphertext []byte) [16]byte {
	// SHA-256 of ciphertext
	hash := sha256.Sum256(ciphertext)
	// XOR-fold 32 bytes to 16 bytes
	var macInput [16]byte
	for i := 0; i < 16; i++ {
		macInput[i] = hash[i] ^ hash[i+16]
	}
	// AES-ECB encrypt (single block)
	var mac [16]byte
	block.Encrypt(mac[:], macInput[:])
	return mac
}

// --- V2 AAD Construction ---

// buildAADv2 constructs the Additional Authenticated Data for V2.
// Format (82 bytes):
//
//	to_mid (33 bytes): raw UTF-8 string bytes (lowercase)
//	from_mid (33 bytes): raw UTF-8 string bytes (lowercase)
//	BE(senderKeyId, 4)
//	BE(receiverKeyId, 4)
//	BE(2, 4)           // protocol version
//	BE(contentType, 4)
func buildAADv2(to, from string, senderKeyID, receiverKeyID, contentType int) []byte {
	aad := make([]byte, 0, 82)
	aad = append(aad, processMIDforAAD(to)...)
	aad = append(aad, processMIDforAAD(from)...)

	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(senderKeyID))
	aad = append(aad, buf[:]...)
	binary.BigEndian.PutUint32(buf[:], uint32(receiverKeyID))
	aad = append(aad, buf[:]...)
	binary.BigEndian.PutUint32(buf[:], 2) // protocol version
	aad = append(aad, buf[:]...)
	binary.BigEndian.PutUint32(buf[:], uint32(contentType))
	aad = append(aad, buf[:]...)

	return aad
}

// processMIDforAAD processes a LINE MID for use in V2 AAD.
// MIDs are used as raw lowercase UTF-8 string bytes (33 bytes).
// LINE MIDs are like "u8ae764e8e69e6bd4ecdd9b6ea0c40fce" where 'u' is user prefix.
// The WASM hex-decodes and re-formats with "%s%08llx%08llx%s" which is identity.
func processMIDforAAD(mid string) []byte {
	result := make([]byte, 33)
	if len(mid) == 0 {
		return result
	}
	// Lowercase the entire MID and copy as raw bytes
	n := len(mid)
	if n > 33 {
		n = 33
	}
	for i := 0; i < n; i++ {
		c := mid[i]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		result[i] = c
	}
	return result
}

// --- PKCS#7 Padding ---

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid PKCS#7 padded data length: %d", len(data))
	}
	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > blockSize {
		return nil, fmt.Errorf("invalid PKCS#7 padding value: %d", padLen)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid PKCS#7 padding at byte %d", i)
		}
	}
	return data[:len(data)-padLen], nil
}

// --- Utilities ---

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
