package connector

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"os"

	ffmpeg "github.com/u2takey/ffmpeg-go"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/image/draw"
)

// deriveFileKeys derives AES encryption key, HMAC key, and nonce from key material
// using HKDF (SHA-256, no salt, info="FileEncryption").
// Returns encKey (32 bytes), macKey (32 bytes), nonce (12 bytes).
func deriveFileKeys(keyMaterial []byte) (encKey, macKey, nonce []byte, err error) {
	kdf := hkdf.New(sha256.New, keyMaterial, nil, []byte("FileEncryption"))
	derived := make([]byte, 76)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}
	return derived[0:32], derived[32:64], derived[64:76], nil
}

// newCTRStream creates an AES-256-CTR cipher stream from an encryption key and nonce.
// The 16-byte counter is composed of nonce (12 bytes) + zero counter (4 bytes).
func newCTRStream(encKey, nonce []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	counter := make([]byte, 16)
	copy(counter, nonce)
	return cipher.NewCTR(block, counter), nil
}

// LINE's E2EE file format: [encrypted_data][32-byte HMAC]
func (lc *LineClient) decryptImageData(encryptedData []byte, keyMaterialB64 string) ([]byte, error) {
	keyMaterial, err := base64.StdEncoding.DecodeString(keyMaterialB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key material: %w", err)
	}

	encKey, _, nonce, err := deriveFileKeys(keyMaterial)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < 32 {
		return nil, fmt.Errorf("encrypted data too short (< 32 bytes for HMAC)")
	}
	encryptedData = encryptedData[:len(encryptedData)-32]

	stream, err := newCTRStream(encKey, nonce)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedData))
	stream.XORKeyStream(decrypted, encryptedData)
	return decrypted, nil
}

func (lc *LineClient) encryptFileData(plainData []byte) ([]byte, string, error) {
	keyMaterial := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		return nil, "", fmt.Errorf("failed to generate key material: %w", err)
	}

	encKey, macKey, nonce, err := deriveFileKeys(keyMaterial)
	if err != nil {
		return nil, "", err
	}

	stream, err := newCTRStream(encKey, nonce)
	if err != nil {
		return nil, "", err
	}

	encrypted := make([]byte, len(plainData))
	stream.XORKeyStream(encrypted, plainData)

	h := hmac.New(sha256.New, macKey)
	h.Write(encrypted)
	result := append(encrypted, h.Sum(nil)...)
	return result, base64.StdEncoding.EncodeToString(keyMaterial), nil
}

// encryptVideoData encrypts video data with HMAC computed on chunk hashes
func (lc *LineClient) encryptVideoData(plainData []byte) ([]byte, string, error) {
	keyMaterial := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		return nil, "", fmt.Errorf("failed to generate key material: %w", err)
	}

	encKey, macKey, nonce, err := deriveFileKeys(keyMaterial)
	if err != nil {
		return nil, "", err
	}

	stream, err := newCTRStream(encKey, nonce)
	if err != nil {
		return nil, "", err
	}

	encrypted := make([]byte, len(plainData))
	stream.XORKeyStream(encrypted, plainData)

	chunkHashes := generateChunkHashes(encrypted)
	h := hmac.New(sha256.New, macKey)
	h.Write(chunkHashes)
	result := append(encrypted, h.Sum(nil)...)
	return result, base64.StdEncoding.EncodeToString(keyMaterial), nil
}

func generateThumbnail(imageData []byte) ([]byte, int, int, error) {
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode image: %w", err)
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	maxDim := 1280
	newWidth := width
	newHeight := height

	if width > maxDim || height > maxDim {
		if width > height {
			newWidth = maxDim
			newHeight = (height * maxDim) / width
		} else {
			newHeight = maxDim
			newWidth = (width * maxDim) / height
		}
	}

	var thumbnail image.Image
	if newWidth != width || newHeight != height {
		thumbnail = image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
		draw.CatmullRom.Scale(thumbnail.(draw.Image), thumbnail.Bounds(), img, bounds, draw.Over, nil)
	} else {
		thumbnail = img
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: 60}); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to encode thumbnail: %w", err)
	}

	return buf.Bytes(), newWidth, newHeight, nil
}

// encryptThumbnail encrypts thumbnail data using the same key material as the parent media.
// Returns the encrypted thumbnail with HMAC appended, matching LINE's E2EE thumbnail format.
func encryptThumbnail(thumbnailData []byte, keyMaterialB64 string) ([]byte, error) {
	keyMaterial, err := base64.StdEncoding.DecodeString(keyMaterialB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key material: %w", err)
	}

	encKey, macKey, nonce, err := deriveFileKeys(keyMaterial)
	if err != nil {
		return nil, err
	}

	stream, err := newCTRStream(encKey, nonce)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(thumbnailData))
	stream.XORKeyStream(encrypted, thumbnailData)

	h := hmac.New(sha256.New, macKey)
	h.Write(encrypted)
	return append(encrypted, h.Sum(nil)...), nil
}

func isAnimatedGif(data []byte) bool {
	// GIF header: "GIF89a" or "GIF87a"
	if len(data) < 6 {
		return false
	}

	if string(data[0:3]) != "GIF" {
		return false
	}

	// Count image descriptors (0x2C) which indicate frames
	frameCount := 0
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x2C { // Image descriptor separator
			frameCount++
			if frameCount > 1 {
				return true
			}
		}
	}

	return false
}

// generates the first frame of a video and resizes it to fit within 384x384
func extractVideoThumbnail(videoData []byte) ([]byte, int, int, error) {
	tmpVideoFile, err := os.CreateTemp("", "video-*.mp4")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create temp video file: %w", err)
	}
	defer os.Remove(tmpVideoFile.Name())
	defer tmpVideoFile.Close()

	if _, err := tmpVideoFile.Write(videoData); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to write video data: %w", err)
	}
	tmpVideoFile.Close()

	tmpThumbFile, err := os.CreateTemp("", "thumb-*.jpg")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to create temp thumb file: %w", err)
	}
	defer os.Remove(tmpThumbFile.Name())
	tmpThumbFile.Close()

	err = ffmpeg.Input(tmpVideoFile.Name()).
		Filter("scale", ffmpeg.Args{"384:384:force_original_aspect_ratio=decrease"}).
		Output(tmpThumbFile.Name(), ffmpeg.KwArgs{
			"vframes": 1,
			"q:v":     5,
		}).
		OverWriteOutput().
		Silent(true).
		Run()

	if err != nil {
		return nil, 0, 0, fmt.Errorf("ffmpeg failed: %w", err)
	}

	thumbData, err := os.ReadFile(tmpThumbFile.Name())
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read thumbnail: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(thumbData))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to decode thumbnail: %w", err)
	}

	bounds := img.Bounds()
	return thumbData, bounds.Dx(), bounds.Dy(), nil
}

// generateChunkHashes generates SHA-256 hashes for 128KB chunks of encrypted video data
// This is required by LINE for video integrity verification
func generateChunkHashes(encryptedData []byte) []byte {
	const chunkSize = 131072 // 128KB chunks
	var allHashes []byte

	for i := 0; i < len(encryptedData); i += chunkSize {
		end := i + chunkSize
		if end > len(encryptedData) {
			end = len(encryptedData)
		}

		chunk := encryptedData[i:end]
		hash := sha256.Sum256(chunk)
		allHashes = append(allHashes, hash[:]...)
	}

	return allHashes
}

func forceAPNGLoop(data []byte) []byte {
	if len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
		return data
	}

	offset := 8
	for offset < len(data) {
		if offset+8 > len(data) {
			break
		}
		length := binary.BigEndian.Uint32(data[offset : offset+4])
		chunkType := string(data[offset+4 : offset+8])

		if chunkType == "acTL" {
			if length >= 8 && offset+8+8 <= len(data) {
				binary.BigEndian.PutUint32(data[offset+8+4:offset+8+8], 0)

				crc := crc32.NewIEEE()
				crc.Write(data[offset+4 : offset+8+int(length)])
				newCRC := crc.Sum32()

				binary.BigEndian.PutUint32(data[offset+8+int(length):offset+8+int(length)+4], newCRC)
			}
			break
		}

		offset += 4 + 4 + int(length) + 4
	}
	return data
}
