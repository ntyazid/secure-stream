package secure_stream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdjustIVForOffset(t *testing.T) {
	iv, _ := hex.DecodeString("00000000000000000000000000000001")
	offset := int64(32)

	newIV := adjustIVForOffset(iv, offset)

	expected, _ := hex.DecodeString("00000000000000000000000000000003")

	if !bytes.Equal(newIV, expected) {
		t.Errorf("adjustedIVForOffset failed, result: %x expected: %x", newIV, expected)
	}
}

func TestParseRangeOffset(t *testing.T) {
	tests := []struct {
		header   string
		expected int64
	}{
		{"bytes=1024-2048", 1024},
		{"bytes=0-100", 0},
		{"", 0},
	}

	for _, ts := range tests {
		result, err := parseRangeOffset(ts.header)
		if err != nil {
			t.Errorf("Unexpected error for %s: %v", ts.header, err)
		}

		if result != ts.expected {
			t.Errorf("parseRangeOffset(%q) = %d, result: %d", ts.header, result, ts.expected)
		}
	}
}

func TestStreamFromUrl(t *testing.T) {
	sourceContent := []byte("HelloSecureStreamingWorld!")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(sourceContent)
	}))

	defer mockServer.Close()

	key := []byte("examplekey123456examplekey123456")
	iv := make([]byte, 16)

	recorder := httptest.NewRecorder()
	err := StreamFromUrl(recorder, mockServer.URL, key, iv)

	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	encrypted := recorder.Body.Bytes()
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	expected := sourceContent
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decryption mismatch, result: %s, expected: %s", decrypted, expected)
	}
}

func TestStreamFromUrlWithRange(t *testing.T) {
	sourceContent := []byte("HelloSecureStreamingWorld!")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "bytes=6-25" {
			w.Header().Set("Content-Range", "bytes 6-25/26")
			w.WriteHeader(http.StatusPartialContent)
			w.Write(sourceContent[6:26])
		} else {
			w.Write(sourceContent)
		}
		fmt.Printf("Range header: %s\n", rangeHeader)
	}))

	defer mockServer.Close()

	key := []byte("examplekey123456examplekey123456")
	iv := make([]byte, 16)

	recorder := httptest.NewRecorder()
	err := StreamFromUrlWithRange(recorder, mockServer.URL, key, iv, "bytes=6-25")

	if err != nil {
		t.Fatalf("StreamWithRange error: %v", err)
	}

	encrypted := recorder.Body.Bytes()
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, adjustIVForOffset(iv, 6))
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	expected := sourceContent[6:26]
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decryption mismatch, result: %s, expected: %s", decrypted, expected)
	}
}

func TestStreamFromByte(t *testing.T) {
	sourceData := []byte("HelloSecureStreamingWorld!")
	data := bytes.NewReader(sourceData)
	size := int64(len(sourceData))

	key := []byte("examplekey123456examplekey123456")
	iv := make([]byte, aes.BlockSize)

	recorder := httptest.NewRecorder()

	err := StreamFromByte(recorder, data, size, key, iv)
	if err != nil {
		t.Fatalf("Stream error: %v", err)
	}

	encrypted := recorder.Body.Bytes()

	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	fmt.Printf("decrypted: %s\n", decrypted)

	expected := sourceData
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("decryption mismatch, result: %s, expected: %s", decrypted, expected)
	}
}

func TestStreamFromByteWithRange(t *testing.T) {
	sourceData := []byte("HelloSecureStreamingWorld!")
	data := bytes.NewReader(sourceData)
	size := int64(len(sourceData))

	key := []byte("examplekey123456examplekey123456")
	iv := make([]byte, aes.BlockSize)

	byteRange := "bytes=5-20"

	recorder := httptest.NewRecorder()

	err := StreamFromByteWithRange(recorder, data, size, key, iv, byteRange)
	if err != nil {
		t.Fatalf("StreamFromByteWithRange error: %v", err)
	}

	encrypted := recorder.Body.Bytes()

	offset := int64(5)
	adjustedIV := adjustIVForOffset(iv, offset)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES cipher creation failed: %v", err)
	}

	decrypter := cipher.NewCTR(block, adjustedIV)
	decrypted := make([]byte, len(encrypted))
	decrypter.XORKeyStream(decrypted, encrypted)
	fmt.Printf("decrypted: %s\n", decrypted)

	expected := sourceData[5 : 20+1]
	if !bytes.Equal(decrypted, expected) {
		t.Errorf("Decrypted data mismatch.\nResult: %s\nExpected: %s", decrypted, expected)
	}
	fmt.Printf("expected: %s\n", expected)

	contentRange := recorder.Header().Get("Content-Range")
	expectedHeader := fmt.Sprintf("bytes 5-20/%d", size)
	if contentRange != expectedHeader {
		t.Errorf("Content-Range header mismatch.\nResult: %s\nExpected: %s", contentRange, expectedHeader)
	}
}
