package secure_stream

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func StreamFromUrl(w http.ResponseWriter, fileUrl string, key, iv []byte) error {
	req, err := http.NewRequest("GET", fileUrl, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	streamReader := &cipher.StreamReader{S: stream, R: resp.Body}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/octet-stream")

	_, err = io.Copy(w, streamReader)
	return err
}

// func StreamFromUrlWithRange(w http.ResponseWriter, fileUrl string, key, iv []byte, byteRange string) error {
// 	req, err := http.NewRequest("GET", fileUrl, nil)
// 	if err != nil {
// 		return err
// 	}

// 	if byteRange != "" {
// 		req.Header.Set("Range", byteRange)
// 	}

// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	offset, err := parseRangeOffset(byteRange)
// 	if err != nil {
// 		return err
// 	}

// 	adjustedIV := adjustIVForOffset(iv, offset)

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return err
// 	}

// 	stream := cipher.NewCTR(block, adjustedIV)
// 	streamReader := &cipher.StreamReader{S: stream, R: resp.Body}

// 	if resp.StatusCode == http.StatusPartialContent {
// 		w.WriteHeader(http.StatusPartialContent)
// 	} else {
// 		w.WriteHeader(http.StatusOK)
// 	}
// 	w.Header().Set("Content-Type", "application/octet-stream")

// 	_, err = io.Copy(w, streamReader)
// 	return err
// }

func StreamFromUrlWithRange(w http.ResponseWriter, fileUrl string, key, iv []byte, byteRange string) error {
	req, err := http.NewRequest("GET", fileUrl, nil)
	if err != nil {
		return err
	}

	if byteRange != "" {
		req.Header.Set("Range", byteRange)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var totalSize int64
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		var start, end, size int64
		_, err = fmt.Sscanf(cr, "bytes %d-%d/%d", &start, &end, &size)
		if err == nil {
			totalSize = size
		}
	} else if cl := resp.Header.Get("Content-Length"); cl != "" {
		totalSize, _ = strconv.ParseInt(cl, 10, 64)
	}

	offset, err := parseRangeOffset(byteRange)
	if err != nil {
		return err
	}

	adjustedIV := adjustIVForOffset(iv, offset)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, adjustedIV)
	streamReader := &cipher.StreamReader{S: stream, R: resp.Body}

	if byteRange != "" && resp.StatusCode == http.StatusPartialContent {
		chunkLen := resp.ContentLength
		end := offset + chunkLen - 1

		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, end, totalSize))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", chunkLen))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", totalSize))
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Type", "application/pdf")
		w.WriteHeader(http.StatusOK)
	}

	_, err = io.Copy(w, streamReader)
	return err
}

func StreamFromByte(w http.ResponseWriter, data io.ReaderAt, size int64, key, iv []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	sectionReader := io.NewSectionReader(data, 0, size)
	streamReader := &cipher.StreamReader{S: stream, R: sectionReader}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/octet-stream")

	_, err = io.Copy(w, streamReader)
	return err
}

func StreamFromByteWithRange(w http.ResponseWriter, data io.ReaderAt, size int64, key, iv []byte, byteRange string) error {
	offset, length, err := parseByteRange(byteRange, size)
	if err != nil {
		return err
	}

	adjustedIV := adjustIVForOffset(iv, offset)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, adjustedIV)

	sectionReader := io.NewSectionReader(data, offset, length)
	streamReader := &cipher.StreamReader{S: stream, R: sectionReader}

	if byteRange != "" {
		w.WriteHeader(http.StatusPartialContent)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, size))
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Header().Set("Content-Type", "application/octet-stream")

	_, err = io.Copy(w, streamReader)
	return err
}

func parseRangeOffset(rangeHeader string) (int64, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, nil
	}

	rangePart := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangePart, "-")
	if len(parts) != 2 {
		return 0, errors.New("Invalid range format.")
	}
	return strconv.ParseInt(parts[0], 10, 64)
}

func parseByteRange(byteRange string, size int64) (start int64, length int64, err error) {
	if byteRange == "" {
		return 0, size, nil
	}
	if !strings.HasPrefix(byteRange, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range header")
	}

	rangeParts := strings.Split(strings.TrimPrefix(byteRange, "bytes="), "-")
	if len(rangeParts) != 2 {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	start, err = strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start byte")
	}

	end, err := strconv.ParseInt(rangeParts[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end byte")
	}

	if start > end || end >= size {
		return 0, 0, fmt.Errorf("range out of bounds")
	}

	length = end - start + 1
	return start, length, nil
}

func adjustIVForOffset(originalIV []byte, offset int64) []byte {
	if len(originalIV) != 16 {
		panic("IV must be 16 bytes.")
	}

	blockSize := 16
	blockOffset := offset / int64(blockSize)

	newIV := make([]byte, 16)
	copy(newIV, originalIV)

	counter := binary.BigEndian.Uint64(originalIV[8:16])
	counter += uint64(blockOffset)
	binary.BigEndian.PutUint64(newIV[8:16], counter)

	return newIV
}
