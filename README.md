# secure-stream

Go module for secure streaming of AES-CTR files (e.g., PDF/EPUB) over HTTP with support for byte range requests.

This module is designed to stream encrypted content to the frontend where decryption and rendering can be handled in a streaming manner.

---

## Features

- AES-256 encryption with `cipher.NewCTR` stream mode
- Partial streaming support with HTTP Range headers
- Includes test coverage for key streaming scenarios
- Ideal for serving EPUB or PDF files securely (see limitations below)

---

## Limitations with PDF.js

One of the goals of this module was to **stream encrypted PDFs** and allow PDF.js to render pages **as byte ranges are decrypted**.

However, based on testing and implementation insights:

> - **PDF.js does not support rendering PDF pages from individually decrypted byte ranges.**
>
> - PDF.js requires a **complete and coherent PDF structure** before it can begin rendering any page.
>
> - This means the **entire encrypted file must be downloaded and decrypted first**, making partial rendering via decrypted byte chunks unfeasible with PDF.js.

---

## Installation

```bash
go get github.com/ntyazid/secure-stream
```

---

## Example Usage

### Stream Encrypted PDF File

```go
http.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
    fileUrl := r.URL.Query().Get("fileUrl")
    key := []byte("examplekey123456examplekey123456") // 32 bytes
    iv := make([]byte, 16) // 16-byte IV

    err := secure_stream.StreamFromUrl(w, fileUrl, key, iv)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
})
```

### Stream Encrypted File With Range Support

```go
http.HandleFunc("/stream-range", func(w http.ResponseWriter, r *http.Request) {
    fileUrl := r.URL.Query().Get("fileUrl")
    byteRange := r.Header.Get("Range")
    key := []byte("examplekey123456examplekey123456")
    iv := make([]byte, 16)

    err := secure_stream.StreamFromUrlWithRange(w, fileUrl, key, iv, byteRange)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
})
```

---

## How Encryption Works

This module uses AES-CTR stream encryption:

- Encrypted data is streamed directly over HTTP
- IV is adjusted based on requested byte offset to keep decryption in sync
- Decryption can be done client-side (e.g., using `crypto.subtle.decrypt` in JS)

---

## Testing

The repository includes unit tests for:

- IV adjustment
- Range offset parsing
- Full-stream and ranged stream encryption/decryption

Run tests with:

```bash
go test -v
```

---

## API Reference

| Function | Description |
|----------|-------------|
| `StreamFromUrl()` | Streams full encrypted file |
| `StreamFromUrlWithRange()` | Streams a range of the encrypted file |
| `StreamFromByte()` | Streams from `io.ReaderAt` |
| `StreamFromByteWithRange()` | Streams range from `io.ReaderAt` |
| `adjustIVForOffset()` | Adjusts AES-CTR IV based on offset |
| `parseRangeOffset()` | Extracts offset from `Range` header |
| `parseByteRange()` | Parses range into start/length |

---