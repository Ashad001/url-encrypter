package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
	"text/template"

	"github.com/gorilla/mux"
)


var (
	key       = ""
	usedKeys  = make(map[string]bool)
	usedKeysMu sync.Mutex
)


func SetKey(newKey string) {
	key = newKey
}

func GetKey() string {
	return key
}

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	SetKey(string(key))
	return key, nil
}

func IsKeyUsed(encryptedURL string) bool {
	usedKeysMu.Lock()
	defer usedKeysMu.Unlock()

	return usedKeys[encryptedURL]
}

func MarkKeyAsUsed(encryptedURL string) {
	usedKeysMu.Lock()
	defer usedKeysMu.Unlock()

	usedKeys[encryptedURL] = true
}






// Based on Wikipedia: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
func PadToBlockSize(input string) string {
    paddingNeeded := aes.BlockSize - (len(input) % aes.BlockSize)
    if paddingNeeded >= 256 {
        panic("I'm too lazy to handle this case for the sake of an example :)")
    }
    
    if paddingNeeded == 0 {
        paddingNeeded = aes.BlockSize
    }

    // Inefficient, once again, this is an example only!
    for i := 0; i < paddingNeeded; i++ {
        input += string(byte(paddingNeeded))
    }
    return input
}

// (Identical to your code, I just deleted comments to save space)
func encrypt(plainstring string) string {
	keyString, _ := GenerateRandomKey()
    key := []byte(keyString)
	plaintext := []byte(plainstring)
    if len(plaintext)%aes.BlockSize != 0 {
        panic("plaintext is not a multiple of the block size")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(bytes.NewReader([]byte("97iEhhtgVjoVwdUw")), iv); err != nil {
        panic(err)
    }
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
    return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(cipherText string) string {
	key := GetKey()
	keyBytes := []byte(key)
	cipherBytes, err := base64.URLEncoding.DecodeString(cipherText)

	if err != nil {
		panic("Decyption failed")
		
	}
	
	initVec := cipherBytes[:aes.BlockSize]
	cipherTextBytes := cipherBytes[aes.BlockSize:]

	block, err := aes.NewCipher(keyBytes)

	if err != nil {
		panic("Decryption Failed: ")
	}
	mode := cipher.NewCBCDecrypter(block, initVec)
	mode.CryptBlocks(cipherTextBytes, cipherTextBytes)
	padding := int(cipherTextBytes[len(cipherTextBytes) - 1])

	plainText := cipherTextBytes[:len(cipherTextBytes) - padding]

	return string(plainText)
}

func accessPrivateURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	encryptedURL := vars["encryptedURL"]

	if IsKeyUsed(encryptedURL) {
		http.Error(w, "This key has already been used.", http.StatusUnauthorized)
		return
	}

	originalURL := decrypt(encryptedURL)
	MarkKeyAsUsed(encryptedURL)

	http.Redirect(w, r, originalURL, http.StatusTemporaryRedirect)
}


func generatePrivateURL(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	originalURL := r.FormValue("original_url")

	if originalURL == "" {
		http.Error(w, "Original URL cannot be empty", http.StatusBadRequest)
		return
	}



	paddedURL := PadToBlockSize(originalURL)
	encryptedURL := encrypt(paddedURL)

	if IsKeyUsed(encryptedURL) {
		http.Error(w, "Failed to generate private URL. Please try again.", http.StatusInternalServerError)
		return
	}


	resultHTML := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Private URL Generated</title>
		</head>
		<body>
			<h2>Private URL Generated:</h2>
			<p><strong>Encrypted URL:</strong> %s</p>
		</body>
		</html>
	`, encryptedURL)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(resultHTML))
}


func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("index").Parse(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Private URL Generator</title>
		</head>
		<body>
			<h2>Private URL Generator</h2>
			<form action="/generate" method="post">
				<label for="original_url">Original URL:</label>
				<input type="text" id="original_url" name="original_url" required>
				<button type="submit">Generate Private URL</button>
			</form>
		</body>
		</html>
	`)

	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/generate", generatePrivateURL).Methods("POST")
	r.HandleFunc("/{encryptedURL}", accessPrivateURL).Methods("GET")

	http.Handle("/", r)

	fmt.Println("Server is running on http://127.0.0.1:8080/")
	http.ListenAndServe(":8080", nil)
}