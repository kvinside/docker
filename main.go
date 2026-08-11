package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
        "os"
)

var key = []byte(os.Getenv("ENCRYPTION_KEY"))

type Request struct {
	Text string `json:"text"`
}

type Response struct {
	Result string `json:"result"`
}

func encrypt(text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := gcm.Seal(nonce, nonce, []byte(text), nil)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(data) < nonceSize {
		return "", fmt.Errorf("data terlalu pendek")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method harus POST", http.StatusMethodNotAllowed)
		return
	}

	var req Request

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "JSON tidak valid", http.StatusBadRequest)
		return
	}

	result, err := encrypt(req.Text)
	if err != nil {
		http.Error(w, "Gagal encrypt", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: result,
	})
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method harus POST", http.StatusMethodNotAllowed)
		return
	}

	var req Request

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "JSON tidak valid", http.StatusBadRequest)
		return
	}

	result, err := decrypt(req.Text)
	if err != nil {
		http.Error(w, "Gagal decrypt", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: result,
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `
<!DOCTYPE html>
<html lang="id">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">

	<title>App1 Encryption</title>

	<style>
		body {
			font-family: Arial, sans-serif;
			background: #f2f2f2;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
		}

		.container {
			background: white;
			padding: 30px;
			border-radius: 12px;
			width: 500px;
			box-shadow: 0 5px 20px rgba(0,0,0,0.15);
		}

		h1 {
			text-align: center;
		}

		textarea {
			width: 100%;
			box-sizing: border-box;
			padding: 12px;
			margin-top: 8px;
			border: 1px solid #ccc;
			border-radius: 6px;
			resize: vertical;
		}

		button {
			padding: 10px 20px;
			margin-top: 12px;
			margin-right: 8px;
			border: none;
			border-radius: 6px;
			cursor: pointer;
		}

		.encrypt {
			background: #222;
			color: white;
		}

		.decrypt {
			background: #ddd;
			color: black;
		}

		button:hover {
			opacity: 0.8;
		}

		#status {
			margin-top: 15px;
			font-size: 14px;
		}
	</style>
</head>

<body>

<div class="container">

	<h1>🔐 App1 Encryption</h1>

	<label>Input:</label>

	<textarea
		id="text"
		rows="6"
		placeholder="Masukkan text atau ciphertext..."
	></textarea>

	<button class="encrypt" onclick="encryptText()">
		Encrypt
	</button>

	<button class="decrypt" onclick="decryptText()">
		Decrypt
	</button>

	<br>

	<label>Result:</label>

	<textarea
		id="result"
		rows="6"
		readonly
		placeholder="Hasil akan muncul di sini..."
	></textarea>

	<div id="status"></div>

</div>

<script>

async function processText(endpoint) {

	const text = document.getElementById("text").value;

	if (!text) {
		document.getElementById("status").innerText =
			"Masukkan text terlebih dahulu.";

		return;
	}

	try {

		const response = await fetch(endpoint, {

			method: "POST",

			headers: {
				"Content-Type": "application/json"
			},

			body: JSON.stringify({
				text: text
			})

		});

		const data = await response.json();

		if (!response.ok) {
			throw new Error(data.result || "Request gagal");
		}

		document.getElementById("result").value =
			data.result;

		document.getElementById("status").innerText =
			"Berhasil.";

	} catch (error) {

		document.getElementById("status").innerText =
			"Error: " + error.message;

	}

}

function encryptText() {
	processText("/encrypt");
}

function decryptText() {
	processText("/decrypt");
}

</script>

</body>
</html>
`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	fmt.Fprint(w, html)
}

func main() {

	http.HandleFunc("/", homeHandler)

	http.HandleFunc("/encrypt", encryptHandler)

	http.HandleFunc("/decrypt", decryptHandler)

	fmt.Println("App1 running on port 9000")

	err := http.ListenAndServe(":9000", nil)

	if err != nil {
		fmt.Println(err)
	}
}
