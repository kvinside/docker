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

	"golang.org/x/crypto/bcrypt"
)

type Request struct {
	Text string `json:"text"`
}

type VerifyRequest struct {
	Text string `json:"text"`
	Hash string `json:"hash"`
}

type Response struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

var key []byte

// =========================
// AES ENCRYPT
// =========================

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

// =========================
// AES DECRYPT
// =========================

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
		return "", fmt.Errorf("ciphertext tidak valid")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt gagal: data bukan hasil encrypt yang valid")
	}

	return string(plaintext), nil
}

// =========================
// HASH PASSWORD
// =========================

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// =========================
// VERIFY PASSWORD
// =========================

func verifyPassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	)

	return err == nil
}

// =========================
// JSON ERROR
// =========================

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(Response{
		Error: message,
	})
}

// =========================
// ENCRYPT API
// =========================

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method harus POST")
		return
	}

	var req Request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	if req.Text == "" {
		jsonError(w, http.StatusBadRequest, "Text tidak boleh kosong")
		return
	}

	result, err := encrypt(req.Text)

	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Gagal encrypt")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: result,
	})
}

// =========================
// DECRYPT API
// =========================

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method harus POST")
		return
	}

	var req Request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	if req.Text == "" {
		jsonError(w, http.StatusBadRequest, "Ciphertext tidak boleh kosong")
		return
	}

	result, err := decrypt(req.Text)

	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: result,
	})
}

// =========================
// HASH API
// =========================

func hashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method harus POST")
		return
	}

	var req Request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	if req.Text == "" {
		jsonError(w, http.StatusBadRequest, "Password tidak boleh kosong")
		return
	}

	hash, err := hashPassword(req.Text)

	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Gagal hash password")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: hash,
	})
}

// =========================
// VERIFY API
// =========================

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "Method harus POST")
		return
	}

	var req VerifyRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}

	if req.Text == "" {
		jsonError(w, http.StatusBadRequest, "Password tidak boleh kosong")
		return
	}

	if req.Hash == "" {
		jsonError(w, http.StatusBadRequest, "Hash tidak boleh kosong")
		return
	}

	if verifyPassword(req.Text, req.Hash) {
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(Response{
			Result: "Password cocok",
		})

		return
	}

	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(Response{
		Result: "Password tidak cocok",
	})
}

// =========================
// WEB UI
// =========================

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		jsonError(w, http.StatusNotFound, "Page tidak ditemukan")
		return
	}

	html := `
<!DOCTYPE html>
<html lang="id">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>App1 Security Tool</title>

<style>

* {
	box-sizing: border-box;
}

body {
	font-family: Arial, sans-serif;
	background: #f2f2f2;
	margin: 0;
	padding: 30px;
}

.container {
	max-width: 700px;
	margin: auto;
	background: white;
	padding: 30px;
	border-radius: 14px;
	box-shadow: 0 5px 25px rgba(0,0,0,0.15);
}

h1 {
	text-align: center;
	margin-top: 0;
}

h2 {
	margin-top: 30px;
	border-bottom: 1px solid #ddd;
	padding-bottom: 8px;
}

label {
	display: block;
	margin-top: 15px;
	margin-bottom: 6px;
	font-weight: bold;
}

textarea {
	width: 100%;
	min-height: 100px;
	padding: 12px;
	border: 1px solid #ccc;
	border-radius: 7px;
	font-family: monospace;
	resize: vertical;
}

button {
	padding: 10px 18px;
	margin-top: 12px;
	margin-right: 5px;
	border: none;
	border-radius: 7px;
	cursor: pointer;
	font-size: 14px;
}

button:hover {
	opacity: 0.8;
}

.encrypt {
	background: #222;
	color: white;
}

.decrypt {
	background: #555;
	color: white;
}

.hash {
	background: #333;
	color: white;
}

.verify {
	background: #777;
	color: white;
}

.result {
	background: #f7f7f7;
}

.status {
	margin-top: 12px;
	font-weight: bold;
}

.info {
	background: #f5f5f5;
	padding: 12px;
	border-radius: 7px;
	font-size: 14px;
	margin-top: 10px;
}

</style>

</head>

<body>

<div class="container">

<h1> App1 Security Tool</h1>

<div class="info">

<b>Encrypt / Decrypt</b><br>

AES encryption bisa diencrypt dan didecrypt kembali.

<br><br>

<b>Hash / Verify</b><br>

bcrypt adalah one-way hash dan tidak bisa didecrypt.

</div>

<!-- ===================== -->
<!-- AES -->
<!-- ===================== -->

<h2> AES Encrypt / Decrypt</h2>

<label>Input</label>

<textarea
id="aesInput"
placeholder="Masukkan text atau ciphertext..."
></textarea>

<button
class="encrypt"
onclick="aesEncrypt()"
>
Encrypt
</button>

<button
class="decrypt"
onclick="aesDecrypt()"
>
Decrypt
</button>

<label>Result</label>

<textarea
id="aesResult"
class="result"
readonly
></textarea>

<div
id="aesStatus"
class="status"
></div>


<!-- ===================== -->
<!-- BCRYPT -->
<!-- ===================== -->

<h2> bcrypt Password</h2>

<label>Password</label>

<textarea
id="passwordInput"
placeholder="Masukkan password..."
></textarea>

<button
class="hash"
onclick="hashPassword()"
>
Hash Password
</button>

<label>Hash</label>

<textarea
id="hashResult"
class="result"
placeholder="$2a$10$..."
></textarea>


<button
class="verify"
onclick="verifyPassword()"
>
Verify Password
</button>

<div
id="verifyStatus"
class="status"
></div>

</div>


<script>

// =========================
// AES
// =========================

async function aesProcess(endpoint) {

	const text =
		document.getElementById("aesInput").value;

	if (!text) {

		document.getElementById("aesStatus").innerText =
			"Input tidak boleh kosong.";

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
			throw new Error(data.error || "Request gagal");
		}

		document.getElementById("aesResult").value =
			data.result;

		document.getElementById("aesStatus").innerText =
			"Berhasil.";

	}

	catch(error) {

		document.getElementById("aesStatus").innerText =
			"Error: " + error.message;

	}

}


function aesEncrypt() {

	aesProcess("/encrypt");

}


function aesDecrypt() {

	aesProcess("/decrypt");

}


// =========================
// HASH
// =========================

async function hashPassword() {

	const password =
		document.getElementById("passwordInput").value;

	if (!password) {

		document.getElementById("verifyStatus").innerText =
			"Password tidak boleh kosong.";

		return;
	}

	try {

		const response = await fetch("/hash", {

			method: "POST",

			headers: {
				"Content-Type": "application/json"
			},

			body: JSON.stringify({
				text: password
			})

		});

		const data = await response.json();

		if (!response.ok) {
			throw new Error(data.error || "Hash gagal");
		}

		document.getElementById("hashResult").value =
			data.result;

		document.getElementById("verifyStatus").innerText =
			"Password berhasil di-hash.";

	}

	catch(error) {

		document.getElementById("verifyStatus").innerText =
			"Error: " + error.message;

	}

}


// =========================
// VERIFY
// =========================

async function verifyPassword() {

	const password =
		document.getElementById("passwordInput").value;

	const hash =
		document.getElementById("hashResult").value;

	if (!password) {

		document.getElementById("verifyStatus").innerText =
			"Password tidak boleh kosong.";

		return;
	}

	if (!hash) {

		document.getElementById("verifyStatus").innerText =
			"Hash tidak boleh kosong.";

		return;
	}

	try {

		const response = await fetch("/verify", {

			method: "POST",

			headers: {
				"Content-Type": "application/json"
			},

			body: JSON.stringify({

				text: password,

				hash: hash

			})

		});

		const data = await response.json();

		if (!response.ok) {
			throw new Error(data.error || "Verify gagal");
		}

		document.getElementById("verifyStatus").innerText =
			data.result;

	}

	catch(error) {

		document.getElementById("verifyStatus").innerText =
			"Error: " + error.message;

	}

}

</script>

</body>

</html>
`

	w.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)

	fmt.Fprint(w, html)
}

// =========================
// MAIN
// =========================

func main() {


	http.HandleFunc("/", homeHandler)

	http.HandleFunc("/encrypt", encryptHandler)

	http.HandleFunc("/decrypt", decryptHandler)

	http.HandleFunc("/hash", hashHandler)

	http.HandleFunc("/verify", verifyHandler)

	fmt.Println("App1 Security Tool running on port 9000")

	err := http.ListenAndServe(":9000", nil)

	if err != nil {
		fmt.Println("Server error:", err)
	}
}
