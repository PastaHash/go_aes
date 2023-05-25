package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("Please choose: 1. Encrypt file 2. Decrypt file 3. Exit")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "1":
			fmt.Println("Enter the input file path:")
			scanner.Scan()
			inPath := scanner.Text()

			fmt.Println("Enter the output file path:")
			scanner.Scan()
			outPath := scanner.Text()

			fmt.Println("Enter the key:")
			scanner.Scan()
			key := scanner.Text()

			err := encryptFile(inPath, outPath, key)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println("File encryption successful!")

		case "2":
			fmt.Println("Enter the encrypted file path:")
			scanner.Scan()
			inPath := scanner.Text()

			fmt.Println("Enter the output file path:")
			scanner.Scan()
			outPath := scanner.Text()

			fmt.Println("Enter the key:")
			scanner.Scan()
			key := scanner.Text()

			err := decryptFile(inPath, outPath, key)
			if err != nil {
				fmt.Println(err)
				continue
			}

			fmt.Println("File decryption successful!")

		case "3":
			fmt.Println("Exiting...")
			return

		default:
			fmt.Println("Invalid option. Please choose 1, 2, or 3.")
		}
	}
}

func encryptFile(inPath string, outPath string, key string) error {
	data, err := ioutil.ReadFile(inPath)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(string(data), key)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(outPath, []byte(ciphertext), 0644)
	if err != nil {
		return err
	}

	return nil
}

func decryptFile(inPath string, outPath string, key string) error {
	data, err := ioutil.ReadFile(inPath)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(string(data), key)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(outPath, []byte(plaintext), 0644)
	if err != nil {
		return err
	}

	return nil
}

func encrypt(plaintext string, key string) (string, error) {
	block, _ := aes.NewCipher(generateKey(key))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(ciphertext string, key string) (string, error) {
	cipherdata, _ := base64.StdEncoding.DecodeString(ciphertext)
	block, _ := aes.NewCipher(generateKey(key))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(cipherdata) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherdata := cipherdata[:nonceSize], cipherdata[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherdata, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func generateKey(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}
