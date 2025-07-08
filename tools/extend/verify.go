package main

import (
	"flag"
	"bytes"
	"crypto"         
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"crypto/sha512"
	"os"
)

func WriteAtStart48Bytes(file *os.File, data []byte) error {
	if len(data) != 48 {
		return fmt.Errorf("error: data must be exactly 48 bytes in size, but got %d bytes", len(data))
	}

	_, err := file.WriteAt(data, 0)
	if err != nil {
		return fmt.Errorf("failed to write data at offset 0: %w", err)
	}

	return nil
}

func main() {	
	// Algorithm Definition
	
	const hashAlgo = crypto.SHA384
	const digestSize = sha512.Size384

	// Flags Definition
	idx := flag.Int("idx", 0, "index of rtmr")
	filePath := fmt.Sprintf("/sys/class/misc/tdx_guest/measurements/rtmr%d:sha384", *idx)
	fmt.Println(filePath)
	flag.Parse()

	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("Failed to open file '%s': %v\n", filePath, err)
		return
	}
	defer file.Close()

	fmt.Println("\n--- Looping 10 times with random value extensions, write and read back the digest for comparison---")
	
	for i := 0; i < 10; i++ {
		var oldDigest = sha512.New384()
		// Read Initial Digest
		initialData := make([]byte, digestSize)
		initialData, err := ioutil.ReadFile(filePath)
		if err != nil {
    			fmt.Printf("failed to read original digest from %s\n", filePath)
    			return
		}
		fmt.Printf("read back original digest: %s\n", hex.EncodeToString(initialData))
		_, err = oldDigest.Write(initialData)

		// Create Random Event Digest
		eventData := make([]byte, digestSize)
		if _, err := rand.Read(eventData); err != nil {
			fmt.Printf("Error generating random data: %v\n", err)
			return
		}

		fmt.Printf("\nExtension #%d:\n", i+1)
		fmt.Printf("  - Random Event Data (hex): %s\n", hex.EncodeToString(eventData))
		
		// Hardware Operation
		err = WriteAtStart48Bytes(file, eventData)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
 			return
    		}

		readDigest, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("failed to read back from %s for verification: %w\n", filePath, err)
			return
		}

		// Simulation Extension
		_, err = oldDigest.Write(eventData)
		currentHashValue := oldDigest.Sum(nil)

		// Verify
		fmt.Printf("expected value: %s\n", hex.EncodeToString(currentHashValue))
    		fmt.Printf("read back value: %s\n", hex.EncodeToString(readDigest))
		if !bytes.Equal(currentHashValue, readDigest) {
			fmt.Printf("verification failed: written and read digests do not match for %s\n", filePath)
			return
		}

		fmt.Printf("Successfully verified that the read digest matches the written digest for %s\n in test round %d\n", filePath, i)
	}
}
