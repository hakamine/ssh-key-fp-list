package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func main() {
	keysGlob := flag.String("keysglob", "", "glob pattern to look for public keys (e.g. /some/dir/*.pub) (quote to avoid shell expansion")
	outFileName := flag.String("o", "", "file to write output to (if omitted will print to stdout")
	flag.Parse()

	log.Printf("Looking for keys in: %s\n", *keysGlob)

	// Get list of files to be parsed for keys
	matches, err := filepath.Glob(*keysGlob)
	if err != nil {
		log.Fatal(err)
	}

	// Open file for output
	var fd *os.File
	if *outFileName == "" {
		log.Printf("Output to stdout\n")
		fd = os.Stdout
	} else {
		log.Printf("Output to file: %s\n", *outFileName)
		fd, err = os.Create(*outFileName)
		if err != nil {
			log.Fatal(err)
		}

	}

	for _, kf := range matches {
		// log.Printf("Parsing file: %s\n", kf)

		data, err := os.ReadFile(kf)
		if err != nil {
			log.Printf("Error reading: %s. Skipping...", kf)
			continue
		}

		// Parse the key and comment, other info ignored
		pk, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			log.Printf("Error parsing key in: %s. Skipping...", kf)
			continue
		}

		// Get the fingerprint
		fp := ssh.FingerprintSHA256(pk)

		// output key information
		keyInfoStr := fmt.Sprintf("%s,%s\n", comment, fp)
		_, err = fd.WriteString(keyInfoStr)
		if err != nil {
			log.Fatal(err)
		}

	}

}
