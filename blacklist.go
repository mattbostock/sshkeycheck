package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const blacklistPath = "blacklist"

var blacklist = make(map[string]bool)

func loadBlacklistedKeys() {
	files, err := ioutil.ReadDir(blacklistPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			log.Fatalf("Subdirectories not supported in %q directory\n", blacklistPath)
		}

		file, err := os.Open(filepath.Join(blacklistPath, f.Name()))
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key := strings.TrimSpace(scanner.Text())
			blacklist[key] = true
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	return
}

func markBlacklistedKeys(keys []*publicKey) {

	for _, k := range keys {
		key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.key)))
		if blacklist[key] {
			k.blacklisted = true
		}
	}

	return
}
