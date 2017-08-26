package saml

import (
	"crypto/sha1"
	"fmt"
	"os"
)

// WorkDir is a temporary directory for files.
var WorkDir = "/tmp"

func writeFile(buf []byte) (string, error) {
	destDir := WorkDir

	if err := os.MkdirAll(destDir, 0700); err != nil {
		return "", err
	}

	hash := sha1.Sum(buf)
	fileName := destDir + "/" + fmt.Sprintf("%x.tmp", hash)

	if stat, err := os.Stat(fileName); err == nil {
		if !stat.IsDir() {
			// Path exists and is a file.
			return fileName, nil
		}
	}

	fp, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer fp.Close()

	if _, err := fp.Write(buf); err != nil {
		return "", err
	}

	return fileName, nil
}
