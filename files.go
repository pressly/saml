// MIT License
//
// Copyright (c) 2017 Pressly Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package saml

import (
	"crypto/sha1"
	"fmt"
	"os"
)

// WorkDir is a temporary directory for files. We need to write keys to disk in
// order for xmlsec1 to pick them and use them.
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
