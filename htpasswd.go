package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"io"
	"log"
	"os"
)

// lookup passwords in a htpasswd file
// The entries must have been created with -s for SHA encryption

// HtpasswdFile a struct representing the contents of the htpasswd file
type HtpasswdFile struct {
	Users map[string]string
}

// NewHtpasswdFromFile placeholder comment
func NewHtpasswdFromFile(path string) (*HtpasswdFile, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return NewHtpasswd(r)
}

// NewHtpasswd function to generate new htpasswd struct from a file
func NewHtpasswd(file io.Reader) (*HtpasswdFile, error) {
	csvReader := csv.NewReader(file)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	h := &HtpasswdFile{Users: make(map[string]string)}
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
	return h, nil
}

// Validate placeholder comment
func (h *HtpasswdFile) Validate(user string, password string) bool {
	realPassword, exists := h.Users[user]
	if !exists {
		return false
	}
	if realPassword[:5] == "{SHA}" {
		d := sha1.New()
		d.Write([]byte(password))
		if realPassword[5:] == base64.StdEncoding.EncodeToString(d.Sum(nil)) {
			return true
		}
	} else {
		log.Printf("Invalid htpasswd entry for %s. Must be a SHA entry.", user)
	}
	return false
}
