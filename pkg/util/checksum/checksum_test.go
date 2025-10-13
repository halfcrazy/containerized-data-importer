/*
Copyright 2026 The CDI Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package checksum

import (
	"testing"
)

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name        string
		checksumStr string
		wantErr     bool
	}{
		// Valid cases
		{
			name:        "valid sha256",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:     false,
		},
		{
			name:        "valid sha256 uppercase",
			checksumStr: "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			wantErr:     false,
		},
		{
			name:        "valid md5",
			checksumStr: "md5:d41d8cd98f00b204e9800998ecf8427e",
			wantErr:     false,
		},
		{
			name:        "valid sha1",
			checksumStr: "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709",
			wantErr:     false,
		},
		{
			name:        "valid sha512",
			checksumStr: "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			wantErr:     false,
		},
		{
			name:        "empty string",
			checksumStr: "",
			wantErr:     false,
		},
		// Invalid cases
		{
			name:        "invalid format - no colon",
			checksumStr: "sha256e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:     true,
		},
		{
			name:        "unsupported algorithm",
			checksumStr: "crc32:12345678",
			wantErr:     true,
		},
		{
			name:        "invalid sha256 length - too short",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
			wantErr:     true,
		},
		{
			name:        "invalid sha256 length - too long",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8551",
			wantErr:     true,
		},
		{
			name:        "invalid hex characters",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g",
			wantErr:     true,
		},
		{
			name:        "empty hash value",
			checksumStr: "sha256:",
			wantErr:     true,
		},
		{
			name:        "only algorithm",
			checksumStr: "sha256",
			wantErr:     true,
		},
		{
			name:        "multiple colons - non-hex character",
			checksumStr: "sha256:abc:123",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFormat(tt.checksumStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFormat() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAndValidate(t *testing.T) {
	tests := []struct {
		name          string
		checksumStr   string
		wantAlgorithm string
		wantHash      string
		wantErr       bool
	}{
		{
			name:          "valid sha256",
			checksumStr:   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantAlgorithm: "sha256",
			wantHash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:       false,
		},
		{
			name:          "valid sha256 uppercase converted to lowercase",
			checksumStr:   "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			wantAlgorithm: "sha256",
			wantHash:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:       false,
		},
		{
			name:          "valid md5",
			checksumStr:   "md5:d41d8cd98f00b204e9800998ecf8427e",
			wantAlgorithm: "md5",
			wantHash:      "d41d8cd98f00b204e9800998ecf8427e",
			wantErr:       false,
		},
		{
			name:        "invalid format",
			checksumStr: "sha256",
			wantErr:     true,
		},
		{
			name:        "unsupported algorithm",
			checksumStr: "sha384:abc123",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm, hash, err := ParseAndValidate(tt.checksumStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAndValidate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if algorithm != tt.wantAlgorithm {
					t.Errorf("ParseAndValidate() algorithm = %v, want %v", algorithm, tt.wantAlgorithm)
				}
				if hash != tt.wantHash {
					t.Errorf("ParseAndValidate() hash = %v, want %v", hash, tt.wantHash)
				}
			}
		})
	}
}
