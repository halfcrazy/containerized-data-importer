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

package importer

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNewChecksumValidator(t *testing.T) {
	tests := []struct {
		name        string
		checksumStr string
		wantErr     bool
		wantAlgo    string
	}{
		{
			name:        "valid SHA256",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:     false,
			wantAlgo:    "sha256",
		},
		{
			name:        "valid MD5",
			checksumStr: "md5:d41d8cd98f00b204e9800998ecf8427e",
			wantErr:     false,
			wantAlgo:    "md5",
		},
		{
			name:        "valid SHA512",
			checksumStr: "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			wantErr:     false,
			wantAlgo:    "sha512",
		},
		{
			name:        "empty string returns nil",
			checksumStr: "",
			wantErr:     false,
			wantAlgo:    "",
		},
		{
			name:        "invalid format - no colon",
			checksumStr: "sha256abc123",
			wantErr:     true,
		},
		{
			name:        "invalid format - multiple colons (non-hex character)",
			checksumStr: "sha256:abc:123",
			wantErr:     true, // Hash part "abc:123" contains invalid character ':'
		},
		{
			name:        "unsupported algorithm",
			checksumStr: "crc32:abc123",
			wantErr:     true,
		},
		{
			name:        "empty hash value",
			checksumStr: "sha256:",
			wantErr:     true,
		},
		{
			name:        "case insensitive algorithm",
			checksumStr: "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			wantErr:     false,
			wantAlgo:    "sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewChecksumValidator(tt.checksumStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewChecksumValidator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checksumStr != "" {
				if validator == nil {
					t.Error("NewChecksumValidator() returned nil validator")
					return
				}
				if validator.GetAlgorithm() != tt.wantAlgo {
					t.Errorf("GetAlgorithm() = %v, want %v", validator.GetAlgorithm(), tt.wantAlgo)
				}
			}
		})
	}
}

func TestChecksumValidation(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		checksumStr string
		wantErr     bool
	}{
		{
			name:        "valid SHA256 - empty string",
			data:        "",
			checksumStr: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr:     false,
		},
		{
			name:        "valid MD5 - empty string",
			data:        "",
			checksumStr: "md5:d41d8cd98f00b204e9800998ecf8427e",
			wantErr:     false,
		},
		{
			name:        "valid SHA256 - hello world",
			data:        "hello world",
			checksumStr: "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErr:     false,
		},
		{
			name:        "invalid SHA256 - wrong hash",
			data:        "hello world",
			checksumStr: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			wantErr:     true,
		},
		{
			name:        "valid MD5 - hello world",
			data:        "hello world",
			checksumStr: "md5:5eb63bbbe01eeed093cb22bb8f5acdc3",
			wantErr:     false,
		},
		{
			name:        "no checksum specified",
			data:        "hello world",
			checksumStr: "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewChecksumValidator(tt.checksumStr)
			if err != nil {
				t.Fatalf("NewChecksumValidator() error = %v", err)
			}

			if validator != nil {
				reader := validator.GetReader(strings.NewReader(tt.data))
				// Read all data
				_, err = io.Copy(io.Discard, reader)
				if err != nil {
					t.Fatalf("Failed to read data: %v", err)
				}

				err = validator.Validate()
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetReader(t *testing.T) {
	t.Run("nil validator returns original reader", func(t *testing.T) {
		var validator *ChecksumValidator
		reader := strings.NewReader("test data")
		result := validator.GetReader(reader)
		if result != reader {
			t.Error("GetReader() should return original reader when validator is nil")
		}
	})

	t.Run("non-nil validator returns TeeReader", func(t *testing.T) {
		validator, err := NewChecksumValidator("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
		if err != nil {
			t.Fatalf("NewChecksumValidator() error = %v", err)
		}
		reader := strings.NewReader("hello world")
		result := validator.GetReader(reader)
		if result == reader {
			t.Error("GetReader() should return a different reader (TeeReader) when validator is non-nil")
		}
	})
}

func TestErrChecksumMismatch(t *testing.T) {
	t.Run("errors.Is should detect ErrChecksumMismatch", func(t *testing.T) {
		// Create validator with wrong checksum
		validator, err := NewChecksumValidator("sha256:0000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			t.Fatalf("NewChecksumValidator() error = %v", err)
		}

		// Read some data
		reader := validator.GetReader(strings.NewReader("hello world"))
		_, err = io.Copy(io.Discard, reader)
		if err != nil {
			t.Fatalf("Failed to read data: %v", err)
		}

		// Validate should return ErrChecksumMismatch
		err = validator.Validate()
		if err == nil {
			t.Fatal("Validate() should return error for mismatched checksum")
		}

		if !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("errors.Is(err, ErrChecksumMismatch) = false, want true; err = %v", err)
		}

		// The error message should contain details
		if !strings.Contains(err.Error(), "expected sha256:") {
			t.Errorf("error message should contain expected checksum; got: %v", err)
		}
	})
}
