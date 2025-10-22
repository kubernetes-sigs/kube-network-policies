package dataplane

import (
	"encoding/hex"
	"testing"
)

func TestGenerateLabelMask(t *testing.T) {
	// The expected results are derived from the nftables debug output,
	// serialized as a 16-byte Big-Endian array (MSW first, LSW last).
	tests := []struct {
		name     string
		bitIndex int
		expected string // Expected 16-byte hex string
	}{
		{
			name:     "Bit 10 (LSW)",
			bitIndex: 10,
			// Bit 10 is 2^10 = 0x400. This is in the LSW (last 8 bytes).
			expected: "00000000000000000000000000000400",
		},
		{
			name:     "Bit 126 (MSW)",
			bitIndex: 126,
			// Bit 126 is 2^62 within the 64-bit MSW (first 8 bytes). 0x4000000000000000
			expected: "40000000000000000000000000000000",
		},
		{
			name:     "Bit 127 (MSW)",
			bitIndex: 127,
			// Bit 127 is 2^63 within the 64-bit MSW (first 8 bytes). 0x8000000000000000
			expected: "80000000000000000000000000000000",
		},
		{
			name:     "Bit 0 (LSW Start)",
			bitIndex: 0,
			// 2^0 = 0x1. In the LSW (last byte).
			expected: "00000000000000000000000000000001",
		},
		{
			name:     "Bit 63 (LSW End)",
			bitIndex: 63,
			// 2^63 = 0x8000000000000000. In the LSW (last 8 bytes).
			expected: "00000000000000008000000000000000",
		},
		{
			name:     "Bit 64 (MSW Start)",
			bitIndex: 64,
			// 2^0 (within the MSW). In the MSW (first 8 bytes).
			expected: "00000000000000010000000000000000",
		},
		{
			name:     "Out of Range (128)",
			bitIndex: 128,
			// Expected 16 zero bytes: "00...00"
			expected: "00000000000000000000000000000000",
		},
		{
			name:     "Out of Range (-1)",
			bitIndex: -1,
			// Expected 16 zero bytes: "00...00"
			expected: "00000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function
			result := generateLabelMask(tt.bitIndex)

			// Convert result to hex string for easy comparison
			actualHex := hex.EncodeToString(result)

			// Compare the actual result with the expected hex string
			if actualHex != tt.expected {
				t.Errorf("generateLabelMask() for index %d:\n Got:  %v\n Want: %v", tt.bitIndex, actualHex, tt.expected)
			}
		})
	}
}

// TestClearLabelBit tests the clearLabelBit function across various scenarios.
func TestClearLabelBit(t *testing.T) {
	// Helper function to convert a hex string to a byte slice
	mustDecodeHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}

	// A base label with bits 10, 63, 64, and 127 set.
	// Bit 127 (MSW: 0x8000000000000000)
	// Bit 64 (MSW: 0x0000000000000001)
	// Bit 63 (LSW: 0x8000000000000000)
	// Bit 10 (LSW: 0x0000000000000400)
	// Base Hex: 80000000000000018000000000000400
	baseLabelHex := "80000000000000018000000000000400"
	baseLabel := mustDecodeHex(baseLabelHex)

	tests := []struct {
		name         string
		initialLabel []byte
		bitIndex     int
		expectedHex  string
		expectChange bool // Used to verify if the original array remains untouched
	}{
		{
			name:         "Clear Bit 10 (LSW Middle)",
			initialLabel: baseLabel,
			bitIndex:     10,
			// Expected: Bit 10 (0x400) cleared -> 8000...018000...0000
			expectedHex:  "80000000000000018000000000000000",
			expectChange: true,
		},
		{
			name:         "Clear Bit 127 (MSW End)",
			initialLabel: baseLabel,
			bitIndex:     127,
			// Expected: Bit 127 (0x80...) cleared -> 0000...018000...0400
			expectedHex:  "00000000000000018000000000000400",
			expectChange: true,
		},
		{
			name:         "Clear Bit 63 (LSW End Boundary)",
			initialLabel: baseLabel,
			bitIndex:     63,
			// Expected: Bit 63 (0x80...) cleared -> 8000...010000...0400
			expectedHex:  "80000000000000010000000000000400",
			expectChange: true,
		},
		{
			name:         "Clear Bit 64 (MSW Start Boundary)",
			initialLabel: baseLabel,
			bitIndex:     64,
			// Expected: Bit 64 (0x01) cleared -> 8000...008000...0400
			expectedHex:  "80000000000000008000000000000400",
			expectChange: true,
		},
		{
			name:         "Clear Bit 0 (LSW Start Boundary)",
			initialLabel: mustDecodeHex("00000000000000000000000000000001"), // Only bit 0 set
			bitIndex:     0,
			// Expected: All zeros
			expectedHex:  "00000000000000000000000000000000",
			expectChange: true,
		},
		{
			name:         "Clear Bit Already Zero (Bit 50)",
			initialLabel: baseLabel,
			bitIndex:     50, // Bit 50 is zero in the base label
			expectedHex:  baseLabelHex,
			expectChange: true, // A copy is still returned, but the content is the same
		},
		{
			name:         "Out of Range (128)",
			initialLabel: baseLabel,
			bitIndex:     128,
			expectedHex:  baseLabelHex,
			expectChange: true, // A copy is still returned, but the content is the same
		},
		{
			name:         "Out of Range (-1)",
			initialLabel: baseLabel,
			bitIndex:     -1,
			expectedHex:  baseLabelHex,
			expectChange: true, // A copy is still returned, but the content is the same
		},
		{
			name:         "Invalid Length (10 bytes)",
			initialLabel: mustDecodeHex("F0F0F0F0F0"), // Only 5 bytes
			bitIndex:     10,
			expectedHex:  "00000000000000000000000000000000", // Should return 16 zero bytes
			expectChange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the original hex string for verification
			originalHex := hex.EncodeToString(tt.initialLabel)

			// Execute the function
			result := clearLabelBit(tt.initialLabel, tt.bitIndex)

			actualHex := hex.EncodeToString(result)
			if actualHex != tt.expectedHex {
				t.Errorf("Result Mismatch for index %d:\n Got:  %s\n Want: %s", tt.bitIndex, actualHex, tt.expectedHex)
			}

			if len(tt.initialLabel) == 16 && originalHex != hex.EncodeToString(tt.initialLabel) {
				t.Errorf("Original array was modified!\n Initial: %s\n After call: %s", originalHex, hex.EncodeToString(tt.initialLabel))
			}
		})
	}
}
