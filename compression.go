package main

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"strconv"
	"strings"
)

type compressionConfig struct {
	method uint16
	level  int
}

func parseCompression(value string) (compressionConfig, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none", "no", "off", "store", "0":
		return compressionConfig{method: zip.Store}, nil
	case "fastest", "fast":
		return compressionConfig{method: zip.Deflate, level: flate.BestSpeed}, nil
	case "default", "normal":
		return compressionConfig{method: zip.Deflate, level: flate.DefaultCompression}, nil
	case "highest", "best", "maximum", "max":
		return compressionConfig{method: zip.Deflate, level: flate.BestCompression}, nil
	default:
		level, err := strconv.Atoi(value)
		if err != nil || level < flate.BestSpeed || level > flate.BestCompression {
			return compressionConfig{}, fmt.Errorf("compression must be none, fastest, default, highest, or a level from 0 to 9")
		}
		return compressionConfig{method: zip.Deflate, level: level}, nil
	}
}

func manifestCompression(m manifest) (compressionConfig, error) {
	if m.Compression == "" || m.Compression == "none" {
		if m.CompressionLevel != 0 {
			return compressionConfig{}, fmt.Errorf("invalid ZIP compression level")
		}
		return compressionConfig{method: zip.Store}, nil
	}
	if m.Compression != "deflate" || (m.CompressionLevel != flate.DefaultCompression && (m.CompressionLevel < flate.BestSpeed || m.CompressionLevel > flate.BestCompression)) {
		return compressionConfig{}, fmt.Errorf("unsupported ZIP compression configuration")
	}
	return compressionConfig{method: zip.Deflate, level: m.CompressionLevel}, nil
}

func (c compressionConfig) apply(m *manifest) {
	if c.method == zip.Deflate {
		m.Compression = "deflate"
		m.CompressionLevel = c.level
	}
}

func compressedPayloadUpperBound(size int64, c compressionConfig) int64 {
	if c.method == zip.Store {
		return size
	}
	// DEFLATE may expand incompressible input. Five bytes per 16 KiB block is
	// deliberately more conservative than the format's 65,535-byte block cap.
	return size + ((size+16*1024-1)/(16*1024))*5 + 64
}

func packagePayloadCapacity(maxSize int64, encrypted bool, c compressionConfig) int64 {
	available := maxSize - metadataReserve
	if available <= 0 {
		return 0
	}
	lo, hi := int64(0), available
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		stored := mid
		if encrypted {
			stored = encryptedStoredSize(mid)
		}
		if compressedPayloadUpperBound(stored, c) <= available {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}
