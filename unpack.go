package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func unpack(paths []string, out string) error {
	return unpackWithPassword(paths, out, nil)
}

func unpackWithPassword(paths []string, out string, password []byte) (resultErr error) {
	parts, err := verifyParts(paths, false)
	if err != nil {
		return err
	}
	return unpackVerifiedParts(parts, out, password)
}

func unpackSelectorsWithPassword(selectors []string, out string, password []byte) error {
	return unpackSelectorsWithOptions(selectors, out, password, false)
}

func unpackSelectorsWithOptions(selectors []string, out string, password []byte, overwrite bool) error {
	packages, err := resolveUnpackPackages(selectors)
	if err != nil {
		return err
	}
	verified := make([][]verifiedPart, 0, len(packages))
	roots := make(map[string]int)
	var conflicts []string
	for _, pkg := range packages {
		parts, err := verifyParts(pkg.paths, false)
		if err != nil {
			return err
		}
		root := parts[0].m.SourceName
		roots[root]++
		if roots[root] == 2 {
			conflicts = append(conflicts, root)
		}
		verified = append(verified, parts)
	}
	if len(conflicts) > 0 && !overwrite {
		ok, err := confirmUnpackOverwrite(conflicts)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New(tr("unpack_overwrite_declined"))
		}
	}
	for _, parts := range verified {
		if err := unpackVerifiedParts(parts, out, password); err != nil {
			return err
		}
	}
	return nil
}

func confirmUnpackOverwrite(roots []string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf(tr("unpack_overwrite_nonterminal"), strings.Join(roots, ", "))
	}
	fmt.Fprintf(uiOutput, tr("unpack_overwrite_prompt"), strings.Join(roots, ", "))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "예", "네":
		return true, nil
	default:
		return false, nil
	}
}

func unpackVerifiedParts(parts []verifiedPart, out string, password []byte) (resultErr error) {
	tarFile, err := createWorkingTemp("sugyeol-restore-*.tar")
	if err != nil {
		return err
	}
	defer cleanupWorkingTemp(tarFile)
	var master []byte
	if parts[0].m.Encryption == encryptionName {
		if len(password) == 0 {
			password, err = readEncryptionPassword("", false)
			if err != nil {
				return err
			}
			defer clearBytes(password)
		}
		uiVerbosef("deriving package decryption key with Argon2id")
		master, err = deriveMasterKey(password, parts[0].m.KDFSalt, parts[0].m.KDFMemory, parts[0].m.KDFTime, parts[0].m.KDFParallelism)
		if err != nil {
			return err
		}
		defer clearBytes(master)
	}
	var total int64
	for _, p := range parts {
		if p.m.PayloadSize > 0 && total > (1<<63-1)-p.m.PayloadSize {
			return fmt.Errorf("package payload size overflow")
		}
		total += p.m.PayloadSize
	}
	restoreProgress := newProgress(tr("progress_restore"), total)
	defer func() { restoreProgress.Finish(resultErr) }()
	for _, p := range parts {
		if err := checkCanceled(); err != nil {
			return err
		}
		uiVerbosef("restoring part %d/%d: %s", p.m.Part, p.m.TotalParts, p.path)
		zr, payload, err := payloadReader(p.path)
		if err != nil {
			return err
		}
		nonce, _ := decodeNonce(p.m.Nonce)
		h := sha256.New()
		var n int64
		var copyErr error
		if p.m.Encryption == encryptionName {
			n, copyErr = decryptPayload(tarFile, payload, p.m, master, io.MultiWriter(h, restoreProgress))
		} else {
			var decoded io.Reader = payload
			if p.m.Scramble == "xor-sha256-counter-v1" {
				decoded = newXORReader(payload, p.m.SetID, p.m.Part, nonce)
			}
			n, copyErr = io.Copy(io.MultiWriter(tarFile, h, restoreProgress), decoded)
		}
		closeErr := payload.Close()
		zipCloseErr := zr.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if zipCloseErr != nil {
			return zipCloseErr
		}
		if n != p.m.PayloadSize || hex.EncodeToString(h.Sum(nil)) != p.m.PayloadSHA256 {
			return fmt.Errorf("파트 %d의 원본 payload SHA-256 불일치", p.m.Part)
		}
	}
	restoreProgress.Finish(nil)
	if _, err := tarFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	extractProgress := newProgress(tr("progress_extract"), total)
	extractErr := extractTar(extractProgress.Reader(tarFile), out)
	extractProgress.Finish(extractErr)
	if extractErr != nil {
		return extractErr
	}
	fmt.Printf(tr("restored"), parts[0].m.SourceName, out)
	return nil
}
