package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "1.0.0"

func main() {
	startUpdateRefresh(os.Args[1:])
	defer maybeNotifyUpdate(os.Args[1:])
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sugyeol:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	args = parseLanguageArg(args)
	if len(args) == 0 {
		usage()
		return errors.New(tr("command_required"))
	}
	switch args[0] {
	case "pack":
		fs := flag.NewFlagSet("pack", flag.ContinueOnError)
		sizeText := fs.String("size", "100", tr("size_help"))
		out := fs.String("out", "package", tr("out_help"))
		scramble := fs.Bool("scramble", true, tr("scramble_help"))
		encrypt := fs.Bool("encrypt", false, "encrypt payloads with a password (overrides scrambling)")
		passwordFile := fs.String("password-file", "", "read encryption password from a 0600 file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New(tr("pack_usage"))
		}
		sz, err := parseSize(*sizeText)
		if err != nil {
			return err
		}
		if *encrypt {
			password, err := readEncryptionPassword(*passwordFile, true)
			if err != nil {
				return err
			}
			defer clearBytes(password)
			return packWithPassword(fs.Arg(0), *out, sz, false, password)
		}
		if *passwordFile != "" {
			return errors.New("-password-file requires -encrypt")
		}
		return pack(fs.Arg(0), *out, sz, *scramble)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		source := fs.String("source", "", "source file/directory for a detached signature")
		var pubkeys stringList
		fs.Var(&pubkeys, "pubkey", "trusted public key PEM path or hex key (repeatable)")
		minSignatures := fs.Int("min-signatures", 1, "minimum valid signatures required for detached metadata")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New(tr("verify_files"))
		}
		if *source != "" || (fs.NArg() == 1 && strings.HasSuffix(fs.Arg(0), ".meta")) {
			if fs.NArg() != 1 {
				return errors.New("detached signature verification requires exactly one .meta file")
			}
			return verifyDetached(fs.Arg(0), *source, pubkeys, *minSignatures)
		}
		parts, err := verifyParts(fs.Args(), true)
		if err != nil {
			return err
		}
		for _, pubkey := range pubkeys {
			if err := verifyPinnedPartKey(parts, pubkey); err != nil {
				return err
			}
		}
		return nil
	case "sign":
		return signCommand(args[1:])
	case "countersign", "endorse", "co-sign", "cosign":
		return countersignCommand(args[1:])
	case "key":
		return keyCommand(args[1:])
	case "image", "container":
		return imageCommand(args[1:])
	case "verify-signature", "verify-sig":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		source := fs.String("source", "", "source file/directory")
		var pubkeys stringList
		fs.Var(&pubkeys, "pubkey", "trusted public key PEM path or hex key (repeatable)")
		minSignatures := fs.Int("min-signatures", 1, "minimum valid signatures")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("specify one .meta file")
		}
		return verifyDetached(fs.Arg(0), *source, pubkeys, *minSignatures)
	case "unpack", "restore":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		out := fs.String("out", ".", tr("restore_help"))
		passwordFile := fs.String("password-file", "", "read decryption password from a 0600 file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New(tr("unpack_files"))
		}
		var password []byte
		var err error
		if *passwordFile != "" {
			password, err = readEncryptionPassword(*passwordFile, false)
			if err != nil {
				return err
			}
			defer clearBytes(password)
		}
		return unpackWithPassword(fs.Args(), *out, password)
	case "version", "--version", "-version":
		fmt.Println("sugyeol", version)
		return nil
	case "update", "self-update":
		return updateCommand(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf(tr("unknown_command"), args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, tr("usage"))
}
