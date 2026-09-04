package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var version = "1.5.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	commandContext = ctx
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore the default handler so a second Ctrl+C can force termination.
		stop()
	}()
	startUpdateRefresh(os.Args[1:])
	defer maybeNotifyUpdate(os.Args[1:])
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, tr("canceled"))
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "sugyeol:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var err error
	for {
		before := len(args)
		args = parseLanguageArg(args)
		args, err = parseGlobalUIArgs(args)
		if err != nil {
			return err
		}
		if len(args) == before {
			break
		}
	}
	if len(args) == 0 {
		usage()
		return errors.New(tr("command_required"))
	}
	uiDebugf("version=%s command=%s progress=%s", version, args[0], ui.mode.String())
	switch args[0] {
	case "pack":
		fs := flag.NewFlagSet("pack", flag.ContinueOnError)
		sizeWasSet := packSizeFlagSpecified(args[1:])
		partsWasSet := packPartsFlagSpecified(args[1:])
		sizeText := fs.String("size", "100", tr("size_help"))
		partsCount := fs.Int("parts", 0, tr("parts_help"))
		out := fs.String("out", "package", tr("out_help"))
		scramble := fs.Bool("scramble", true, tr("scramble_help"))
		compressionText := fs.String("compression", "none", tr("compression_help"))
		encrypt := fs.Bool("encrypt", false, "encrypt payloads with a password (overrides scrambling)")
		passwordFile := fs.String("password-file", "", "read encryption password from a 0600 file")
		passwordText := fs.String("password", "", "encryption password (may be exposed in process listings and shell history)")
		fs.StringVar(sizeText, "s", "100", tr("size_help"))
		fs.IntVar(partsCount, "n", 0, tr("parts_help"))
		fs.StringVar(out, "o", "package", tr("out_help"))
		fs.BoolVar(scramble, "x", true, tr("scramble_help"))
		fs.StringVar(compressionText, "c", "none", tr("compression_help"))
		fs.BoolVar(encrypt, "e", false, "encrypt payloads with a password (overrides scrambling)")
		fs.StringVar(passwordFile, "p", "", "read encryption password from a 0600 file")
		fs.StringVar(passwordText, "P", "", "encryption password (may be exposed in process listings and shell history)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New(tr("pack_usage"))
		}
		uiDebugf("pack source=%q output=%q size=%q parts=%d scramble=%t compression=%q encrypted=%t", fs.Arg(0), *out, *sizeText, *partsCount, *scramble, *compressionText, *encrypt)
		if partsWasSet && (*partsCount < 1 || *partsCount > 100000) {
			return errors.New("-parts must be between 1 and 100000")
		}
		if *partsCount > 0 && sizeWasSet {
			return errors.New("-size and -parts are mutually exclusive")
		}
		sz, err := parseSize(*sizeText)
		if err != nil {
			return err
		}
		compression, err := parseCompression(*compressionText)
		if err != nil {
			return err
		}
		if *encrypt {
			if *passwordText != "" && *passwordFile != "" {
				return errors.New("-password and -password-file are mutually exclusive")
			}
			var password []byte
			if *passwordText != "" {
				password, err = passwordBytes(*passwordText)
			} else {
				password, err = readEncryptionPassword(*passwordFile, true)
			}
			if err != nil {
				return err
			}
			defer clearBytes(password)
			return packWithOptionsAndParts(fs.Arg(0), *out, sz, false, password, compression, *partsCount)
		}
		if *passwordFile != "" || *passwordText != "" {
			return errors.New("-password and -password-file require -encrypt")
		}
		return packWithOptionsAndParts(fs.Arg(0), *out, sz, *scramble, nil, compression, *partsCount)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		source := fs.String("source", "", "source file/directory for a detached signature")
		var pubkeys stringList
		fs.Var(&pubkeys, "pubkey", "trusted public key PEM path or hex key (repeatable)")
		minSignatures := fs.Int("min-signatures", 1, "minimum valid signatures required for detached metadata")
		fs.StringVar(source, "s", "", "source file/directory for a detached signature")
		fs.Var(&pubkeys, "k", "trusted public key PEM path or hex key (repeatable)")
		fs.IntVar(minSignatures, "n", 1, "minimum valid signatures required for detached metadata")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New(tr("verify_files"))
		}
		uiDebugf("verify inputs=%d detached=%t trusted_keys=%d minimum=%d", fs.NArg(), *source != "" || (fs.NArg() == 1 && strings.HasSuffix(fs.Arg(0), ".meta")), len(pubkeys), *minSignatures)
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
		if err := printPackageVerification(os.Stdout, parts, len(pubkeys) > 0); err != nil {
			return err
		}
		if len(pubkeys) == 0 {
			fmt.Fprintln(os.Stderr, tr("unpinned_warning"))
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
		fs.StringVar(source, "s", "", "source file/directory")
		fs.Var(&pubkeys, "k", "trusted public key PEM path or hex key (repeatable)")
		fs.IntVar(minSignatures, "n", 1, "minimum valid signatures")
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
		passwordText := fs.String("password", "", "decryption password (may be exposed in process listings and shell history)")
		fs.StringVar(out, "o", ".", tr("restore_help"))
		fs.StringVar(passwordFile, "p", "", "read decryption password from a 0600 file")
		fs.StringVar(passwordText, "P", "", "decryption password (may be exposed in process listings and shell history)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New(tr("unpack_files"))
		}
		uiDebugf("unpack parts=%d output=%q password_source=%s", fs.NArg(), *out, func() string {
			if *passwordText != "" {
				return "argument"
			}
			if *passwordFile != "" {
				return "file"
			}
			return "prompt-if-required"
		}())
		var password []byte
		var err error
		if *passwordText != "" && *passwordFile != "" {
			return errors.New("-password and -password-file are mutually exclusive")
		}
		if *passwordText != "" {
			password, err = passwordBytes(*passwordText)
		} else if *passwordFile != "" {
			password, err = readEncryptionPassword(*passwordFile, false)
		}
		if err != nil {
			return err
		}
		if len(password) > 0 {
			defer clearBytes(password)
		}
		return unpackSelectorsWithPassword(fs.Args(), *out, password)
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

func packSizeFlagSpecified(args []string) bool {
	for _, arg := range args {
		if arg == "-s" || arg == "--size" || arg == "-size" || strings.HasPrefix(arg, "-s=") || strings.HasPrefix(arg, "--size=") || strings.HasPrefix(arg, "-size=") {
			return true
		}
	}
	return false
}

func packPartsFlagSpecified(args []string) bool {
	for _, arg := range args {
		if arg == "-n" || arg == "--parts" || arg == "-parts" || strings.HasPrefix(arg, "-n=") || strings.HasPrefix(arg, "--parts=") || strings.HasPrefix(arg, "-parts=") {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintln(os.Stderr, tr("usage"))
}
