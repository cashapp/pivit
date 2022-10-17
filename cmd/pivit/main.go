package main

import (
	"fmt"
	"os"

	"github.com/pborman/getopt/v2"
	"github.com/pkg/errors"
)

func main() {
	if err := runCommand(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCommand() error {
	helpFlag := getopt.BoolLong("help", 'h', "print this help message")
	signFlag := getopt.BoolLong("sign", 's', "make a signature")
	verifyFlag := getopt.BoolLong("verify", 0, "verify a signature")
	resetFlag := getopt.BoolLong("reset", 'r', "resets the smart card PIV applet and sets new PIN, random PUK, and PIN derived management key")
	generateFlag := getopt.BoolLong("generate", 'g', "generates a new key pair and a certificate signing request")
	attestCodeSign := getopt.BoolLong("codesign", 'c', "generates a new key pair and a certificate signing request for a code signing certificate")
	importFlag := getopt.BoolLong("import", 'i', "imports a certificate to the PIV applet")
	printFlag := getopt.BoolLong("print", 'p', "prints the certificate and its fingerprint")

	localUserOpt := getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag := getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag := getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt := getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	tsaOpt := getopt.StringLong("timestamp-authority", 't', "", "URL of RFC3161 timestamp authority to use for timestamping", "url")

	certFileOpt := getopt.StringLong("cert-file", 0, "", "certificate file")

	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs := getopt.Args()

	if *helpFlag {
		getopt.Usage()
		return nil
	}

	if *signFlag {
		if *verifyFlag || *generateFlag || *resetFlag || *importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		}
		return commandSign(*statusFdOpt, *detachSignFlag, *armorFlag, *localUserOpt, *tsaOpt, fileArgs)
	}

	if *verifyFlag {
		if *signFlag || *generateFlag || *resetFlag || *importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for verification")
		}
		return commandVerify(fileArgs)
	}

	if *resetFlag {
		if *signFlag || *verifyFlag || *generateFlag || *importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandReset()
	}

	if *generateFlag {
		if *signFlag || *verifyFlag || *resetFlag || *importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandGenerate()
	}

	if *attestCodeSign {
		if *signFlag || *verifyFlag || *resetFlag || *importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandGenerate("codesign")
	}

	if *importFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandImport(*certFileOpt)
	}

	if *printFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || *importFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandPrint()
	}

	return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
}
