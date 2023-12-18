package main

import (
	"fmt"
	"os"

	"github.com/go-piv/piv-go/piv"

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
	slot := getopt.StringLong("slot", 'w', "9e", "choose 4 available PIV slots, defaults to PIV slot 9e", "slot")
	importOpt := getopt.StringLong("import", 'i', "", "imports a certificate to the PIV applet", "file")
	printFlag := getopt.BoolLong("print", 'p', "prints the certificate and its fingerprint")

	localUserOpt := getopt.StringLong("local-user", 'u', "", "use USER-ID to sign", "USER-ID")
	detachSignFlag := getopt.BoolLong("detach-sign", 'b', "make a detached signature")
	armorFlag := getopt.BoolLong("armor", 'a', "create ascii armored output")
	statusFdOpt := getopt.IntLong("status-fd", 0, -1, "write special status strings to the file descriptor n.", "n")
	firstOpt := getopt.BoolLong("first-pem", 0, "imports the first PEM block found when importing, ignoring the rest of the imported file")
	tsaOpt := getopt.StringLong("timestamp-authority", 't', "", "URL of RFC3161 timestamp authority to use for timestamping", "url")
	p256Flag := getopt.BoolLong("p256", 0, "use P-256 elliptic curve for key pair generation. If missing, P-384 is used")
	selfSignFlag := getopt.BoolLong("self-sign", 0, "generate a self-signed certificate instead of a CSR")
	noCsrFlag := getopt.BoolLong("no-csr", 0, "don't create and print a certificate signing request when generating a key pair")
	assumeYesFlag := getopt.BoolLong("assume-yes", 0, "assume yes to any y/n prompts, for scripting")
	pinPolicyFlag := getopt.EnumLong("pin-policy", 0, []string{"always", "once", "never"}, "never", "set the PIN policy of the generated key (never, once, or always)", "policy")
	touchPolicyFlag := getopt.EnumLong("touch-policy", 0, []string{"always", "never"}, "always", "set the touch policy of the generated key (never or always)", "policy")

	getopt.HelpColumn = 40
	getopt.SetParameters("[files]")
	getopt.Parse()
	fileArgs := getopt.Args()

	var importFlag bool
	if len(*importOpt) > 0 {
		importFlag = true
	} else {
		importFlag = false
	}

	if *helpFlag {
		getopt.Usage()
		return nil
	}

	if *signFlag {
		if *verifyFlag || *generateFlag || *resetFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		}
		return commandSign(*statusFdOpt, *detachSignFlag, *armorFlag, *localUserOpt, *tsaOpt, *slot, fileArgs)
	}

	if *verifyFlag {
		if *signFlag || *generateFlag || *resetFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		} else if len(*localUserOpt) > 0 {
			return errors.New("local-user cannot be specified for verification")
		} else if *detachSignFlag {
			return errors.New("detach-sign cannot be specified for verification")
		} else if *armorFlag {
			return errors.New("armor cannot be specified for verification")
		}
		return commandVerify(fileArgs, *slot)
	}

	if *resetFlag {
		if *signFlag || *verifyFlag || *generateFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandReset()
	}

	if *generateFlag {
		if *signFlag || *verifyFlag || *resetFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		isP256 := false
		if *p256Flag {
			isP256 = true
		}
		if *selfSignFlag && *noCsrFlag {
			return errors.New("can't specify both --self-sign and --no-csr")
		}
		generateCsr := true
		if *noCsrFlag {
			generateCsr = false
		}
		pinPolicy := piv.PINPolicyNever
		switch *pinPolicyFlag {
		case "once":
			pinPolicy = piv.PINPolicyOnce
		case "always":
			pinPolicy = piv.PINPolicyAlways
		case "never":
			pinPolicy = piv.PINPolicyNever
		}
		touchPolicy := piv.TouchPolicyAlways
		switch *touchPolicyFlag {
		case "never":
			touchPolicy = piv.TouchPolicyNever
		case "always":
			touchPolicy = piv.TouchPolicyAlways
		}

		if pinPolicy == piv.PINPolicyNever && touchPolicy == piv.TouchPolicyNever {
			return errors.New("can't set both PIN and touch policies to \"never\"")
		}
		return commandGenerate(*slot, isP256, *selfSignFlag, generateCsr, *assumeYesFlag, pinPolicy, touchPolicy)
	}

	if importFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandImport(*importOpt, *firstOpt, *slot)
	}

	if *printFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || importFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		return commandPrint(*slot)
	}

	return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
}
