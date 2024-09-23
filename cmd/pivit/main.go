package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/cashapp/pivit/pkg/pivit"
	"github.com/go-piv/piv-go/v2/piv"
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
	touchPolicyFlag := getopt.EnumLong("touch-policy", 0, []string{"always", "cached", "never"}, "always", "set the touch policy of the generated key (never, cached, or always)", "policy")

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

	yk, err := pivit.YubikeyHandle()
	if err != nil {
		return errors.Wrap(err, "failed to open yubikey")
	}
	defer func() {
		_ = yk.Close()
	}()

	if *signFlag {
		if *verifyFlag || *generateFlag || *resetFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		} else if len(*localUserOpt) == 0 {
			return errors.New("specify a USER-ID to sign with")
		}

		var message io.ReadCloser
		var err error
		if len(fileArgs) == 0 {
			message = os.Stdin
		} else if len(fileArgs) == 1 {
			if message, err = os.Open(fileArgs[0]); err != nil {
				return err
			}
			defer func() {
				_ = message.Close()
			}()
		} else {
			return errors.New(fmt.Sprintf("expected 0 or 1 file arguments but got: %v", fileArgs))
		}

		opts := &pivit.SignOpts{
			StatusFd:           *statusFdOpt,
			Detach:             *detachSignFlag,
			Armor:              *armorFlag,
			UserId:             *localUserOpt,
			TimestampAuthority: *tsaOpt,
			Message:            message,
			Slot:               pivit.GetSlot(*slot),
			Prompt:             os.Stdin,
		}
		signature, err := pivit.Sign(yk, opts)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(signature)
		return err
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

		var signature io.ReadCloser
		var message io.ReadCloser
		var err error
		message = nil
		if len(fileArgs) == 2 {
			// verify detached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return errors.Wrap(err, "read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()

			if fileArgs[1] == "-" {
				message = os.Stdin
			} else {
				message, err = os.Open(fileArgs[1])
				if err != nil {
					return errors.Wrap(err, "read message file")
				}

				defer func() {
					_ = message.Close()
				}()
			}
		} else if len(fileArgs) == 1 {
			// verify attached signature
			signature, err = os.Open(fileArgs[0])
			if err != nil {
				return errors.Wrap(err, "read signature file")
			}
			defer func() {
				_ = signature.Close()
			}()
		} else if len(fileArgs) == 0 {
			// verify attached signature from stdin
			signature = os.Stdin
		} else {
			return errors.New(fmt.Sprintf("expected either 0, 1, or 2 file arguments but got: %v", fileArgs))
		}

		opts := &pivit.VerifyOpts{
			Signature: signature,
			Message:   message,
			Slot:      pivit.GetSlot(*slot),
		}
		return pivit.VerifySignature(yk, opts)
	}

	if *resetFlag {
		if *signFlag || *verifyFlag || *generateFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		pin, err := pivit.GetPin(os.Stdin)
		if err != nil {
			return err
		}
		opts := &pivit.ResetOpts{Pin: pin}
		return pivit.ResetYubikey(yk, opts)
	}

	if *generateFlag {
		if *signFlag || *verifyFlag || *resetFlag || importFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		var algorithm piv.Algorithm
		if *p256Flag {
			algorithm = piv.AlgorithmEC256
		} else {
			algorithm = piv.AlgorithmEC384
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
		case "cached":
			touchPolicy = piv.TouchPolicyCached
		case "always":
			touchPolicy = piv.TouchPolicyAlways
		}
		if pinPolicy == piv.PINPolicyNever && touchPolicy == piv.TouchPolicyNever {
			return errors.New("can't set both PIN and touch policies to \"never\"")
		}

		pin, err := pivit.GetPin(os.Stdin)
		if err != nil {
			return err
		}

		certEmailAddress := os.Getenv("PIVIT_EMAIL")
		certOrg := strings.Split(os.Getenv("PIVIT_ORG"), ",")
		certOrgUnit := strings.Split(os.Getenv("PIVIT_ORG_UNIT"), ",")
		certURIs := strings.Split(os.Getenv("PIVIT_CERT_URIS"), " ")
		certURLs := make([]*url.URL, 0)
		for _, uri := range certURIs {
			url, err := url.Parse(uri)
			if err != nil {
				certURLs = append(certURLs, url)
			}
		}

		certParams := pivit.CertificateParameters{
			SubjectEmailAddress:       certEmailAddress,
			SubjectOrganization:       certOrg,
			SubjectOrganizationUnit:   certOrgUnit,
			CertificateURIs:           certURLs,
			CertificateIPAddresses:    []net.IP{},
			CertificateEmailAddresses: []string{certEmailAddress},
			CertificateDNSNames:       []string{},
		}
		opts := &pivit.GenerateCertificateOpts{
			Algorithm:             algorithm,
			SelfSign:              *selfSignFlag,
			GenerateCsr:           generateCsr,
			AssumeYes:             *assumeYesFlag,
			PINPolicy:             pinPolicy,
			TouchPolicy:           touchPolicy,
			CertificateParameters: certParams,
			Slot:                  pivit.GetSlot(*slot),
			Prompt:                os.Stdin,
			Pin:                   pin,
		}
		if generateCsr {
			fmt.Println("Touch Yubikey now to sign your CSR...")
		} else {
			fmt.Println("Touch Yubikey now to sign your key...")
		}
		result, err := pivit.GenerateCertificate(yk, opts)
		if err != nil {
			return err
		}
		fmt.Println("Printing Yubikey device attestation certificate:")
		fmt.Println(string(result.AttestationCertificate))
		if opts.SelfSign {
			fmt.Println("Printing self-signed certificate:")
		} else {
			fmt.Println("Printing generated key certificate:")
		}
		fmt.Println(string(result.Certificate))
		if opts.GenerateCsr {
			fmt.Println("Printing certificate signing request:")
			fmt.Println(string(result.CertificateSigningRequest))
		}

		return nil
	}

	if importFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || *printFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}

		pin, err := pivit.GetPin(os.Stdin)
		if err != nil {
			return err
		}
		certificateBytes, err := os.ReadFile(*importOpt)
		if err != nil {
			return errors.Wrap(err, "failed to read certificate file")
		}
		opts := &pivit.ImportOpts{
			CertificateBytes: certificateBytes,
			StopAfterFirst:   *firstOpt,
			Slot:             pivit.GetSlot(*slot),
			Pin:              pin,
		}
		return pivit.ImportCertificate(yk, opts)
	}

	if *printFlag {
		if *signFlag || *verifyFlag || *generateFlag || *resetFlag || importFlag {
			return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
		}
		opts := &pivit.CertificateOpts{
			Slot: pivit.GetSlot(*slot),
		}
		certificateInfo, err := pivit.Certificate(yk, opts)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(os.Stdout, "%s\n%s\n", certificateInfo.Fingerprint, certificateInfo.CertificatePem)
		return err
	}

	return errors.New("specify --help, --sign, --verify, --import, --generate, --reset or --print")
}
