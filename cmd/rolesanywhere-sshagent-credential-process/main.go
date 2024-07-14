package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/espadolini/yubiaws/rolesanywhere"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var trustAnchorARN, profileARN, roleARN string
	var durationSeconds int
	flag.StringVar(&trustAnchorARN, "trust-anchor-arn", "", "trust anchor ARN")
	flag.StringVar(&profileARN, "profile-arn", "", "profile ARN")
	flag.StringVar(&roleARN, "role-arn", "", "role ARN")
	flag.IntVar(&durationSeconds, "duration-seconds", 3600, "credential duration")
	var certificatePath, agentPath string
	flag.StringVar(&certificatePath, "certificate", "", "path to certificate (DER)")
	flag.StringVar(&agentPath, "agent", "", "path to agent socket")

	flag.Parse()

	certDer, err := os.ReadFile(certificatePath)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	pubKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	agConn, err := new(net.Dialer).DialContext(ctx, "unix", agentPath)
	if err != nil {
		return fmt.Errorf("connecting to agent: %w", err)
	}
	context.AfterFunc(ctx, func() { _ = agConn.Close() })

	ag := agent.NewClient(agConn)

	hc := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer hc.CloseIdleConnections()

	creds, err := rolesanywhere.CreateSession(ctx, rolesanywhere.CreateSessionParams{
		Client: hc,

		Certificate: cert,
		HashAndSignFunc: func(s string) ([]byte, error) {
			var flags agent.SignatureFlags
			if cert.PublicKeyAlgorithm == x509.RSA {
				// for rsa we have to ask for SHA256 because the default uses
				// SHA1 for hashing, but the format of the returned signature
				// should already be PKCS #1 v1.5 (untested)
				flags |= agent.SignatureFlagRsaSha256
			}
			sshSig, err := ag.SignWithFlags(pubKey, []byte(s), flags)
			if err != nil {
				return nil, fmt.Errorf("signing request: %w", err)
			}
			sigBlob := sshSig.Blob
			if cert.PublicKeyAlgorithm == x509.ECDSA {
				// for ecdsa we have to repackage the SSH signature into an
				// ASN.1 sequence
				var inner struct {
					R, S *big.Int
				}
				if err := ssh.Unmarshal(sshSig.Blob, &inner); err != nil {
					return nil, fmt.Errorf("parsing signature: %w", err)
				}
				b, err := asn1.Marshal([]*big.Int{inner.R, inner.S})
				if err != nil {
					return nil, fmt.Errorf("marshaling signature: %w", err)
				}
				sigBlob = b
			}
			return sigBlob, nil
		},

		TrustAnchorARN:  trustAnchorARN,
		ProfileARN:      profileARN,
		RoleARN:         roleARN,
		DurationSeconds: durationSeconds,
	})
	if err != nil {
		return fmt.Errorf("obtaining credentials: %w", err)
	}

	out := credentialProcessOutput{
		Version:         1,
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}
	if creds.CanExpire {
		out.Expiration = creds.Expires.Format(time.RFC3339)
	}

	j, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshaling output: %w", err)
	}

	os.Stdout.Write(j)
	return nil
}

type credentialProcessOutput struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}
