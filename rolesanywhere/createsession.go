// Copyright (c) 2024 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package rolesanywhere

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type CreateSessionParams struct {
	Client *http.Client

	Certificate *x509.Certificate
	Signer      crypto.Signer

	TrustAnchorARN string
	ProfileARN     string
	RoleARN        string

	DurationSeconds int
}

func CreateSession(ctx context.Context, params CreateSessionParams) (aws.Credentials, error) {
	var region string
	if a, err := arn.Parse(params.TrustAnchorARN); err != nil {
		return aws.Credentials{}, fmt.Errorf("parsing trust anchor ARN: %w", err)
	} else if r := a.Region; r == "" {
		return aws.Credentials{}, errors.New("trust anchor ARN has no region")
	} else {
		region = r
	}

	var signatureAlgorithm string
	switch p := params.Signer.Public(); p.(type) {
	case *ecdsa.PublicKey:
		signatureAlgorithm = "AWS4-X509-ECDSA-SHA256"
	case *rsa.PublicKey:
		signatureAlgorithm = "AWS4-X509-RSA-SHA256"
	default:
		return aws.Credentials{}, fmt.Errorf("unsupported public key type %T", p)
	}

	reqBody, err := json.Marshal(createSessionInput{
		TrustAnchorARN:  params.TrustAnchorARN,
		ProfileARN:      params.ProfileARN,
		RoleARN:         params.RoleARN,
		DurationSeconds: params.DurationSeconds,
	})
	if err != nil {
		return aws.Credentials{}, err
	}

	reqURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("rolesanywhere.%v.amazonaws.com", region),
		Path:   "/sessions",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return aws.Credentials{}, err
	}

	const signedHeaders = "content-type;host;x-amz-date;x-amz-x509"

	req.Header.Set("Content-Type", "application/json")

	now := time.Now().UTC().Round(time.Second)
	xAmzDate := now.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", xAmzDate)

	xAmzX509 := base64.StdEncoding.EncodeToString(params.Certificate.Raw)
	req.Header.Set("X-Amz-X509", xAmzX509)

	canonicalRequest := sha256.New()
	fmt.Fprintf(canonicalRequest,
		"POST\n/sessions\n\ncontent-type:application/json\nhost:%v\nx-amz-date:%v\nx-amz-x509:%v\n\n%v\n%x",
		reqURL.Host,
		xAmzDate,
		xAmzX509,
		signedHeaders,
		sha256.Sum256(reqBody),
	)

	scope := fmt.Sprintf("%v/%v/rolesanywhere/aws4_request", now.Format("20060102"), region)

	stringToSign := sha256.New()
	fmt.Fprintf(stringToSign,
		"%v\n%v\n%v\n%x",
		signatureAlgorithm,
		xAmzDate,
		scope,
		canonicalRequest.Sum(nil),
	)

	signature, err := params.Signer.Sign(rand.Reader, stringToSign.Sum(nil), crypto.SHA256)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("signing request: %w", err)
	}

	credentialID := params.Certificate.SerialNumber.String()
	req.Header.Set("Authorization", fmt.Sprintf(
		"%v Credential=%v/%v, SignedHeaders=%v, Signature=%x",
		signatureAlgorithm,
		credentialID,
		scope,
		signedHeaders,
		signature,
	))

	resp, err := params.Client.Do(req)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("writing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		errBody, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 16*1024))
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("reading error response with status %q: %w", resp.Status, err)
		}
		return aws.Credentials{}, fmt.Errorf("error response with status %q: %q", resp.Status, errBody)
	}

	respBody, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, 128*1024))
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("reading response: %w", err)
	}

	var out createSessionOutput
	if err := json.Unmarshal(respBody, &out); err != nil {
		return aws.Credentials{}, fmt.Errorf("parsing response: %w", err)
	}

	if le := len(out.CredentialSet); le != 1 {
		return aws.Credentials{}, fmt.Errorf("unexpected credentialSet size: got %v, expected 1", le)
	}

	outCred := out.CredentialSet[0].Credentials

	expiration, err := time.Parse(time.RFC3339, outCred.Expiration)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("parsing credentials expiration: %w", err)
	}

	return aws.Credentials{
		AccessKeyID:     outCred.AccessKeyId,
		SecretAccessKey: outCred.SecretAccessKey,
		SessionToken:    outCred.SessionToken,
		Source:          "rolesanywhere.CreateSession",
		CanExpire:       true,
		Expires:         expiration,
	}, nil
}

type createSessionInput struct {
	TrustAnchorARN  string `json:"trustAnchorArn"`
	ProfileARN      string `json:"profileArn"`
	RoleARN         string `json:"roleArn"`
	DurationSeconds int    `json:"durationSeconds"`
}

type createSessionOutput struct {
	CredentialSet []struct {
		Credentials struct {
			AccessKeyId     string
			Expiration      string
			SecretAccessKey string
			SessionToken    string
		}
	}
}
