// Copyright (c) 2024 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package yubicreds

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-piv/piv-go/piv"

	"github.com/espadolini/yubiaws/rolesanywhere"
)

func openYubikey(serial uint32) (*piv.YubiKey, error) {
	names, err := piv.Cards()
	if err != nil {
		return nil, err
	}

	var errs []error
	for _, name := range names {
		card, err := piv.Open(name)
		if err != nil {
			continue
		}
		cardSerial, err := card.Serial()
		if err != nil {
			errs = append(errs, err)
			_ = card.Close()
			continue
		}
		if cardSerial == serial {
			return card, nil
		}
		_ = card.Close()
	}

	errs = append(errs, piv.ErrNotFound)
	return nil, errors.Join(errs...)
}

func Credentials(serial uint32, params rolesanywhere.CreateSessionParams) aws.CredentialsProvider {
	return credentials{
		serial: serial,
		params: params,
	}
}

type credentials struct {
	serial uint32
	params rolesanywhere.CreateSessionParams
}

func (c credentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	card, err := openYubikey(c.serial)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("opening yubikey %v: %w", c.serial, err)
	}
	defer card.Close()

	cert, err := card.Certificate(piv.SlotCardAuthentication)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("reading certificate from yubikey %v: %w", c.serial, err)
	}
	privKey, err := card.PrivateKey(piv.SlotCardAuthentication, cert.PublicKey, piv.KeyAuth{PINPolicy: piv.PINPolicyNever})
	if err != nil {
		return aws.Credentials{}, err
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return aws.Credentials{}, fmt.Errorf("expected a crypto.Signer, got %T", privKey)
	}

	c.params.Certificate = cert
	return rolesanywhere.CreateSessionSigner(ctx, c.params, signer)
}
