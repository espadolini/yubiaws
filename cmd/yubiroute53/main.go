// Copyright (c) 2024 Edoardo Spadolini
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53 "github.com/aws/aws-sdk-go-v2/service/route53"
	r53t "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/espadolini/yubiaws/rolesanywhere"
	"github.com/espadolini/yubiaws/yubicreds"
)

func main() {
	var trustAnchorARN, profileARN, roleARN string
	var serial uint
	flag.StringVar(&trustAnchorARN, "trust-anchor-arn", "", "trust anchor ARN")
	flag.StringVar(&profileARN, "profile-arn", "", "profile ARN")
	flag.StringVar(&roleARN, "role-arn", "", "role ARN")
	flag.UintVar(&serial, "serial", 0, "YubiKey serial number")

	var region, hostedZoneID, name, typ, value string
	var ttl int64
	flag.StringVar(&region, "region", "", "region")
	flag.StringVar(&hostedZoneID, "hosted-zone-id", "", "ID of the hosted zone")
	flag.StringVar(&name, "name", "", "name of the resource record set")
	flag.StringVar(&typ, "type", "", "type of the record set")
	flag.StringVar(&value, "value", "", "single value of the record set")
	flag.Int64Var(&ttl, "ttl", 0, "TTL of the record set")

	flag.Parse()

	hc := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer hc.CloseIdleConnections()

	cfg := aws.Config{
		Credentials: aws.NewCredentialsCache(yubicreds.Credentials(uint32(serial), rolesanywhere.CreateSessionParams{
			Client: hc,

			TrustAnchorARN:  trustAnchorARN,
			ProfileARN:      profileARN,
			RoleARN:         roleARN,
			DurationSeconds: 900,
		})),
		Region: region,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clt := r53.NewFromConfig(cfg)
	out, err := clt.ChangeResourceRecordSets(ctx, &r53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneID),
		ChangeBatch: &r53t.ChangeBatch{
			Changes: []r53t.Change{{
				Action: "UPSERT",
				ResourceRecordSet: &r53t.ResourceRecordSet{
					Name: aws.String(name),
					Type: r53t.RRType(typ),
					TTL:  aws.Int64(ttl),
					ResourceRecords: []r53t.ResourceRecord{{
						Value: aws.String(value),
					}},
				},
			}},
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("change %q submitted at %v\n", aws.ToString(out.ChangeInfo.Id), aws.ToTime(out.ChangeInfo.SubmittedAt))
}
