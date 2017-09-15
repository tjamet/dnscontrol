package commands

import (
	"fmt"

	"github.com/StackExchange/dnscontrol/pkg/acme"
	"github.com/StackExchange/dnscontrol/pkg/normalize"
	"github.com/urfave/cli"
)

type GetCertsArgs struct {
	GetDNSConfigArgs
	GetCredentialsArgs
}

func (args *GetCertsArgs) flags() []cli.Flag {
	flags := args.GetDNSConfigArgs.flags()
	flags = append(flags, args.GetCredentialsArgs.flags()...)
	return flags
}

var _ = cmd(catUtils, func() *cli.Command {
	var args GetCertsArgs
	return &cli.Command{
		Name:  "get-certs",
		Usage: "issue Let's encrypt certs for domains",
		Action: func(ctx *cli.Context) error {
			return exit(GetCerts(args))
		},
		Flags: args.flags(),
	}
}())

func GetCerts(args GetCertsArgs) error {
	cfg, err := GetDNSConfig(args.GetDNSConfigArgs)
	if err != nil {
		return err
	}
	errs := normalize.NormalizeAndValidateConfig(cfg)
	if PrintValidationErrors(errs) {
		return fmt.Errorf("Exiting due to validation errors")
	}
	_, dnsProviders, _, err := InitializeProviders(args.CredsFile, cfg)
	if err != nil {
		return err
	}
	return acme.IssueCerts(cfg, dnsProviders)
}
