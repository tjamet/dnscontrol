package cmd

import (
	"fmt"

	"github.com/urfave/cli"
)

var expireCheckCommand = &cli.Command{
	Name:  "check-expirations",
	Usage: "Fetch domains from all supporting registrars and print expiration dates",
	Action: func(ctx *cli.Context) error {
		return exit(CheckExpirations(globalExpireCheckArgs))
	},
	Category: catUtils,
	Flags:    globalExpireCheckArgs.flags(),
}

// PreviewArgs contains all data/flags needed to run preview, independently of CLI
type ExpireCheckArgs struct {
	GetDNSConfigArgs
	GetCredentialsArgs
}

var globalExpireCheckArgs ExpireCheckArgs

func (args *ExpireCheckArgs) flags() []cli.Flag {
	flags := args.GetDNSConfigArgs.flags()
	flags = append(flags, args.GetCredentialsArgs.flags()...)
	return flags
}

func CheckExpirations(args ExpireCheckArgs) error {
	cfg, err := GetDNSConfig(args.GetDNSConfigArgs)
	if err != nil {
		return err
	}
	fmt.Println(len(cfg.Registrars))
	return nil
}
