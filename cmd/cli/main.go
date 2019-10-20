package main

import (
	"encoding/json"
	"errors"
	"fmt"

	libentitlements "github.com/grantseltzer/selkie/pkg/entitlements"
	"github.com/spf13/cobra"
)

func main() {

	var karnCommand = &cobra.Command{
		Use:   "karn ['--' FLAGS] [Entitlements]",
		Short: "A simple generator of OCI-compliant seccomp profiles based on entitlements",
		Args:  verifyEntitlementArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entitlements := libentitlements.GetEntitlementsFromNames(args)
			spec := libentitlements.CreateOCIProfileFromEntitlements(entitlements)
			jsonSpec, err := json.MarshalIndent(spec, "", " ")
			if err != nil {
				return errors.New("error preparing JSON seccomp profile")
			}

			fmt.Printf("%s\n", jsonSpec)
			return nil
		},
	}

	err := karnCommand.Execute()
	if err != nil {

	}
}

// verifyEntitlementArgs accumulates all invalid entitlement args into a single error message
func verifyEntitlementArgs(cmd *cobra.Command, args []string) error {

	invalidEntitlements := []string{}
	for _, arg := range args {
		if !libentitlements.ValidEntitlement(arg) {
			invalidEntitlements = append(invalidEntitlements, arg)
		}
	}

	if len(invalidEntitlements) != 0 {
		return fmt.Errorf("invalid entitlement names: %v", invalidEntitlements)
	}

	return nil
}
