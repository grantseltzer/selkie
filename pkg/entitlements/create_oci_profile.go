package entitlements

import spec "github.com/opencontainers/runtime-spec/specs-go"

// CreateProfileFromEntitlements allows you to pass a set of entitlements and to
// create an OCI compliant seccomp profile. That profile can be marshalled to JSON
// and passed to OCI container runtimes such as docker, or podman
func CreateOCIProfileFromEntitlements(entitlements []Entitlement) spec.LinuxSeccomp {

	spec := spec.LinuxSeccomp{
		DefaultAction: spec.ActAllow,
		Architectures: []spec.Arch{ //TODO: allow to specify arch, make defaults on detection
			spec.ArchX86,
			spec.ArchX86_64,
		},
		Syscalls: []spec.LinuxSyscall{
			{
				Names:  []string{},
				Action: spec.ActErrno,
			},
		},
	}

	entitlementsToDeny := removeEntitlementsFromDefaultDeny(entitlements)

	for _, e := range entitlementsToDeny {
		for _, s := range e.Syscalls {
			spec.Syscalls[0].Names = append(spec.Syscalls[0].Names, s)
		}
	}

	return spec
}

func GetEntitlementsFromNames(entitlementNames []string) []Entitlement {
	return nil
}
