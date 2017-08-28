package providers

//CapabilityFlag is an identifier for a "feature" that a provider supports. Only use constants from this package.
type CapabilityFlag uint32

// Add all capabilies to this list. Even ones just for documentation are ok.
const (
	// CanUseAlias indicates the provider support ALIAS records (or flattened CNAMES). Up to the provider to translate them to the appropriate record type.
	// If you add something to this list, you probably want to add it to pkg/normalize/validate.go checkProviderCapabilities() or somewhere near there.
	CanUseAlias CapabilityFlag = iota
	// CanUsePTR indicates the provider can handle PTR records
	CanUsePTR
	// CanUseSRV indicates the provider can handle SRV records
	CanUseSRV
	// CanUseCAA indicates the provider can handle CAA records
	CanUseCAA
	// CantUseNOPURGE indicates NO_PURGE is broken for this provider. To make it
	// work would require complex emulation of an incremental update mechanism,
	// so it is easier to simply mark this feature as not working for this
	// provider.
	CantUseNOPURGE
	// CanDoCloudflareRedirects is really only supported by cloudflare
	CanDoCloudflareRedirects

	// CanDualHost indicates the provider is fully capable of acting in a dual-host setup. Includes full control of apex NS records. DOCUMENTATION ONLY.
	CanDualHost

	// AllCapabilities is a special value that indicates this provider can do everything. Any provider declaring this should expect and handle unexpected record types cleanly.
	AllCapabilities // KEEP AT END OF LIST!
)

// RestrictedRecordTypes tracks record types that require special capabilities in order to be valid.
// (#rtype_variations)
var RestrictedRecordTypes = map[string]CapabilityFlag{
	"ALIAS":            CanUseAlias,
	"PTR":              CanUsePTR,
	"SRV":              CanUseSRV,
	"CAA":              CanUseCAA,
	"CF_REDIRECT":      CanDoCloudflareRedirects,
	"CF_TEMP_REDIRECT": CanDoCloudflareRedirects,
}

// Capability describes a provider's ability to perform a function
type Capability struct {
	Flag    CapabilityFlag
	Enabled bool
	Comment string
}

var providerCapabilities = map[string][]Capability{}

func ProviderHasCabability(pType string, cap CapabilityFlag) bool {
	for _, c := range providerCapabilities[pType] {
		if c.Flag == AllCapabilities && c.Enabled {
			return true
		}
		if c.Flag == cap && c.Enabled {
			return true
		}
	}
	return false
}

//CapabilityOption is an interface that lets CapabilityFlags and more complex options be passed into registration func interchangably
type CapabilityOption interface {
	Get() Capability
}

func (cf CapabilityFlag) Get() Capability {
	return Capability{
		Flag:    cf,
		Enabled: true,
	}
}

func (c Capability) Get() Capability {
	return c
}

func Cannot(flag CapabilityFlag, comment string) Capability {
	return Capability{
		Flag:    flag,
		Enabled: false,
		Comment: comment,
	}
}

func Can(flag CapabilityFlag, comment string) Capability {
	return Capability{
		Flag:    flag,
		Enabled: true,
		Comment: comment,
	}
}
