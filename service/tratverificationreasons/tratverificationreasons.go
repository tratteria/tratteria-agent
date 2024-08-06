package tratverificationreasons

const (
	VerificationSkipped      = "trat verification skipped for excluded endpoint"
	EmptyTraT                = "empty trat in the request"
	InvalidTraTSignature     = "invalid trat signature"
	InvalidIssuer            = "invalid issuer"
	InvalidAudience          = "invalid audience"
	InvalidAuthDetails       = "invalid authorization details"
	VerificationRuleNotFound = "trat verification rules not found for %s path and %s method"
)
