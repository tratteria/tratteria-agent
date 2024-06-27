package trats

import "github.com/golang-jwt/jwt"

type TxnToken struct {
	Txn    string           `json:"txn"`
	Sub    subject          `json:"sub"`
	ReqCtx requesterContext `json:"req_ctx"`
	Purp   string           `json:"purp"`
	Azd    any              `json:"azd"`
	jwt.StandardClaims
}

type requesterContext struct {
	ReqIP string   `json:"req_ip"`
	Authn string   `json:"authn"`
	ReqWl []string `json:"req_wl"`
}

// TODO: support other subject types.
type subject struct {
	Format string `json:"format"`
	Email  string `json:"email"`
}
