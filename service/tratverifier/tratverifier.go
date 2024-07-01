package tratverifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tratteria/tratteria-agent/common"
	"github.com/tratteria/tratteria-agent/tratteriatrustbundlemanager"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"

	"github.com/golang-jwt/jwt"

	"github.com/tratteria/tratteria-agent/trat"
)

type TraTVerifier struct {
	verificationRulesApplier    v1alpha1.VerificationRulesApplier
	tratteriaTrustBundleManager *tratteriatrustbundlemanager.TratteriaTrustBundleManager
}

func NewTraTVerifier(verificationRulesApplier v1alpha1.VerificationRulesApplier, tratteriaTrustBundleManager *tratteriatrustbundlemanager.TratteriaTrustBundleManager) *TraTVerifier {
	return &TraTVerifier{
		verificationRulesApplier:    verificationRulesApplier,
		tratteriaTrustBundleManager: tratteriaTrustBundleManager,
	}
}

func (tv *TraTVerifier) VerifyTraT(ctx context.Context, rawTrat string, path string, method common.HttpMethod, queryParameters map[string]string, headers http.Header, body json.RawMessage) (bool, string, error) {
	valid, trat, err := tv.verifyTraTSignature(ctx, rawTrat)
	if err != nil {
		return false, "", fmt.Errorf("couldn't verify trat signature: %w", err)
	}

	if !valid {
		return false, "invalid trat signature", nil
	}

	headersJson, err := convertHeaderToJson(headers)
	if err != nil {
		return false, "", fmt.Errorf("error reading request header")
	}

	queryParamsJson, err := convertMapToJson(queryParameters)
	if err != nil {
		return false, "", fmt.Errorf("error reading query parameters")
	}

	input := make(map[string]interface{})

	input["body"] = body
	input["headers"] = headersJson
	input["queryParameters"] = queryParamsJson

	return tv.verificationRulesApplier.ApplyRule(trat, path, method, input)
}

func convertMapToJson(data map[string]string) (json.RawMessage, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	if len(bytes) == 0 {
		bytes = []byte("{}")
	}

	return json.RawMessage(bytes), nil
}

// TODO: handle keys with multiple values.
func convertHeaderToJson(headers http.Header) (json.RawMessage, error) {
	headerMap := make(map[string]string)
	for key, values := range headers {
		headerMap[key] = values[0]
	}

	return convertMapToJson(headerMap)
}

func (tv *TraTVerifier) verifyTraTSignature(ctx context.Context, rawTrat string) (bool, *trat.TraT, error) {
	token, err := jwt.ParseWithClaims(rawTrat, &trat.TraT{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		key, err := tv.tratteriaTrustBundleManager.GetJWK(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("key %v not found: %w", kid, err)
		}

		var publicKey interface{}
		if err := key.Raw(&publicKey); err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return false, nil, err
	}

	if !token.Valid {
		return false, nil, nil
	}

	if claims, ok := token.Claims.(*trat.TraT); ok {
		return true, claims, nil
	}

	return false, nil, fmt.Errorf("error retrieving trat claims")
}
