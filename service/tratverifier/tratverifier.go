package tratverifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tokenetes/tokenetes-agent/common"
	"github.com/tokenetes/tokenetes-agent/tokenetesagenterrors"
	"github.com/tokenetes/tokenetes-agent/tokenetestrustbundlemanager"
	"github.com/tokenetes/tokenetes-agent/tratverificationreasons"
	"github.com/tokenetes/tokenetes-agent/verificationrules/v1alpha1"

	"github.com/golang-jwt/jwt"

	"github.com/tokenetes/tokenetes-agent/trat"
)

type TraTVerifier struct {
	verificationRulesApplier    v1alpha1.VerificationRulesApplier
	tokenetesTrustBundleManager *tokenetestrustbundlemanager.TokenetesTrustBundleManager
}

func NewTraTVerifier(verificationRulesApplier v1alpha1.VerificationRulesApplier, tokenetesTrustBundleManager *tokenetestrustbundlemanager.TokenetesTrustBundleManager) *TraTVerifier {
	return &TraTVerifier{
		verificationRulesApplier:    verificationRulesApplier,
		tokenetesTrustBundleManager: tokenetesTrustBundleManager,
	}
}

func (tv *TraTVerifier) VerifyTraT(ctx context.Context, rawTrat string, path string, method common.HttpMethod, queryParameters json.RawMessage, headers json.RawMessage, body json.RawMessage) (bool, string, error) {
	excluded, err := tv.verificationRulesApplier.IsTraTExcluded(path, method)
	if err != nil {
		return false, "", err
	}

	if excluded {
		return true, tratverificationreasons.VerificationSkipped, nil
	}

	if rawTrat == "" {
		return false, tratverificationreasons.EmptyTraT, nil
	}

	valid, trat, err := tv.verifyTraTSignature(ctx, rawTrat)

	if err != nil {
		if errors.Is(err, tokenetesagenterrors.ErrInvalidKeyID) {
			return false, tratverificationreasons.InvalidTraTSignature, nil
		}

		if errors.Is(err, tokenetesagenterrors.ErrTraTExpired) {
			return false, tratverificationreasons.ExpiredTraT, nil
		}

		return false, "", fmt.Errorf("couldn't verify trat signature: %w", err)
	}

	if !valid {
		return false, tratverificationreasons.InvalidTraTSignature, nil
	}

	input := make(map[string]interface{})

	input["body"] = body
	input["headers"] = headers
	input["queryParameters"] = queryParameters

	return tv.verificationRulesApplier.ApplyRule(trat, path, method, input)
}

func (tv *TraTVerifier) verifyTraTSignature(ctx context.Context, rawTrat string) (bool, *trat.TraT, error) {
	token, err := jwt.ParseWithClaims(rawTrat, &trat.TraT{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not present in token header")
		}

		key, err := tv.tokenetesTrustBundleManager.GetJWK(ctx, kid)
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
		if validationErr, ok := err.(*jwt.ValidationError); ok {
			if validationErr.Errors&jwt.ValidationErrorExpired != 0 {
				return false, nil, tokenetesagenterrors.ErrTraTExpired
			}

			if validationErr.Inner != nil {
				return false, nil, validationErr.Inner
			}
		}

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
