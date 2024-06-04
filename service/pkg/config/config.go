package config

import (
	"fmt"
	"net/url"
	"os"
)

type Config struct {
	TconfigdUrl   *url.URL
	Service       string
	TraTsAudience string
	TraTsIssuer   string
	TraTsJWKS     string
}

func GetAppConfig() *Config {
	return &Config{
		TconfigdUrl:   parseURL(getEnv("TCONFIGD_URL")),
		Service:       getEnv("SERVICE"),
		TraTsAudience: getEnv("TRATS_AUDIENCE"),
		TraTsIssuer:   getEnv("TRATS_ISSUER"),
		TraTsJWKS:     getEnv("TTS_JWKS"),
	}
}

func getEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		panic(fmt.Sprintf("%s environment variable not set", key))
	}

	return value
}

func parseURL(rawurl string) *url.URL {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		panic(fmt.Sprintf("Error parsing URL %s: %v", rawurl, err))
	}

	return parsedURL
}
