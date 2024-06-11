package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
)

type Config struct {
	TconfigdUrl *url.URL
	ServiceName string
	ServicePort int
}

func GetAppConfig() *Config {
	return &Config{
		TconfigdUrl: parseURL(getEnv("TCONFIGD_URL")),
		ServiceName: getEnv("SERVICE_NAME"),
		ServicePort: getEnvAsInt("SERVICE_PORT"),
	}
}

func getEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists || value == "" {
		panic(fmt.Sprintf("%s environment variable not set", key))
	}

	return value
}

func getEnvAsInt(key string) int {
	valueStr := getEnv(key)
	valueInt, err := strconv.Atoi(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Error converting %s to integer: %v", key, err))
	}
	return valueInt
}

func parseURL(rawurl string) *url.URL {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		panic(fmt.Sprintf("Error parsing URL %s: %v", rawurl, err))
	}

	return parsedURL
}
