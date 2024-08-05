package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Config struct {
	TconfigdHost         string
	TconfigdSpiffeID     spiffeid.ID
	ServicePort          *int
	InterceptionMode     bool
	AgentApiPort         int
	AgentInterceptorPort int
	MyNamespace          string
}

func GetAppConfig() *Config {
	return &Config{
		TconfigdHost:         getEnv("TCONFIGD_HOST"),
		TconfigdSpiffeID:     spiffeid.RequireFromString(getEnv("TCONFIGD_SPIFFE_ID")),
		ServicePort:          getOptionalEnvAsInt("SERVICE_PORT"),
		InterceptionMode:     getEnvAsBool("INTERCEPTION_MODE"),
		AgentApiPort:         getEnvAsInt("AGENT_API_PORT"),
		AgentInterceptorPort: getEnvAsInt("AGENT_INTERCEPTOR_PORT"),
		MyNamespace:          getEnv("MY_NAMESPACE"),
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

func getOptionalEnvAsInt(key string) *int {
	valueStr, exists := os.LookupEnv(key)
	if !exists || valueStr == "" {
		return nil
	}

	valueInt, err := strconv.Atoi(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Error converting %s to integer: %v", key, err))
	}

	return &valueInt
}

func getEnvAsBool(key string) bool {
	valueStr := getEnv(key)
	valueBool, err := strconv.ParseBool(valueStr)

	if err != nil {
		panic(fmt.Sprintf("Error converting %s to bool: %v", key, err))
	}

	return valueBool
}
