package configsync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tratteria/tratteria-agent/rules"
	"go.uber.org/zap"
)

const (
	MAX_REGISTRATION_ATTEMPTS       = 5
	FAILED_HEARTBEAT_RETRY_INTERVAL = 5 * time.Second
)

type Client struct {
	WebhookPort       int
	TconfigdUrl       *url.URL
	ServiceName       string
	Rules             *rules.Rules
	HeartbeatInterval time.Duration
	HttpClient        *http.Client
	Logger            *zap.Logger
}

type registrationRequest struct {
	IPAddress   string `json:"ipAddress"`
	Port        int    `json:"port"`
	ServiceName string `json:"serviceName"`
}

type heartBeatRequest struct {
	IPAddress      string `json:"ipAddress"`
	Port           int    `json:"port"`
	ServiceName    string `json:"serviceName"`
	RulesVersionID string `json:"rulesVersionId"`
}

func (c *Client) Start() error {
	if err := c.registerWithBackoff(); err != nil {
		return fmt.Errorf("failed to register with tconfigd: %w", err)
	}

	c.Logger.Info("Successfully registered to tconfigd")

	c.Logger.Info("Starting heartbeats to tconfigd...")

	go c.startHeartbeat()

	return nil
}

func (c *Client) registerWithBackoff() error {
	var attempt int

	for {
		if err := c.register(); err != nil {
			c.Logger.Error("Registration failed", zap.Error(err))

			attempt++

			if attempt >= MAX_REGISTRATION_ATTEMPTS {
				return fmt.Errorf("max registration attempts reached: %w", err)
			}

			backoff := time.Duration(rand.Intn(1<<attempt)) * time.Second

			c.Logger.Info("Retrying registration", zap.Duration("backoff", backoff), zap.Int("attempt", attempt))

			time.Sleep(backoff)

			continue
		}

		break
	}

	return nil
}

func (c *Client) register() error {
	localIP, err := getLocalIP()
	if err != nil {
		return fmt.Errorf("failed to get local IP address: %w", err)
	}

	registrationReq := registrationRequest{
		IPAddress:   localIP,
		Port:        c.WebhookPort,
		ServiceName: c.ServiceName,
	}

	jsonData, err := json.Marshal(registrationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}

	registerEndpoint := c.TconfigdUrl.ResolveReference(&url.URL{Path: "agent-register"})

	req, err := http.NewRequest(http.MethodPost, registerEndpoint.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) startHeartbeat() {
	heartbeatEndpoint := c.TconfigdUrl.ResolveReference(&url.URL{Path: "agent-heartbeat"})

	for {
		heartBeatReq := heartBeatRequest{
			IPAddress:      c.ServiceName,
			Port:           c.WebhookPort,
			ServiceName:    c.ServiceName,
			RulesVersionID: c.Rules.GetRulesVersionID(),
		}

		heartBeatRequestJson, err := json.Marshal(heartBeatReq)
		if err != nil {
			c.Logger.Error("Failed to marshal heartbeat request", zap.Error(err))
			time.Sleep(FAILED_HEARTBEAT_RETRY_INTERVAL)

			continue
		}

		req, err := http.NewRequest(http.MethodPost, heartbeatEndpoint.String(), bytes.NewBuffer(heartBeatRequestJson))
		if err != nil {
			c.Logger.Error("Failed to create heartbeat request", zap.Error(err))
			time.Sleep(FAILED_HEARTBEAT_RETRY_INTERVAL)

			continue
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HttpClient.Do(req)
		if err != nil {
			c.Logger.Error("Failed to send heartbeat", zap.Error(err))
			time.Sleep(FAILED_HEARTBEAT_RETRY_INTERVAL)

			continue
		} else {
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				c.Logger.Error("Received non-ok heartbeat response", zap.Int("status", resp.StatusCode))
				time.Sleep(FAILED_HEARTBEAT_RETRY_INTERVAL)

				continue
			} else {
				c.Logger.Info("Heartbeat sent successfully")
			}
		}

		time.Sleep(c.HeartbeatInterval)
	}
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("couldn't obtain a webhook IP address")
}
