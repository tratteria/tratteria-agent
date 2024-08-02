package configsync

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

const (
	TCONFIGD_WEBSOCKET_PATH    = "ws"
	CONNECTION_INITIAL_BACKOFF = 1 * time.Second
	CONNECTION_MAX_BACKOFF     = 60 * time.Second
	CONNECTION_MAX_RETRIES     = 5
	WRITE_WAIT                 = 10 * time.Second
	PONG_WAIT                  = 60 * time.Second
	PING_PERIOD                = (PONG_WAIT * 9) / 10
	REQUEST_TIMEOUT            = 15 * time.Second
)

type Client struct {
	tconfigdHost             string
	tconfigdSpiffeId         spiffeid.ID
	x509Source               *workloadapi.X509Source
	namespace                string
	verificationRulesManager v1alpha1.VerificationRulesManager
	logger                   *zap.Logger
	conn                     *websocket.Conn
	send                     chan []byte
	done                     chan struct{}
	closeOnce                sync.Once
	pendingRequests          sync.Map
}

type MessageType string

const (
	MessageTypeInitialRulesResponse                          MessageType = "INITIAL_RULES_RESPONSE"
	MessageTypeGetJWKSRequest                                MessageType = "GET_JWKS_REQUEST"
	MessageTypeGetJWKSResponse                               MessageType = "GET_JWKS_RESPONSE"
	MessageTypeTraTVerificationRuleUpsertRequest             MessageType = "TRAT_VERIFICATION_RULE_UPSERT_REQUEST"
	MessageTypeTraTVerificationRuleUpsertResponse            MessageType = "TRAT_VERIFICATION_RULE_UPSERT_RESPONSE"
	MessageTypeTratteriaConfigVerificationRuleUpsertRequest  MessageType = "TRATTERIA_CONFIG_VERIFICATION_RULE_UPSERT_REQUEST"
	MessageTypeTratteriaConfigVerificationRuleUpsertResponse MessageType = "TRATTERIA_CONFIG_VERIFICATION_RULE_UPSERT_RESPONSE"
	MessageTypeRuleReconciliationRequest                     MessageType = "RULE_RECONCILIATION_REQUEST"
	MessageTypeRuleReconciliationResponse                    MessageType = "RULE_RECONCILIATION_RESPONSE"
	MessageTypeTraTDeletionRequest                           MessageType = "TRAT_DELETION_REQUEST"
	MessageTypeTraTDeletionResponse                          MessageType = "TRAT_DELETION_RESPONSE"
	MessageTypeUnknown                                       MessageType = "UNKNOWN"
)

type PingData struct {
	RuleHash string `json:"ruleHash"`
}

type Request struct {
	ID      string          `json:"id"`
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	ID      string          `json:"id"`
	Type    MessageType     `json:"type"`
	Status  int             `json:"status"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type AllActiveVerificationRulesPayload struct {
	VerificationRules *v1alpha1.VerificationRules `json:"verificationRules"`
}

type TraTDeletionPayload struct {
	TraTName string
}

func NewClient(tconfigdHost string, tconfigdSpiffeId spiffeid.ID, namespace string, verificationRulesManager v1alpha1.VerificationRulesManager, x509Source *workloadapi.X509Source, logger *zap.Logger) *Client {
	return &Client{
		tconfigdHost:             tconfigdHost,
		tconfigdSpiffeId:         tconfigdSpiffeId,
		x509Source:               x509Source,
		namespace:                namespace,
		verificationRulesManager: verificationRulesManager,
		logger:                   logger,
	}
}

func (c *Client) close() {
	c.closeOnce.Do(func() {
		c.conn.Close()
		close(c.send)
		close(c.done)
		c.logger.Info("Connection closed and resources released")
	})
}

func (c *Client) Start(ctx context.Context) error {
	backoff := CONNECTION_INITIAL_BACKOFF

	for retries := 0; retries < CONNECTION_MAX_RETRIES; retries++ {
		if retries > 0 {
			time.Sleep(backoff)

			backoff *= 2

			if backoff > CONNECTION_MAX_BACKOFF {
				backoff = CONNECTION_MAX_BACKOFF
			}

			jitter := time.Duration(rand.Int63n(int64(backoff) / 2))
			backoff = backoff/2 + jitter
		}

		if err := c.connect(ctx); err != nil {
			c.logger.Error("Failed to connect to tconfigd. Retrying...", zap.Error(err), zap.Int("retry", retries+1))

			continue
		}

		c.logger.Info("Successfully connected to tconfigd.")

		c.done = make(chan struct{})
		c.send = make(chan []byte, 256)

		go c.readPump()
		go c.writePump()

		backoff = CONNECTION_INITIAL_BACKOFF
		retries = 0

		select {
		case <-c.done:
			c.logger.Info("Connection closed. Attempting to reconnect...")
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down config sync client...")

			c.close()

			return ctx.Err()
		}
	}

	c.logger.Info("Max retries reached. Shutting down...")

	return fmt.Errorf("max retries reached; shutting down")
}

func (c *Client) connect(ctx context.Context) error {
	wsURL := url.URL{
		Scheme:   "wss",
		Host:     c.tconfigdHost,
		Path:     TCONFIGD_WEBSOCKET_PATH,
		RawQuery: url.Values{"namespace": {c.namespace}}.Encode(),
	}

	tlsConfig := tlsconfig.MTLSClientConfig(c.x509Source, c.x509Source, tlsconfig.AuthorizeID(c.tconfigdSpiffeId))

	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	c.logger.Info("Connecting to tconfigd's WebSocket server.", zap.String("url", wsURL.String()))

	conn, _, err := dialer.DialContext(ctx, wsURL.String(), nil)
	if err != nil {
		c.logger.Error("Failed to connect to tconfigd's websocket server.", zap.Error(err))

		return fmt.Errorf("failed to connect to tconfigd's websocket server: %w", err)
	}

	c.conn = conn

	c.logger.Info("Successfully connected to tconfigd's websocket server.", zap.String("url", wsURL.String()))

	_, message, err := conn.ReadMessage()
	if err != nil {
		c.logger.Error("Failed to read initial configuration message", zap.Error(err))

		conn.Close()

		return fmt.Errorf("failed to read initial configuration: %w", err)
	}

	var initialRuleResponse Response

	err = json.Unmarshal(message, &initialRuleResponse)
	if err != nil {
		c.logger.Error("Failed to unmarshal initial rules response", zap.Error(err))

		conn.Close()

		return fmt.Errorf("failed to unmarshal initial rules response: %w", err)
	}

	if initialRuleResponse.Type != MessageTypeInitialRulesResponse {
		c.logger.Error("Unexpected message type for initial rules response", zap.String("type", string(initialRuleResponse.Type)))

		conn.Close()

		return fmt.Errorf("unexpected message type for initial rules response: %s", initialRuleResponse.Type)
	}

	if initialRuleResponse.Status != http.StatusCreated {
		c.logger.Error("Received unexpected status code for initial rules response.", zap.Int("status", initialRuleResponse.Status), zap.ByteString("response", initialRuleResponse.Payload))

		conn.Close()

		return fmt.Errorf("received unexpected status code for initial rules response: %v", initialRuleResponse.Status)
	}

	var initialVerificationRulesResponsePayload AllActiveVerificationRulesPayload

	err = json.Unmarshal(initialRuleResponse.Payload, &initialVerificationRulesResponsePayload)
	if err != nil {
		c.logger.Error("Failed to unmarshal initial verification rules response payload", zap.Error(err))

		conn.Close()

		return fmt.Errorf("failed to unmarshal initial verification rules response payload: %w", err)
	}

	if initialVerificationRulesResponsePayload.VerificationRules == nil {
		c.logger.Error("Received empty initial verification rules")

		conn.Close()

		return fmt.Errorf("received empty initial verification rules")
	}

	c.verificationRulesManager.UpdateCompleteRules(initialVerificationRulesResponsePayload.VerificationRules)

	c.logger.Info("Received and applied initial verification rules")

	return nil
}

func (c *Client) readPump() {
	defer func() {
		c.close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(PONG_WAIT))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(PONG_WAIT))

		return nil
	})

	for {
		select {
		case <-c.done:
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.logger.Error("WebSocket connection closed unexpectedly.", zap.Error(err))
				}

				return
			}

			c.handleMessage(message)
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(PING_PERIOD)

	defer func() {
		ticker.Stop()
		c.close()
	}()

	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.send:
			if !ok {
				return
			}

			if err := c.writeMessage(websocket.TextMessage, message); err != nil {
				c.logger.Error("Failed to write message.", zap.Error(err))

				return
			}
		case <-ticker.C:
			verificationHash, err := c.verificationRulesManager.GetVerificationRulesHash()
			if err != nil {
				c.logger.Error("Error getting verification rule hash.", zap.Error(err))

				return
			}

			pingData := PingData{
				RuleHash: verificationHash,
			}

			pingPayload, err := json.Marshal(pingData)
			if err != nil {
				c.logger.Error("Failed to marshal ping data", zap.Error(err))

				return
			}

			if err := c.writeMessage(websocket.PingMessage, pingPayload); err != nil {
				c.logger.Error("Failed to write ping message.", zap.Error(err))

				return
			}
		}
	}
}

func (c *Client) writeMessage(messageType int, data []byte) error {
	c.conn.SetWriteDeadline(time.Now().Add(WRITE_WAIT))

	return c.conn.WriteMessage(messageType, data)
}

func (c *Client) handleMessage(message []byte) {
	var temp struct {
		Type MessageType `json:"type"`
	}

	if err := json.Unmarshal(message, &temp); err != nil {
		c.logger.Error("Failed to unmarshal message type.", zap.Error(err))

		return
	}

	switch temp.Type {
	case MessageTypeTraTVerificationRuleUpsertRequest,
		MessageTypeTratteriaConfigVerificationRuleUpsertRequest,
		MessageTypeRuleReconciliationRequest,
		MessageTypeTraTDeletionRequest:
		c.handleRequest(message)
	case MessageTypeGetJWKSResponse:
		c.handleResponse(message)
	default:
		c.logger.Error("Received unknown or unexpected message type.", zap.String("type", string(temp.Type)))
	}
}

func (c *Client) handleRequest(message []byte) {
	var request Request
	if err := json.Unmarshal(message, &request); err != nil {
		c.logger.Error("Failed to unmarshal request", zap.Error(err))

		return
	}

	c.logger.Debug("Received request", zap.String("id", request.ID), zap.String("type", string(request.Type)))

	switch request.Type {
	case MessageTypeTraTVerificationRuleUpsertRequest,
		MessageTypeTratteriaConfigVerificationRuleUpsertRequest:
		c.handleRuleUpsertRequest(request)
	case MessageTypeRuleReconciliationRequest:
		c.handleRuleReconciliationRequest(request)
	case MessageTypeTraTDeletionRequest:
		c.handleTraTDeletionRequest(request)
	default:
		c.logger.Error("Received unknown or unexpected request type", zap.String("type", string(request.Type)))
	}
}

func (c *Client) handleRuleUpsertRequest(request Request) {
	switch request.Type {
	case MessageTypeTraTVerificationRuleUpsertRequest:
		var serviceTraTVerificationRule v1alpha1.ServiceTraTVerificationRules

		if err := json.Unmarshal(request.Payload, &serviceTraTVerificationRule); err != nil {
			c.logger.Error("Failed to unmarshal trat verification rule", zap.Error(err))
			c.sendErrorResponse(
				request.ID,
				MessageTypeTraTVerificationRuleUpsertResponse,
				http.StatusBadRequest,
				"error parsing trat verification rule",
			)

			return
		}

		c.logger.Info("Received trat verification rule upsert request",
			zap.String("trat-name", serviceTraTVerificationRule.TraTName))

		err := c.verificationRulesManager.UpsertTraTRule(&serviceTraTVerificationRule)
		if err != nil {
			c.logger.Error("Failed to upsert trat verification rule", zap.Error(err))
			c.sendErrorResponse(
				request.ID,
				MessageTypeTraTVerificationRuleUpsertResponse,
				http.StatusInternalServerError,
				"error upserting trat verification rule",
			)

			return
		}

		err = c.sendResponse(request.ID, MessageTypeTraTVerificationRuleUpsertResponse, http.StatusOK, nil)
		if err != nil {
			c.logger.Error("Error sending trat verification upsert request response", zap.Error(err))
		}

	case MessageTypeTratteriaConfigVerificationRuleUpsertRequest:
		var verificationTratteriaConfigRule v1alpha1.TratteriaConfigVerificationRule

		if err := json.Unmarshal(request.Payload, &verificationTratteriaConfigRule); err != nil {
			c.logger.Error("Failed to unmarshal tratteria config verification rule", zap.Error(err))
			c.sendErrorResponse(
				request.ID,
				MessageTypeTratteriaConfigVerificationRuleUpsertRequest,
				http.StatusBadRequest,
				"error parsing tratteria config verification rule",
			)

			return
		}

		c.logger.Info("Received tratteria config verification rule upsert request")

		c.verificationRulesManager.UpdateTratteriaConfigRule(&verificationTratteriaConfigRule)

		err := c.sendResponse(request.ID, MessageTypeTraTVerificationRuleUpsertResponse, http.StatusOK, nil)
		if err != nil {
			c.logger.Error("Error sending trat verification upsert request response", zap.Error(err))
		}
	default:
		c.logger.Error("Received unknown or unexpected rule upsert request", zap.String("type", string(request.Type)))

		c.sendErrorResponse(
			request.ID,
			MessageTypeUnknown,
			http.StatusBadRequest,
			"received unknown or unexpected rule upsert request",
		)

		return
	}
}

func (c *Client) handleRuleReconciliationRequest(request Request) {
	c.logger.Info("Received verification rules reconciliation request")

	var verificationReconciliationRules AllActiveVerificationRulesPayload

	if err := json.Unmarshal(request.Payload, &verificationReconciliationRules); err != nil {
		c.logger.Error("Failed to unmarshal verification reconciliation rules", zap.Error(err))
		c.sendErrorResponse(
			request.ID,
			MessageTypeRuleReconciliationResponse,
			http.StatusBadRequest,
			"error parsing reconciliation verification rules",
		)

		return
	}

	c.verificationRulesManager.UpdateCompleteRules(verificationReconciliationRules.VerificationRules)

	err := c.sendResponse(request.ID, MessageTypeRuleReconciliationResponse, http.StatusOK, nil)
	if err != nil {
		c.logger.Error("Error sending verification rule reconciliation request response", zap.Error(err))
	}
}

func (c *Client) handleTraTDeletionRequest(request Request) {
	c.logger.Info("Received trat deletion request")

	var traTDeletionPayload TraTDeletionPayload

	if err := json.Unmarshal(request.Payload, &traTDeletionPayload); err != nil {
		c.logger.Error("Failed to unmarshal trat deletion request payload", zap.Error(err))
		c.sendErrorResponse(
			request.ID,
			MessageTypeTraTDeletionResponse,
			http.StatusBadRequest,
			"error parsing trat deletion request payload",
		)

		return
	}

	c.verificationRulesManager.DeleteTrat(traTDeletionPayload.TraTName)

	err := c.sendResponse(request.ID, MessageTypeTraTDeletionResponse, http.StatusOK, nil)
	if err != nil {
		c.logger.Error("Error sending trat deletion request response", zap.Error(err))
	}
}

func (c *Client) handleResponse(message []byte) {
	var response Response

	if err := json.Unmarshal(message, &response); err != nil {
		c.logger.Error("Failed to unmarshal response", zap.Error(err))

		return
	}

	if pending, ok := c.pendingRequests.Load(response.ID); ok {
		if responseChan, ok := pending.(chan Response); ok {
			select {
			case responseChan <- response:
			default:
				c.logger.Warn("Failed to send response, request might have timed out", zap.String("id", response.ID))
			}
		} else {
			c.logger.Error("Pending request value is not of expected type", zap.String("id", response.ID))
		}
	} else {
		c.logger.Error("Received response for unknown request, request might have timed out", zap.String("id", response.ID))
	}
}

func (c *Client) sendRequest(ctx context.Context, msgType MessageType, payload interface{}) (Response, error) {
	id := uuid.New().String()
	request := Request{
		ID:   id,
		Type: msgType,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	request.Payload = payloadBytes

	msgBytes, err := json.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	responseChan := make(chan Response, 1)

	c.pendingRequests.Store(id, responseChan)

	defer func() {
		c.pendingRequests.Delete(id)
		close(responseChan)
	}()

	select {
	case <-ctx.Done():
		return Response{}, fmt.Errorf("context cancelled before sending request for ID %s: %w", id, ctx.Err())
	default:
	}

	select {
	case c.send <- msgBytes:
	case <-ctx.Done():
		return Response{}, fmt.Errorf("context cancelled while trying to send request for ID %s: %w", id, ctx.Err())
	default:
		return Response{}, fmt.Errorf("send channel is full for request ID %s", id)
	}

	timer := time.NewTimer(REQUEST_TIMEOUT)
	defer timer.Stop()

	select {
	case response := <-responseChan:
		return response, nil
	case <-timer.C:
		c.logger.Error("Request timed out.", zap.String("message-type", string(request.Type)))

		return Response{}, fmt.Errorf("request timeout for ID: %s", id)
	case <-ctx.Done():
		return Response{}, fmt.Errorf("context cancelled while waiting for response for ID %s: %w", id, ctx.Err())
	}
}

func (c *Client) sendResponse(id string, respType MessageType, status int, payload interface{}) error {
	var payloadJSON json.RawMessage

	if payload != nil {
		var err error

		payloadJSON, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal response payload: %w", err)
		}
	}

	response := Response{
		ID:      id,
		Type:    respType,
		Status:  status,
		Payload: payloadJSON,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	select {
	case c.send <- responseJSON:
		return nil
	default:
		return fmt.Errorf("send channel is full")
	}
}

func (c *Client) sendErrorResponse(requestID string, messageType MessageType, statusCode int, errorMessage string) {
	err := c.sendResponse(requestID, messageType, statusCode, map[string]string{"error": errorMessage})
	if err != nil {
		c.logger.Error("Failed to send error response",
			zap.String("request-id", requestID),
			zap.Error(err))
	}
}

func (c *Client) GetJWKs(ctx context.Context) (jwk.Set, error) {
	response, err := c.sendRequest(ctx, MessageTypeGetJWKSRequest, nil)
	if err != nil {
		c.logger.Error("Error getting JWKS from tconfigd.", zap.Error(err), zap.ByteString("response", response.Payload))

		return nil, fmt.Errorf("error getting JWKS from tconfigd: %w", err)
	}

	if response.Status != http.StatusOK {
		c.logger.Error("Received non-ok status on get JWKS request.", zap.Int("status", response.Status), zap.ByteString("response", response.Payload))

		return nil, fmt.Errorf("received %v non-ok status on get JWKS request", response.Status)
	}

	return jwk.Parse(response.Payload)
}
