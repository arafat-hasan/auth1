package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Client is an SMS service client
type Client struct {
	serviceURL string
	httpClient *http.Client
	retryCount int
	logger     *logrus.Logger
}

// NewClient creates a new SMS service client
func NewClient(serviceURL string, timeout time.Duration, retryCount int, logger *logrus.Logger) *Client {
	return &Client{
		serviceURL: serviceURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		retryCount: retryCount,
		logger:     logger,
	}
}

// SendSMSRequest represents an SMS send request
type SendSMSRequest struct {
	To       string            `json:"to"`
	Message  string            `json:"message,omitempty"`
	Template string            `json:"template,omitempty"`
	Variables map[string]string `json:"variables,omitempty"`
}

// SendSMSResponse represents an SMS send response
type SendSMSResponse struct {
	Success   bool   `json:"success"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SendSMS sends an SMS via the SMS service
func (c *Client) SendSMS(ctx context.Context, req *SendSMSRequest) error {
	if c.serviceURL == "" {
		c.logger.Warn("SMS service URL not configured, skipping SMS send")
		return nil
	}

	var lastErr error
	for i := 0; i <= c.retryCount; i++ {
		if i > 0 {
			c.logger.WithFields(logrus.Fields{
				"attempt": i + 1,
				"max":     c.retryCount + 1,
			}).Info("Retrying SMS send")
			time.Sleep(time.Second * time.Duration(i))
		}

		err := c.sendSMSAttempt(ctx, req)
		if err == nil {
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("failed to send SMS after %d attempts: %w", c.retryCount+1, lastErr)
}

func (c *Client) sendSMSAttempt(ctx context.Context, req *SendSMSRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serviceURL+"/sms/send", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SMS service returned status %d", resp.StatusCode)
	}

	var smsResp SendSMSResponse
	if err := json.NewDecoder(resp.Body).Decode(&smsResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !smsResp.Success {
		return fmt.Errorf("SMS service error: %s", smsResp.Error)
	}

	c.logger.WithFields(logrus.Fields{
		"to":         req.To,
		"message_id": smsResp.MessageID,
	}).Info("SMS sent successfully")

	return nil
}

// SendOTP sends an OTP via SMS
func (c *Client) SendOTP(ctx context.Context, phone, otp string, expiryMinutes int) error {
	return c.SendSMS(ctx, &SendSMSRequest{
		To:       phone,
		Template: "otp_sms",
		Variables: map[string]string{
			"otp":    otp,
			"expiry": fmt.Sprintf("%d", expiryMinutes),
		},
	})
}

// SendPasswordReset sends a password reset link via SMS
func (c *Client) SendPasswordReset(ctx context.Context, phone, token string, expiryMinutes int) error {
	return c.SendSMS(ctx, &SendSMSRequest{
		To:       phone,
		Template: "password_reset_sms",
		Variables: map[string]string{
			"token":  token,
			"expiry": fmt.Sprintf("%d", expiryMinutes),
		},
	})
}
