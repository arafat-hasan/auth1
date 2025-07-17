package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type EmailRequest struct {
	To        string            `json:"to"`
	Subject   string            `json:"subject"`
	Template  string            `json:"template"`
	Variables map[string]string `json:"variables"`
}

type EmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *logrus.Logger
	retryCount int
}

func NewClient(baseURL string, timeout time.Duration, retryCount int, logger *logrus.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger:     logger,
		retryCount: retryCount,
	}
}

func (c *Client) SendEmail(ctx context.Context, req *EmailRequest) error {
	var lastErr error

	for attempt := 0; attempt <= c.retryCount; attempt++ {
		if attempt > 0 {
			c.logger.WithFields(logrus.Fields{
				"attempt":  attempt,
				"to":       req.To,
				"template": req.Template,
			}).Info("Retrying email send")

			// Exponential backoff
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		err := c.sendEmailOnce(ctx, req)
		if err == nil {
			return nil
		}

		lastErr = err
		c.logger.WithFields(logrus.Fields{
			"attempt":  attempt,
			"error":    err.Error(),
			"to":       req.To,
			"template": req.Template,
		}).Error("Failed to send email")
	}

	return fmt.Errorf("failed to send email after %d attempts: %w", c.retryCount+1, lastErr)
}

func (c *Client) sendEmailOnce(ctx context.Context, req *EmailRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal email request: %w", err)
	}

	url := fmt.Sprintf("%s/email/send", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("email service returned status %d", resp.StatusCode)
	}

	var emailResp EmailResponse
	if err := json.NewDecoder(resp.Body).Decode(&emailResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !emailResp.Success {
		return fmt.Errorf("email service returned error: %s", emailResp.Message)
	}

	c.logger.WithFields(logrus.Fields{
		"to":       req.To,
		"template": req.Template,
	}).Info("Email sent successfully")

	return nil
}

func (c *Client) SendOTPEmail(ctx context.Context, to, otp string, purpose string) error {
	var subject string
	var template string

	switch purpose {
	case "signup":
		subject = "Verify Your Account"
		template = "signup_otp"
	case "login":
		subject = "Login Verification Code"
		template = "login_otp"
	default:
		subject = "Verification Code"
		template = "generic_otp"
	}

	req := &EmailRequest{
		To:       to,
		Subject:  subject,
		Template: template,
		Variables: map[string]string{
			"otp":    otp,
			"expiry": "5 minutes",
		},
	}

	return c.SendEmail(ctx, req)
}
