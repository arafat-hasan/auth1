package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Email    EmailConfig    `mapstructure:"email"`
	App      AppConfig      `mapstructure:"app"`
}

type ServerConfig struct {
	Port string `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type JWTConfig struct {
	PrivateKeyPath  string `mapstructure:"private_key_path"`
	PublicKeyPath   string `mapstructure:"public_key_path"`
	AccessTokenTTL  int    `mapstructure:"access_token_ttl"`
	RefreshTokenTTL int    `mapstructure:"refresh_token_ttl"`
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	PublicKeyPEM    string
}

type EmailConfig struct {
	ServiceURL string `mapstructure:"service_url"`
	Timeout    int    `mapstructure:"timeout"`
	RetryCount int    `mapstructure:"retry_count"`
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Environment string `mapstructure:"environment"`
	LogLevel    string `mapstructure:"log_level"`
	OTPLength   int    `mapstructure:"otp_length"`
	OTPTTL      int    `mapstructure:"otp_ttl"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("$HOME/.auth1")

	// Set defaults
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Load JWT keys
	if err := loadJWTKeys(&config); err != nil {
		return nil, fmt.Errorf("error loading JWT keys: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.host", "0.0.0.0")

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", "5432")
	viper.SetDefault("database.user", "auth1")
	viper.SetDefault("database.password", "password")
	viper.SetDefault("database.name", "auth1")
	viper.SetDefault("database.ssl_mode", "disable")

	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", "6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	viper.SetDefault("jwt.private_key_path", "./assets/private_key.pem")
	viper.SetDefault("jwt.public_key_path", "./assets/public_key.pem")
	viper.SetDefault("jwt.access_token_ttl", 900)     // 15 minutes
	viper.SetDefault("jwt.refresh_token_ttl", 604800) // 7 days

	viper.SetDefault("email.service_url", "http://localhost:8081")
	viper.SetDefault("email.timeout", 30)
	viper.SetDefault("email.retry_count", 3)

	viper.SetDefault("app.name", "auth1")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.log_level", "info")
	viper.SetDefault("app.otp_length", 6)
	viper.SetDefault("app.otp_ttl", 300) // 5 minutes
}

func loadJWTKeys(config *Config) error {
	// Load private key
	privateKeyData, err := os.ReadFile(config.JWT.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("error reading private key file: %w", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	// Try PKCS1 format first
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// If PKCS1 fails, try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing private key (tried both PKCS1 and PKCS8): %w", err)
		}

		// Ensure the key is RSA
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
		privateKey = rsaKey
	}

	config.JWT.PrivateKey = privateKey

	// Load public key
	publicKeyData, err := os.ReadFile(config.JWT.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("error reading public key file: %w", err)
	}

	block, _ = pem.Decode(publicKeyData)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	config.JWT.PublicKey = rsaPublicKey
	config.JWT.PublicKeyPEM = string(publicKeyData)

	return nil
}
