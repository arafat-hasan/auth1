package config

// Environment is app.environment. Only EnvDevelopment relaxes the floors and the production-only
// rules (SDD C-3).
type Environment string

// Environments.
const (
	EnvDevelopment Environment = "development"
	EnvTest        Environment = "test"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "production"
)

// Factor is a first factor a client accepts (SDD D-6).
type Factor string

// First factors.
const (
	FactorPassword Factor = "password"
	FactorOTP      Factor = "otp"
)

// MFAPolicy is a client's MFA policy (SDD D-6, D-8).
type MFAPolicy string

// MFA policies.
const (
	MFAOptional MFAPolicy = "optional"
	MFARequired MFAPolicy = "required"
)

// OTPChannel is the channel of a client's OTP sign-in.
type OTPChannel string

// OTP channels.
const (
	OTPChannelSMS   OTPChannel = "sms"
	OTPChannelEmail OTPChannel = "email"
)

// RefreshTransport is how a client receives refresh tokens.
type RefreshTransport string

// Refresh transports.
const (
	RefreshCookie RefreshTransport = "cookie"
	RefreshBody   RefreshTransport = "body"
)

// VerifyMethod is how an identifier type is verified (TDD-01 §2).
type VerifyMethod string

// Verification methods.
const (
	VerifyEmailLink VerifyMethod = "email_link"
	VerifyEmailCode VerifyMethod = "email_code"
	VerifySMSOTP    VerifyMethod = "sms_otp"
)

// TOTPLabel is what an authenticator app shows beside the issuer.
type TOTPLabel string

// TOTP labels.
const (
	TOTPLabelEmail       TOTPLabel = "email"
	TOTPLabelDisplayName TOTPLabel = "display_name"
	TOTPLabelNone        TOTPLabel = "none"
)

// ConfirmOld is identifier_changes.confirm_old_email (SDD D-11).
type ConfirmOld string

// Old-address confirmation policies.
const (
	ConfirmOldRequired ConfirmOld = "required"
	ConfirmOldNotify   ConfirmOld = "notify"
)

// DeliveryAdapter is delivery.adapter.
type DeliveryAdapter string

// Delivery adapters. DeliveryCapture is for development only.
const (
	DeliveryNotification DeliveryAdapter = "notification"
	DeliveryDirect       DeliveryAdapter = "direct"
	DeliveryCapture      DeliveryAdapter = "capture"
)

// ServiceAuthMode is service_auth.mode.
type ServiceAuthMode string

// Service authentication modes.
const (
	ServiceAuthMesh              ServiceAuthMode = "mesh"
	ServiceAuthClientCredentials ServiceAuthMode = "client_credentials"
	ServiceAuthBoth              ServiceAuthMode = "both"
)

// MeshSource is where the mesh identity of a caller comes from.
type MeshSource string

// Mesh identity sources.
const (
	MeshSourceHeader   MeshSource = "header"
	MeshSourcePeerCert MeshSource = "peer_cert"
)

// MeshFormat is the format of the mesh identity header.
type MeshFormat string

// Mesh header formats.
const (
	MeshFormatXFCC  MeshFormat = "xfcc"
	MeshFormatPlain MeshFormat = "plain"
)
