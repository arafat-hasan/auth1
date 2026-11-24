package handlers

import (
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

var _ gen.StrictServerInterface = (*API)(nil)

// API implements the operations of api/openapi.yaml on the generated strict server. Operations
// without a handler yet answer 501 through gen.Stub. Mount it with gen.Routes.
type API struct {
	gen.Stub

	keys         app.PublicKeys
	metadata     gen.ServerMetadata
	registration Registration
	signIn       SignIn
	basePath     string // http.base_path, for the refresh cookie's path

	clientCredentials ClientCredentials // nil: client credentials are off
}

// NewAPI returns the API serving keys as the JWKS, the metadata m describes, the registration
// steps of reg and the sign-in of signIn; a nil reg or signIn leaves its operations answering 501.
func NewAPI(keys app.PublicKeys, m MetadataOptions, reg Registration, signIn SignIn) (*API, error) {
	md, err := serverMetadata(m)
	if err != nil {
		return nil, err
	}
	return &API{keys: keys, metadata: md, registration: reg, signIn: signIn, basePath: m.BasePath}, nil
}
