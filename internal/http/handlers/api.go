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

	keys     app.PublicKeys
	metadata gen.ServerMetadata
}

// NewAPI returns the API serving keys as the JWKS and the metadata m describes.
func NewAPI(keys app.PublicKeys, m MetadataOptions) (*API, error) {
	md, err := serverMetadata(m)
	if err != nil {
		return nil, err
	}
	return &API{keys: keys, metadata: md}, nil
}
