package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

// jwksCacheControl lets clients and proxies keep the JWKS for 5 minutes (TDD-04 §5.2).
const jwksCacheControl = "public, max-age=300"

// errNoKeySet answers the JWKS before the keyring's first sync.
var errNoKeySet = &domain.Error{Code: domain.CodeUnavailable, Detail: "The key set is not available yet."}

// MetadataOptions describe the deployment for /.well-known/oauth-authorization-server.
type MetadataOptions struct {
	Issuer            string // http.issuer
	BasePath          string // http.base_path
	ClientCredentials bool   // service_auth.mode is client_credentials or both
}

// serverMetadata builds the metadata of TDD-04 §5.4. Its URLs are the issuer's origin, then the
// base path, then the route.
func serverMetadata(m MetadataOptions) (gen.ServerMetadata, error) {
	u, err := url.Parse(m.Issuer)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return gen.ServerMetadata{}, fmt.Errorf("metadata: issuer %q is not an absolute URL", m.Issuer)
	}
	base := u.Scheme + "://" + u.Host + m.BasePath
	ptr := func(v string) *string { return &v }
	list := func(v ...string) *[]string { return &v }
	md := gen.ServerMetadata{
		Issuer:                m.Issuer,
		JwksUri:               base + "/.well-known/jwks.json",
		IntrospectionEndpoint: ptr(base + "/v1/introspect"),
	}
	if m.ClientCredentials {
		md.TokenEndpoint = ptr(base + "/v1/oauth/token")
		md.TokenEndpointAuthMethodsSupported = list("private_key_jwt")
		md.TokenEndpointAuthSigningAlgValuesSupported = list("RS256", "ES256")
		md.GrantTypesSupported = list("client_credentials")
	}
	return md, nil
}

// GetServerMetadata serves /.well-known/oauth-authorization-server.
func (a *API) GetServerMetadata(context.Context, gen.GetServerMetadataRequestObject) (gen.GetServerMetadataResponseObject, error) {
	return gen.GetServerMetadata200JSONResponse(a.metadata), nil
}

// GetJwks serves /.well-known/jwks.json: the published keys, with a strong ETag over the body,
// and 304 for a matching If-None-Match.
func (a *API) GetJwks(_ context.Context, req gen.GetJwksRequestObject) (gen.GetJwksResponseObject, error) {
	keys, ok := a.keys.Published()
	if !ok {
		return nil, errNoKeySet
	}
	set := gen.Jwks{Keys: make([]gen.Jwk, 0, len(keys))}
	for _, k := range keys {
		j, err := jwk(k)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, j)
	}
	// The same encoding as GetJwks200JSONResponse writes, so the tag is over the bytes sent.
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(set); err != nil {
		return nil, fmt.Errorf("encode the JWKS: %w", err)
	}
	sum := sha256.Sum256(body.Bytes())
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
	cc := jwksCacheControl
	if req.Params.IfNoneMatch != nil && noneMatch(*req.Params.IfNoneMatch, etag) {
		return gen.GetJwks304Response{Headers: gen.GetJwks304ResponseHeaders{CacheControl: &cc, ETag: &etag}}, nil
	}
	return gen.GetJwks200JSONResponse{Body: set, Headers: gen.GetJwks200ResponseHeaders{CacheControl: &cc, ETag: &etag}}, nil
}

// noneMatch reports whether an If-None-Match value matches etag: "*", or a listed tag equal to it
// by the weak comparison of RFC 9110 §13.1.2 (W/ ignored).
func noneMatch(header, etag string) bool {
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || strings.TrimPrefix(tag, "W/") == etag {
			return true
		}
	}
	return false
}

// jwk returns the public JWK of k (RFC 7517, RFC 7518 §6).
func jwk(k app.PublicKey) (gen.Jwk, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	var j gen.Jwk
	var err error
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		err = j.FromJwk0(gen.Jwk0{
			Kty: gen.RSA, Kid: k.Kid, Use: gen.Jwk0UseSig, Alg: gen.RS256,
			N: b64(pub.N.Bytes()), E: b64(big.NewInt(int64(pub.E)).Bytes()),
		})
	case *ecdsa.PublicKey:
		var pt []byte
		if pt, err = pub.Bytes(); err != nil { // 0x04 || X || Y, each 32 bytes for P-256
			break
		}
		n := (len(pt) - 1) / 2
		err = j.FromJwk1(gen.Jwk1{
			Kty: gen.EC, Kid: k.Kid, Use: gen.Jwk1UseSig, Alg: gen.ES256, Crv: gen.P256,
			X: b64(pt[1 : 1+n]), Y: b64(pt[1+n:]),
		})
	default:
		err = fmt.Errorf("key %s: a %T key", k.Kid, k.Key)
	}
	if err != nil {
		return gen.Jwk{}, fmt.Errorf("JWK of %s: %w", k.Kid, err)
	}
	return j, nil
}
