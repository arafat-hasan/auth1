package config

import (
	"fmt"
	"net/url"
	"strconv"
)

// Validate applies the rules and security floors of TDD-08 §3.1 and returns every problem at once,
// joined with errors.Join and sorted by key path, or nil. The floors and the production-only rules
// are relaxed only when app.environment is development (SDD C-3).
//
// Files are checked to exist and be readable; their contents are not read. Rules about what a file
// holds (such as a keyring's single active key) belong to the packages that parse it.
func (c *Config) Validate() error {
	v := &validator{c: c, dev: c.App.Environment == EnvDevelopment}
	v.required()
	v.files()
	return joinProblems(v.problems)
}

type validator struct {
	c        *Config
	dev      bool
	problems []*Problem
}

func (v *validator) add(path, format string, args ...any) {
	v.problems = append(v.problems, &Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func index(prefix string, i int) string { return prefix + "[" + strconv.Itoa(i) + "]" }

// required checks the values that have no usable default.
func (v *validator) required() {
	c := v.c
	if c.HTTP.Issuer == "" {
		v.add("http.issuer", "required")
	} else if u, err := url.Parse(c.HTTP.Issuer); err != nil || !u.IsAbs() || u.Host == "" {
		v.add("http.issuer", "%q is not an absolute URL", c.HTTP.Issuer)
	}

	if len(c.Clients) == 0 {
		v.add("clients", "at least one client is required")
	}
	ids := map[string]bool{}
	for i, cl := range c.Clients {
		p := index("clients", i)
		switch {
		case cl.ID == "":
			v.add(p+".id", "required")
		case ids[cl.ID]:
			v.add(p+".id", "duplicate client id %q", cl.ID)
		}
		ids[cl.ID] = true
		if cl.Audience == "" {
			v.add(p+".audience", "required")
		}
	}

	if len(c.Identifiers) == 0 {
		v.add("identifiers", "an identifier policy is required")
	}

	for i, sc := range c.ServiceAuth.ClientCredentials.Clients {
		p := index("service_auth.client_credentials.clients", i)
		if sc.ID == "" {
			v.add(p+".id", "required")
		}
		if (sc.JWKSFile == "") == (sc.JWKSURI == "") {
			v.add(p, "set exactly one of jwks_file and jwks_uri")
		}
	}
}

// files checks that every configured file exists and can be read.
func (v *validator) files() {
	c := v.c
	for path, f := range map[string]SecretFile{
		"keys.keyring_file":                 c.Keys.KeyringFile,
		"encryption.keyring_file":           c.Encryption.KeyringFile,
		"encryption.blind_index_key_file":   c.Encryption.BlindIndexKeyFile,
		"encryption.mac_key_file":           c.Encryption.MACKeyFile,
		"encryption.device_cookie_key_file": c.Encryption.DeviceCookieKeyFile,
		"passwords.pepper_keyring_file":     c.Passwords.PepperKeyringFile,
		"database.dsn_file":                 c.Database.DSNFile,
		"amqp.url_file":                     c.AMQP.URLFile,
	} {
		v.requiredFile(path, f.Path())
	}
	v.requiredFile("passwords.deny_list_file", c.Passwords.DenyListFile)

	v.optionalFile("redis.password_file", c.Redis.PasswordFile.Path())
	v.optionalFile("bootstrap.emails_file", c.Bootstrap.EmailsFile.Path())

	if c.Delivery.Adapter == DeliveryDirect {
		d := c.Delivery.Direct
		v.optionalFile("delivery.direct.smtp.password_file", d.SMTP.PasswordFile.Path())
		v.optionalFile("delivery.direct.sms.token_file", d.SMS.TokenFile.Path())
		if d.TemplatesDir == "" {
			v.add("delivery.direct.templates_dir", "required with the direct adapter")
		} else if err := checkDir(d.TemplatesDir); err != nil {
			v.add("delivery.direct.templates_dir", "%v", err)
		}
	}
	if c.ServiceAuth.Mesh.Source == MeshSourcePeerCert {
		v.requiredFile("service_auth.mesh.ca_file", c.ServiceAuth.Mesh.CAFile)
	}
	for i, sc := range c.ServiceAuth.ClientCredentials.Clients {
		v.optionalFile(index("service_auth.client_credentials.clients", i)+".jwks_file", sc.JWKSFile)
	}
}

func (v *validator) requiredFile(path, file string) {
	if file == "" {
		v.add(path, "required")
		return
	}
	v.optionalFile(path, file)
}

func (v *validator) optionalFile(path, file string) {
	if file == "" {
		return
	}
	if err := checkFile(file); err != nil {
		v.add(path, "%v", err)
	}
}
