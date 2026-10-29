package main

import (
	"log/slog"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/config"
)

// cryptoKeys are the field keyring and the key files of the encryption section (TDD-08 §4). The
// field keyring follows its file once its Run is started; the key files are read once.
type cryptoKeys struct {
	fields     *crypto.WatchedKeyring
	blindIndex crypto.Key
	mac        crypto.Key
}

// loadCryptoKeys loads and checks the encryption section's keyring and key files, so that a bad
// one stops start-up (TDD-08 §3.1). Each failure is a problem at its key path; none shows a key.
// logger receives the keyring's reload messages.
func loadCryptoKeys(c config.Encryption, logger *slog.Logger) (*cryptoKeys, []*config.Problem) {
	var keys cryptoKeys
	var problems []*config.Problem
	fail := func(path string, err error) {
		problems = append(problems, &config.Problem{Path: path, Message: err.Error()})
	}
	var err error
	if keys.fields, err = crypto.NewWatchedKeyring(c.KeyringFile.Path(), crypto.StateDecrypt, logger); err != nil {
		fail("encryption.keyring_file", err)
	}
	if keys.blindIndex, err = crypto.LoadKeyFile(c.BlindIndexKeyFile.Path()); err != nil {
		fail("encryption.blind_index_key_file", err)
	}
	if keys.mac, err = crypto.LoadKeyFile(c.MACKeyFile.Path()); err != nil {
		fail("encryption.mac_key_file", err)
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return &keys, nil
}
