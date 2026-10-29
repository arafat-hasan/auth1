package main

import (
	"log/slog"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/config"
)

// cryptoKeys are the field keyring and the key files of the encryption section, and the pepper
// keyring (TDD-08 §4). The keyrings follow their files once their Run is started; the key files
// are read once.
type cryptoKeys struct {
	fields     *crypto.WatchedKeyring
	blindIndex crypto.Key
	mac        crypto.Key
	pepper     *crypto.WatchedKeyring // the pepper keyring (TDD-03 §1.1)
}

// loadCryptoKeys loads and checks the encryption section's keyring and key files and the pepper
// keyring, so that a bad one stops start-up (TDD-08 §3.1). Each failure is a problem at its key
// path; none shows a key. logger receives the keyrings' reload messages.
func loadCryptoKeys(cfg *config.Config, logger *slog.Logger) (*cryptoKeys, []*config.Problem) {
	c := cfg.Encryption
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
	if keys.pepper, err = crypto.NewWatchedKeyring(cfg.Passwords.PepperKeyringFile.Path(), crypto.StateVerify, logger); err != nil {
		fail("passwords.pepper_keyring_file", err)
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return &keys, nil
}
