// Package capture is the capture delivery adapter (TDD-06 §8.3, SDD D-16): it keeps the last
// messages in memory, values resolved, and serves them at GET /dev/messages. It is for
// development only; start-up refuses it elsewhere (SDD T-17).
package capture
