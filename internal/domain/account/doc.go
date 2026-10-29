// Package account holds the account state machine (SDD §8.1, D-5): the statuses, the transitions
// account control may make, what each flow does in each status, and the token roles of an account
// on a client (D-6). It is pure: configuration and the time are passed in by the caller.
package account
