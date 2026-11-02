// Package contract checks payloads auth1 produces outside its HTTP operations against the
// contracts in api/: the outbound DeliveryRequest that delivery rows hold (TDD-06 §5), and the
// password policy's reasons against Problem.reasons (TDD-03 §2).
package contract
