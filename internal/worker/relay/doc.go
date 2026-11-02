// Package relay hands committed outbox rows to their destination (TDD-06 §3, TDD-08 §7). Every
// replica runs it; rows are claimed with SKIP LOCKED, so no leader is needed.
//
// Deliveries (TDD-06 §3.2, §3.3) are claimed as leases through app.DeliveryOutbox, sent through
// app.MessageDelivery outside any transaction (G-4), and recorded by outcome. The relay wakes on
// the LISTEN channel and polls as the safety net.
package relay
