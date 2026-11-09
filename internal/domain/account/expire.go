package account

// Expire decides what the expiry of a registration or invitation does to its account (TDD-02
// §2.5): a pending account is deleted, with no reason, and its identifiers are released (I-12).
// Nothing else is erased: the purge removes the rows later. ok is false for any other status, and
// the caller changes nothing.
func Expire(s Status) (d Decision, ok bool) {
	if s != StatusPending {
		return Decision{}, false
	}
	return Decision{Changed: true, Status: StatusDeleted, Effects: Effects{ReleaseIdentifiers: true}}, true
}
