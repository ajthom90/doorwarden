package dns

// Unregister removes a type so registry tests are safe under -count=N.
func Unregister(typ string) { unregister(typ) }
