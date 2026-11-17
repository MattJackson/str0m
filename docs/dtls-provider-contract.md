# DTLS provider contract migration

DTLS values now belong to `str0m-proto::crypto::dtls`; `str0m::crypto::dtls` re-exports those same values. Custom providers no longer need a concrete DTLS engine just to implement the contract. Native OpenSSL uses these values without dimpl. Dimpl backends enable `str0m-proto/dtls-dimpl`, which supplies one shared conversion implementation.

`DtlsInstance::poll_output` now returns `Result<DtlsOutput<'a>, DtlsImplError>`. Custom providers must return `Ok` for existing outputs and propagate provider/conversion failures as `Err`. Callers must handle that result before consuming output or queuing packets. Unknown future dimpl outputs or SRTP profiles produce typed errors; they never become a synthetic timeout or a substituted profile.

These are upstream Rust API changes: concrete type identities are no longer dimpl's; its engine-specific error hierarchy is no longer the generic error contract. HandshakePending and ConnectionClosed retain their meaning. Other failures retain their concrete source through the error chain. ProtocolVersion remains a u16 value including unknown values, constants and Debug behavior; parser/Buf methods stay with the engine rather than the neutral value type.

KeyingMaterial retains a redacted Debug representation and wipes its own allocation on drop. Conversion from dimpl copies its exported bytes into that custody; this does not establish erasure of dimpl's source allocation or other backend secrets. SRTP profile preference and wire behavior are unchanged.

The default providers retain their feature selection. The `dtls` proto feature is the neutral contract; `dtls-dimpl` additionally enables the concrete engine adapter. This change does not alter SCTP randomness, standalone SNAP behavior, or the injected random-fill contract. Dependency graph absence, interoperability and target-specific qualification require their own executed evidence.
