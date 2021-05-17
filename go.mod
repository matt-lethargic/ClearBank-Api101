module clear.bank/api101

go 1.16

replace clear.bank/digitalSignature => ../clearbank-digitalsignature

require (
	clear.bank/digitalSignature v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
)
