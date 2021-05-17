package main

type WebhookRequest struct {
	Type    string      `json:"type"`
	Version int         `json:"version"`
	Payload interface{} `json:"payload"`
	Nonce   int         `json:"nonce"`
}
