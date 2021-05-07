package apiserver

type CertRequest struct {
	Serial       string `json:"serial"`
	PublicKeyPem string `json:"public_key_pem"`
}

type CertResponse struct {
	CertPem string `json:"cert_pem"`
}
