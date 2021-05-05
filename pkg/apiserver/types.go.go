package apiserver

type CertRequest struct {
	Email        string `json:"email"`
	PublicKeyPem string `json:"public_key_pem"`
}

type CertResponse struct {
	CertPem string `json:"cert_pem"`
}
