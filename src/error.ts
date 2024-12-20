export enum errorCode {
	OPENID_CONFIGURATION_REQUEST_FAILED = "OPENID_CONFIGURATION_REQUEST_FAILED",
	JWKS_REQUEST_FAILED = "JWKS_REQUEST_FAILED",
	NO_JWKS_URI = "NO_JWKS_URI",
	NO_JWKS = "NO_JWKS",
	JWK_NOT_FOUND = "JWK_NOT_FOUND",
	DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED",
}

const errors: { [key in errorCode]: string } = {
	[errorCode.OPENID_CONFIGURATION_REQUEST_FAILED]:
		"OpenID configuration request failed",
	[errorCode.JWKS_REQUEST_FAILED]: "JWKS request failed",
	[errorCode.NO_JWKS_URI]: "No valid jwks_uri key found in providerConfig",
	[errorCode.NO_JWKS]: "No JWKS found in the response.",
	[errorCode.JWK_NOT_FOUND]: "No matching JWK found in the set.",
	[errorCode.DOMAIN_NOT_ALLOWED]: "The domain is not allowed.",
};

export class GetJwksError extends Error {
	code: errorCode;
	response?: Response;
	body?: unknown;

	constructor(
		code: errorCode,
		requestProperties: { response?: Response; body?: unknown } = {},
	) {
		super(errors[code]);

		this.name = GetJwksError.name;
		this.code = code;
		this.response = requestProperties.response;
		this.body = requestProperties.body;
	}
}
