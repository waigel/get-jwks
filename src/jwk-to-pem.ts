import * as jose from "node-jose";

export async function jwkToPem(jwk: object): Promise<string> {
	const key = await jose.JWK.asKey(jwk);
	return key.toPEM();
}
