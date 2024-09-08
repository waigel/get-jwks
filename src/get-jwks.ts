import { LRUCache } from "lru-cache";
import { jwkToPem } from "../src/jwk-to-pem";
import { GetJwksError, errorCode } from "./error";

const ONE_MINUTE = 60 * 1000;

function ensureTrailingSlash(domain: string | undefined): string {
	if (!domain) return "";
	return domain[domain.length - 1] === "/" ? domain : `${domain}/`;
}

function ensureNoLeadingSlash(path: string): string {
	return path[0] === "/" ? path.substring(1) : path;
}

export type JWKSignature = { domain?: string; alg?: string; kid?: string };
export type GetPublicKeyOptions = JWKSignature;
type JWK = {
	[key: string]: PropertyKey;
	domain: string;
	alg: string;
	kid: string;
};

export type GetJwksOptions = {
	max?: number;
	ttl?: number;
	issuersWhitelist?: string[];
	providerDiscovery?: boolean;
	jwksPath?: string;
	timeout?: number;
	checkIssuer?: (domain: string) => boolean;
};

export type GetJwks = {
	getPublicKey: (options?: JWKSignature) => Promise<string>;
	getJwk: (signature: JWKSignature) => Promise<JWK>;
	getJwksUri: (normalizedDomain: string) => Promise<string>;
	cache: LRUCache<string, Promise<JWK>>;
	staleCache: LRUCache<string, JWK>;
};

function buildGetJwks(options: GetJwksOptions = {}): GetJwks {
	const max = options.max || 100;
	const ttl = options.ttl || ONE_MINUTE;
	const issuersWhitelist = (options.issuersWhitelist || []).map(
		ensureTrailingSlash,
	);
	const checkIssuer = options.checkIssuer;
	const providerDiscovery = options.providerDiscovery || false;
	const jwksPath = options.jwksPath
		? ensureNoLeadingSlash(options.jwksPath)
		: false;
	const staleCache = new LRUCache<string, JWK>({ max: max * 2, ttl });
	const cache = new LRUCache<string, Promise<JWK>>({
		max,
		ttl,
		dispose: async (value, key) => staleCache.set(key, await value),
	});

	async function getJwksUri(normalizedDomain: string): Promise<string> {
		const response = await fetch(
			`${normalizedDomain}.well-known/openid-configuration`,
		);
		const body = await response.json();

		if (!response.ok) {
			throw new GetJwksError(errorCode.OPENID_CONFIGURATION_REQUEST_FAILED, {
				response,
				body,
			});
		}

		if (!body.jwks_uri) {
			throw new GetJwksError(errorCode.NO_JWKS_URI);
		}

		return body.jwks_uri;
	}

	async function getPublicKey(options?: JWKSignature): Promise<string> {
		return await jwkToPem(await getJwk(options));
	}

	function getJwk(options?: JWKSignature): Promise<JWK> {
		const { domain, alg, kid } = options || {};
		const normalizedDomain = ensureTrailingSlash(domain);

		if (
			issuersWhitelist.length &&
			!issuersWhitelist.includes(normalizedDomain)
		) {
			const error = new GetJwksError(errorCode.DOMAIN_NOT_ALLOWED);
			return Promise.reject(error);
		}

		if (checkIssuer && !checkIssuer(normalizedDomain)) {
			const error = new GetJwksError(errorCode.DOMAIN_NOT_ALLOWED);
			return Promise.reject(error);
		}

		const cacheKey = `${alg}:${kid}:${normalizedDomain}`;
		const cachedJwk = cache.get(cacheKey);

		if (cachedJwk) {
			return cachedJwk;
		}

		const jwkPromise = retrieveJwk(normalizedDomain, alg, kid).catch((err) => {
			const stale = staleCache.get(cacheKey);

			cache.delete(cacheKey);

			if (stale) {
				return stale;
			}

			throw err;
		});

		cache.set(cacheKey, jwkPromise);

		return jwkPromise;
	}

	async function retrieveJwk(
		normalizedDomain: string,
		alg?: string,
		kid?: string,
	): Promise<JWK> {
		const jwksUri = jwksPath
			? normalizedDomain + jwksPath
			: providerDiscovery
				? await getJwksUri(normalizedDomain)
				: `${normalizedDomain}.well-known/jwks.json`;

		const response = await fetch(jwksUri, {});
		const body = await response.json();

		if (!response.ok) {
			throw new GetJwksError(errorCode.JWKS_REQUEST_FAILED, {
				response,
				body,
			});
		}

		if (!body.keys?.length) {
			throw new GetJwksError(errorCode.NO_JWKS);
		}

		const jwk = body.keys.find(
			(key: { alg: string; kid: string }) =>
				(alg === undefined || key.alg === undefined || key.alg === alg) &&
				key.kid === kid,
		);

		if (!jwk) {
			throw new GetJwksError(errorCode.JWK_NOT_FOUND);
		}

		return jwk;
	}

	return {
		getPublicKey,
		getJwk,
		getJwksUri,
		cache,
		staleCache,
	};
}

export default buildGetJwks;
