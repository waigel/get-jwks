import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { GetJwksError, errorCode } from "../src/error";
import buildGetJwks from "../src/get-jwks";
import { domain } from "./constants";

const server = setupServer(
	http.get("http://localhost:8000/.well-known/openid-configuration", async () =>
		HttpResponse.json({ msg: "baam" }, { status: 500 }),
	),
	http.get("http://localhost:8001/.well-known/openid-configuration", async () =>
		HttpResponse.json({ msg: "baam" }, { status: 200 }),
	),
	http.get("http://localhost:8002/.well-known/openid-configuration", async () =>
		HttpResponse.json({ jwks_uri: "http://localhost:8002/.well-known/jwks" }),
	),
);
beforeAll(() =>
	server.listen({
		onUnhandledRequest: "error",
	}),
);
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("get-jwks", () => {
	it("should throw error if the discovery request fails", async () => {
		const getJwks = buildGetJwks({ providerDiscovery: true });
		const expectedError = {
			name: GetJwksError.name,
			code: errorCode.OPENID_CONFIGURATION_REQUEST_FAILED,
			body: { msg: "baam" },
		};
		await expect(getJwks.getJwksUri(domain)).rejects.toMatchObject(
			expectedError,
		);
	});

	it("should throw error if the discovery request has no jwks_uri property", async () => {
		const getJwks = buildGetJwks({ providerDiscovery: true });

		const expectedError = {
			name: GetJwksError.name,
			code: errorCode.NO_JWKS_URI,
		};

		await expect(
			getJwks.getJwksUri("http://localhost:8001/"),
		).rejects.toMatchObject(expectedError);
	});
});
