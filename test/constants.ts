import { readFileSync } from "node:fs";
import path from "node:path";
import jwt, { type SignOptions } from "jsonwebtoken";

// Define types for the keys and JWKS
type JWK = {
	alg?: string;
	kid: string;
	e: string;
	kty: string;
	n: string;
	use: string;
};

type JWKS = {
	keys: JWK[];
};

const domain = "http://localhost:8000/";

const jwks: JWKS = {
	keys: [
		{
			alg: "RS512",
			kid: "KEY_0",
			e: "AQAB",
			kty: "RSA",
			n: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImZmMTBmMTg1LWFiODEtNDhjYS1hZmI1LTdkY2FhMzNmYzgzNSIsImlhdCI6MTYxNDEwMzkxNiwiZXhwIjoxNjE0MTA3NTE2fQ.mLx1TZaHDhcymZFmLM7pfBhowY7CEgjuxr54LPXpGXc",
			use: "sig",
		},
		{
			alg: "RS256",
			kid: "KEY_1",
			e: "AQAB",
			kty: "RSA",
			n: "7KRDtHuJ9-R1cYzB9-E4TUVazzv93MMmMo_38nOwEKNxlWs7OVg397d0SCsdmBbcbr4KTMeblY4a-VOzLVZ5ycYgi7ZbMvv7RzunKuPsjm7m863dLnPUFOptsFVANDOHgDYopKBFYoIMoxjXU7bOzLL-Ez0oO5keT1hGZkJT_7GRvKyYigugN4lLia4Tb3AmUN60wiloyQCJ2xYATWHB0e4sTwIDq6MFXhVFHXV6ZBU7sDh0HqmP08gJtMnsFOE7zUcbpqTvpz5nAR6EyUs7R0g61WmGUfQTrE6byVCZ8w0NN4Xer6IQBjnDZWbmf69jsAFFAYDCe-omWXY526qLQw",
			use: "sig",
		},
		{
			kid: "KEY_2",
			e: "AQAB",
			kty: "RSA",
			n: "7KRDtHuJ9-R1cYzB9-E4TUVazzv93MMmMo_38nOwEKNxlWs7OVg397d0SCsdmBbcbr4KTMeblY4a-VOzLVZ5ycYgi7ZbMvv7RzunKuPsjm7m863dLnPUFOptsFVANDOHgDYopKBFYoIMoxjXU7bOzLL-Ez0oO5keT1hGZkJT_7GRvKyYigugN4lLia4Tb3AmUN60wiloyQCJ2xYATWHB0e4sTwIDq6MFXhVFHXV6ZBU7sDh0HqmP08gJtMnsFOE7zUcbpqTvpz5nAR6EyUs7R0g61WmGUfQTrE6byVCZ8w0NN4Xer6IQBjnDZWbmf69jsAFFAYDCe-omWXY526qLQw",
			use: "sig",
		},
	],
};

const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA7KRDtHuJ9+R1cYzB9+E4TUVazzv93MMmMo/38nOwEKNxlWs7
OVg397d0SCsdmBbcbr4KTMeblY4a+VOzLVZ5ycYgi7ZbMvv7RzunKuPsjm7m863d
LnPUFOptsFVANDOHgDYopKBFYoIMoxjXU7bOzLL+Ez0oO5keT1hGZkJT/7GRvKyY
igugN4lLia4Tb3AmUN60wiloyQCJ2xYATWHB0e4sTwIDq6MFXhVFHXV6ZBU7sDh0
HqmP08gJtMnsFOE7zUcbpqTvpz5nAR6EyUs7R0g61WmGUfQTrE6byVCZ8w0NN4Xe
r6IQBjnDZWbmf69jsAFFAYDCe+omWXY526qLQwIDAQABAoIBAQDhLz8uVBDqUABi
WWuLEkqdXU4YviHJHfsPSmjL0sLMUnwXj77/xq8bjvucYUr8G2UQDM+IWLn5Cw0o
DToH/q5OD7eQu6r1TUvEcUOWUOYec/JaGCzNs3MxpBNVJQq/ofljTCZI4iqkntSf
r1fYVbFcoUedzyil7gMlxf7X+G4udVpL4qF/rqeMg+8RoQVodEULvYUKC4iGvDMn
0/euHcH+Ih97pyWyCe8AoYifsBDkIYcQmX0jTnqxXcUEitiXj/bcewJXDUu2hNOK
Vr1eIJnKTZdvXQHF2UoBkQln5cBeAyNHT3QOpONo9Xed77ubwr/j/hU0A0lroNAl
zhUknOQhAoGBAP/djXqYzyu+6qKVLOGjR7r0Vz/yhdqCwlDLM7x4crCHkne8upzg
zw6x71W+mVXjZW44tSzRVaBEpPuXRq6b93yh8haYBvpWJ+AlJD3/XGpylBvdjnDK
gCM87cr/GkT+egEQysThUswANJR4KPIvkmBM4dcfu3QCEJedaYulqvBVAoGBAOzE
H6tnvJkCK4KXmfnRC0jdEZNrVBLe7VkUlV+Wx37cGWmK2K2B2APUnuCrfOwVbFIh
KL/aOiYKWUNne+2+oQOKCI7TmyOfA4mBnEqLnKbZoc5LTI5iDXbaBzvXuqhJVce4
YQqLGYxgr7dcVy9kqUFtFNmaaJhJgEBm1qGOgkU3AoGBAMC3TSK0Cga3C99dYKqq
4xIri7P8pVkJ9/YGt3cTeb8Avg81tZEHuq0k1FHO94s7dWBpkfypx0aprWJadMB7
dRMIn2DpLQhM8EfhccTInAEJQAkk/W5y98SS1cB6GH0y9w3qae+Uj1pcJT5WqvCP
aD7kaY4wtm4QSBMKWz71jyTpAoGBAJbTtW0Gr5E1XaxakR8geTTYh3rG84717nNB
9oonTjzVT2b5qWCWh5qhFvj+pZzrZM7JCuF0zngvPX//62Wfe4j6pMr/qCPAB4vQ
QlUGrStpFneJZmKJuhQNfnAz1FeiKAALx93kkMjpSube7zdkw6HHMHISuDDTGd1s
5auTUg9vAoGBAO8Mg1icLrcz1hcq2VcvD1jArMEj4KLJKbhUJdtmnO1sB2W8S3NY
8Ea83W/KVXSwHo3uaQu3Gpl/iA7ScJR8Bbxwa7oYZxrf3Vm8c63Twuy9rG/K5TPU
FNCax9JdPk5d+ufYUrVCccQaTajUcQmCEwVuyRBos2MkyVukykff+/vD
-----END RSA PRIVATE KEY-----
`;

const jwk: JWK = jwks.keys[1];

const signOptions: SignOptions = {
	algorithm: jwk.alg as "RS512" | "RS256", // Typecasting to allowed values
	issuer: domain,
	keyid: jwk.kid,
};

const token: string = jwt.sign({ name: "Jane Doe" }, privateKey, signOptions);

const oidcConfig = {
	issuer: "https://localhost/",
	jwks_uri: "https://localhost/.well-known/certs",
};

export { oidcConfig, domain, token, jwks };
