import { jwtVerify, createRemoteJWKSet, JWTPayload } from 'jose';

interface Env {
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
}

// Typed responses
type Payload = any;
type APIResponse =
	| {
			success: true;
			data: Payload;
	  }
	| {
			success: false;
			error: string;
	  };

function createResponse(status: number, body: APIResponse, init?: ResponseInit): Response {
	return Response.json(body, {
		...init,
		status,
	});
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// Environment checks

		// Verify environment variables
		if (!env.POLICY_AUD) {
			return createResponse(500, { success: false, error: 'Server configuration error: Missing required audience' });
		}
		if (!env.TEAM_DOMAIN) {
			return createResponse(500, { success: false, error: 'Server configuration error: Missing required team domain' });
		}

		let privileged = false;
		let token_data: null | JWTPayload = null;

		// Get the JWT from the request headers
		const token = request.headers.get('cf-access-jwt-assertion');
		if (token) {
			try {
				// Create JWKS from your team domain
				const JWKS = createRemoteJWKSet(new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`));

				// Verify the JWT
				const { payload } = await jwtVerify(token, JWKS, {
					issuer: env.TEAM_DOMAIN,
					audience: env.POLICY_AUD,
				});

				privileged = true;
				token_data = payload;
			} catch {
				// Invalid token
				return createResponse(401, { success: false, error: 'Invalid token' });
			}
		}

		// Return the response
		return createResponse(200, { success: true, data: { privileged, token_data } });
	},
} satisfies ExportedHandler<Env>;
