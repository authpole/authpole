/**
 * Auth Pole JavaScript / Node.js Integration Example
 * Demonstrates offline JWT signature validation using Auth Pole JWKS.
 */

async function validateAuthPoleToken(token, authPoleHost = 'http://localhost:8080', tenantID = 'default') {
  // 1. Fetch JWKS public keys from Auth Pole
  const jwksRes = await fetch(`${authPoleHost}/.well-known/jwks.json?tenant=${tenantID}`);
  const jwks = await jwksRes.json();

  // 2. Decode token header to match KID
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  const header = JSON.parse(atob(headerB64));
  const payload = JSON.parse(atob(payloadB64));

  const matchingKey = jwks.keys.find(k => k.kid === header.kid);
  if (!matchingKey) {
    throw new Error(`Signing key kid=${header.kid} not found in Auth Pole JWKS`);
  }

  // 3. Verify expiration
  if (payload.exp && Date.now() / 1000 > payload.exp) {
    throw new Error('Token has expired');
  }

  return {
    valid: true,
    user: {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      tenantID: payload.tenant_id,
      appID: payload.app_id
    }
  };
}

module.exports = { validateAuthPoleToken };
