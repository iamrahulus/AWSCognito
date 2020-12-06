package com.amazonaws.cognito.samples;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;

import sun.security.rsa.RSAKeyFactory;

public class JWTTokenParser {

	private String jwtToken;

	private String headerJason;

	private String payloadJason;

	private JWTTokenValidator validator;

	private JWTTokenParser() {
	}

	public static void main(String sp[]) throws Exception{
		JWTTokenParser p = new JWTTokenParser();
		String jwtToken = "eyJraWQiOiJsWks2aStUZjdWangzVWNpUFpGZkU5eDAxaWROYUxsQVNDVnNHUUV4M1V3PSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJlMjYyZTViMS1hYzI4LTQ4ZGUtOWY4NC03YzIzY2E3YWE5ODAiLCJkZXZpY2Vfa2V5IjoidXMtZWFzdC0xXzFlZTUzMjAyLWVkYjItNDAwNy1hOWYxLTlhYzA5OWUzOGJjZCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9KdUhkVkVpQjUiLCJleHAiOjE1MDIzMzM5OTksImlhdCI6MTUwMjMzMDM5OSwianRpIjoiMjEyMGY3OGMtY2Q0Zi00NzU2LTk4ZTItNzIzYzU5M2Y5YTdjIiwiY2xpZW50X2lkIjoiNXBtdjNzMzQ0dDh1MGFibjJ0Z2pwa3RhNXUiLCJ1c2VybmFtZSI6ImlhbXJhaHVsdXMifQ.ID6_4xcnnoz3Wf53NIXrLobsPhiWxx56c7rIZbfwE9TnSmRmWWYq2HiFeWWeRnvsAYR-wnDwRorZmZlnXrYEm0OMAUQKM-2ARMHMftSzbWW4Is5MnziRCvfzQTsIz0aLj1rpc8EHytzBnXC6XDO3-R4G2rGnZD0yHSLP6TM9UrZbgHKNmdisZHQD9TARSByWfhr9UiSudLUwTn9tH73lf2khJ0q0hZxsBCXFackRgUu4g3nitAdGK1KkD5cl5kpi_pn7EAfE69EHlrE4C5OFvDqWc0SLyAoXtrMPNMaF_8yp1RssolJlLnDsZVhF6J_ELx1WBW8ebEjFPIOyHo8UYg";
		JWTTokenParser parser = p.buildTokenParser(jwtToken, JWTTokenValidator.COGNITO, "JuHdVEiB5", "us-east-1");
		parser.parseToken(jwtToken);
	}

	public JWTTokenParser buildTokenParser(String jwtToken, String validatorType, String userPool, String region) {
		JWTTokenParser parser = new JWTTokenParser();
		parser.jwtToken = jwtToken;
		if (validatorType != null && validatorType.equals(JWTTokenValidator.COGNITO)) {
			validator = JWTTokenValidator.getCognitoJWTValidator(userPool, region);
			System.out.println(validator);
		}

		return parser;
	}

	public void parseToken(String token) throws Exception {
		String[] jwtTokens = token.split("\\.");
		String jwtHeader = null;
		String jwtPayload = null;
		String jwtSignature = null;
		JWTParser parser = new JWTParser();

		jwtHeader = new String(Base64.getDecoder().decode(jwtTokens[0]));
		Header header = parser.parseHeader(jwtHeader);

		String keyId = header.getKeyId();
		if (keyId != null)
			this.validator.validateToken(token, keyId);

		System.out.println(jwtHeader);
		jwtPayload = new String(Base64.getDecoder().decode(jwtTokens[1]));

		Payload payload = parser.parsePayload(jwtPayload);
		System.out.println(jwtPayload);
		jwtSignature = new String(Base64.getUrlDecoder().decode(jwtTokens[2]));

		System.out.println(verifyToken(token, payload.getIssuer(), jwtHeader, jwtPayload));

	}

	public static boolean verifyToken(String token, String issuer, String header, String payload) {
		BigInteger modulus = null;
		BigInteger publicExponent = null;

		String E = "AQAB";
		String N = "o4Pely5wZwOa3IzMOGN5BoEIL8dePeYgpdf_g0hZcfpfLUlwOCEiX5rAsuNUltdffyJfK3rVoVkaarYRxY-uCszfMuVbfhgUU2D-gV6-ZkVrVb3CbS1P1UlVDAq4cwgdEEMlfusty7qNPCJ3k3WFsmBHnVGBajzO86lQ547E0QP1p_lGptwj_VDgdemAhm7iBDV_03zj7BIzXgj9vMtI76IOak6Fbs0ZSPBaZJ5PjdQKmf4kUW4O810FkVlNGvpJeM_PVJMwu4VQRLso1BzOBGBHhOQyurF_8PnoF1XAiRxFhDej398WXNowo9UikhXuvUwqt1HpHlR36tFcY--eFw";

		modulus = new BigInteger(1, Base64.getUrlDecoder().decode(N));
		publicExponent = new BigInteger(1, Base64.getUrlDecoder().decode(E));

		RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
		System.out.println("Created RSAPublic key object");
		try {
			PublicKey key = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);
			// System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
			RSAKey rsaKey = RSAKeyFactory.toRSAKey(key);
			JWTVerifier verifier = JWT.require(Algorithm.RSA256(rsaKey)).withIssuer(issuer).build();

			// verifier.String plaintext = jwtHeader + "." + jwtPayload;
			DecodedJWT jwt = verifier.verify(token);
			System.out.println("Obtained Decoded Token: " + jwt.getToken());
			String iss = jwt.getIssuer();
			if (!verifyIssuer(iss))
				return false;
			Claim jwtClaim = jwt.getClaim("token_use");

			if (!verifyClaim(jwtClaim))
				return false;

			String kid = jwt.getKeyId();
			if (!verifyKid(kid))
				return false;

			String signature = jwt.getSignature();
			if (!verifySignature(jwt.getToken(), signature, key))
				return false;

			Claim exp = jwt.getClaim("exp");
			if (!verifyExpiration(exp))
				return false;

		} catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}

	private static boolean verifyExpiration(Claim exp) {
		// TODO Auto-generated method stub
		if (exp == null)
			return false;
		Date now = new Date();
		Date expirationDate = exp.asDate();
		if (!expirationDate.after(now))
			return false;
		return true;
	}

	private static boolean verifySignature(String decodedToken, String signature, PublicKey publicKey) {

		if (decodedToken == null || signature == null || publicKey == null)
			return false;
		System.out.println("Verifying Signature: ");
		System.out.println("Signature is: " + signature);
		String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n"
				+ Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" + "-----END PUBLIC KEY-----";
		System.out.println(publicKeyPEM);
		byte signedData[] = Base64.getUrlDecoder().decode(signature);
		// verify Signature
		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(publicKey);
			String headerAndPayload = decodedToken.substring(0, decodedToken.lastIndexOf("."));
			if (headerAndPayload == null)
				return false;
			sig.update(headerAndPayload.getBytes());
			if (!sig.verify(signedData))
				return false;

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;
	}

	private static boolean verifyKid(String kid) {
		// TODO Auto-generated method stub
		if (kid == null || !kid.equals("lZK6i+Tf7Vjx3UciPZFfE9x01idNaLlASCVsGQEx3Uw=")) {
			System.out.println("Kid validation failed: " + kid);
			return false;
		}
		return true;
	}

	private static boolean verifyClaim(Claim jwtClaim) {
		// TODO Auto-generated method stub
		if (jwtClaim == null)
			return false;

		String claim = jwtClaim.asString();
		System.out.println("Claim is: " + claim);

		if (claim == null || !(claim.equals("id") || claim.equals("access"))) {
			System.out.println("Claim validation failed: " + claim);
			return false;
		}

		return true;
	}

	private static boolean verifyIssuer(String issuer) {
		if (issuer == null || !issuer.equals("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_JuHdVEiB5")) {
			System.out.println("Issuer Validation failed: " + issuer);
			return false;
		}

		return true;
	}
}