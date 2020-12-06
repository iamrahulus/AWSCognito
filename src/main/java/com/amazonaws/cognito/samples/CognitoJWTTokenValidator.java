package com.amazonaws.cognito.samples;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import sun.security.rsa.RSAKeyFactory;

public class CognitoJWTTokenValidator extends JWTTokenValidator {

	String awsRegion;

	String userPool;

	public static void main(String args[]) {
		CognitoJWTTokenValidator v = new CognitoJWTTokenValidator("us-east-1_JuHdVEiB5", "us-east-1");
	}

	public CognitoJWTTokenValidator(String userPool, String region) {
		// TODO Auto-generated constructor stub
		this.awsRegion = region;
		this.userPool = userPool;
		this.validationSource = "";
		String baseURL = "https://cognito-idp." + this.awsRegion + ".amazonaws.com/";
		if (userPool != null && userPool.contains("_"))
			this.issuer = baseURL + this.userPool;

		else
			this.issuer = baseURL + this.awsRegion + "_" + this.userPool;

		this.validationSource = this.issuer + "/.well-known/jwks.json";

		String jwksTokens = getJWKSTokens(this.validationSource);
		System.out.println("JWKS Token: " + jwksTokens);
		parseJWKS(jwksTokens);
	}

	private void parseJWKS(String jwksString) {
		// create ObjectMapper instance
		System.out.println("Parsing...");
		ObjectMapper objectMapper = new ObjectMapper();
		// read JSON like DOM Parser
		JsonNode rootNode = null;
		try {
			rootNode = objectMapper.readTree(jwksString);
			System.out.println(rootNode);
			JsonNode keys = rootNode.get("keys");
			JsonNode key = null;
			String kid = null;
			int idx = 0;
			if (keys != null) {
				while ((key = keys.get(idx)) != null) {
					kid = key.get("kid").toString();
					String e = key.get("e").toString();
					String kty = key.get("kty").toString();
					String alg = key.get("alg").toString();
					String n = key.get("n").toString();
					String use = key.get("use").toString();
					idx++;
					Key keyObject = new Key(alg, kty, n, e, use);
					KidMapper.addToKidMap(kid, keyObject);
				}
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private String getJWKSTokens(String source) {
		try {
			HttpsURLConnection httpsConnection = (HttpsURLConnection) new URL(source).openConnection();
			InputStream is = httpsConnection.getInputStream();
			BufferedInputStream bis = new BufferedInputStream(is);
			int available = bis.available();
			byte[] availableBytes = new byte[available];
			bis.read(availableBytes);
			bis.close();
			return new String(availableBytes);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean validateToken(String token, String keyId) {
		// TODO Auto-generated method stub
		BigInteger modulus = null;
		BigInteger publicExponent = null;

		// Lookup the Kid within the MAp
		if (keyId == null)
			return false;

		Key key = KidMapper.kidMap.get(keyId);
		if (key == null)
			return false;

		modulus = new BigInteger(1, Base64.getUrlDecoder().decode(key.getN()));
		publicExponent = new BigInteger(1, Base64.getUrlDecoder().decode(key.getE()));

		String algorithm = key.getAlg();
		if (algorithm == null)
			return false;

		KeySpec spec = getKeySpec(algorithm, modulus, publicExponent);
		
		
		
		if (spec == null)
			return false;

		PublicKey publicKey;
		try {
			publicKey = getPublicKey(algorithm, spec);

			// System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
			RSAKey rsaKey = null;

			JWTVerifier verifier = JWT.require(Algorithm.RSA256(rsaKey)).withIssuer(issuer).build();

			// verifier.String plaintext = jwtHeader + "." + jwtPayload;
			DecodedJWT jwt = verifier.verify(token);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}

	private PublicKey getPublicKey(String algorithm, KeySpec spec)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
		return publicKey;
	}

	private KeySpec getKeySpec(String algorithm, BigInteger modulus, BigInteger publicExponent) {
		// TODO Auto-generated method stub
		if (algorithm == null)
			return null;

		if (algorithm.equals("RSA")) {
			return new RSAPublicKeySpec(modulus, publicExponent);
		}
		
		return null;
	}

}

class KidMapper {
	static Map<String, Key> kidMap = new HashMap<String, Key>();

	private KidMapper() {

	}

	public static void addToKidMap(String kid, Key key) {
		kidMap.put(kid, key);
	}
}

class Key {
	String alg;
	String kty;
	String n;
	String e;
	String use;

	public String getAlg() {
		return alg;
	}

	public void setAlg(String alg) {
		this.alg = alg;
	}

	public String getKty() {
		return kty;
	}

	public void setKty(String kty) {
		this.kty = kty;
	}

	public String getN() {
		return n;
	}

	public void setN(String n) {
		this.n = n;
	}

	public String getE() {
		return e;
	}

	public void setE(String e) {
		this.e = e;
	}

	public void setUSe(String use) {
		this.use = use;
	}

	public String getUse() {
		return use;
	}

	public Key(String alg, String kty, String n, String e, String use) {
		super();
		this.alg = alg;
		this.kty = kty;
		this.n = n;
		this.e = e;
		this.use = use;
	}

}