package com.nihongo.security;
import java.nio.file.*;import java.security.*;import java.security.interfaces.*;import java.security.spec.*;import java.util.Base64;
public final class SecurityKeyFiles {
 private SecurityKeyFiles(){}
 public static Path resolve(String value){
  Path p=Path.of(value);if(Files.isRegularFile(p))return p;
  if(!p.isAbsolute()){Path alternative=Path.of("..").resolve(p);if(Files.isRegularFile(alternative))return alternative;}
  throw new IllegalStateException("Missing security key file; provision keys before starting the service");
 }
 public static byte[] bytes(String file){try{return Files.readAllBytes(resolve(file));}catch(Exception e){throw new IllegalStateException("Cannot read security key file",e);}}
 private static byte[] pem(String file){return Base64.getMimeDecoder().decode(new String(bytes(file),java.nio.charset.StandardCharsets.US_ASCII).replaceAll("-----[^-]+-----",""));}
 public static RSAPublicKey publicKey(String file){try{RSAPublicKey key=(RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pem(file)));if(key.getModulus().bitLength()<2048)throw new IllegalStateException("RSA public key is too short");return key;}catch(Exception e){throw new IllegalStateException("Invalid RSA public key",e);}}
 public static RSAPrivateKey privateKey(String file){try{return (RSAPrivateKey)KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pem(file)));}catch(Exception e){throw new IllegalStateException("Invalid RSA private key",e);}}
 public static byte[] secret(String configured,String file){byte[] key=configured==null||configured.isBlank()?Base64.getDecoder().decode(new String(bytes(file),java.nio.charset.StandardCharsets.US_ASCII).trim()):Base64.getDecoder().decode(configured);if(key.length<32)throw new IllegalStateException("Security secret must contain at least 32 random bytes");return key;}
}
