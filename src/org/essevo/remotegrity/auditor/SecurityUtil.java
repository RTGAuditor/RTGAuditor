package org.essevo.remotegrity.auditor;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;




/**
 * This file was adapted from the Scantegrity implementation
 * (software.common.SecurityUtil) and later modified, i.e.:
 * - some of the methods were removed
 * - we do not use BouncyCastle provider
 * - references were modified
 * @author Scantegrity & Remotegrity
 *
 */
public class SecurityUtil {

	public static Cipher cipherNoPaddingNoKey = null;
	public static Cipher cipherPkcs5Padding = null;
	
	
	static MessageDigest sha = null;
	static {
		try {
			cipherNoPaddingNoKey = Cipher.getInstance("AES/ECB/NoPadding");
			cipherPkcs5Padding = Cipher.getInstance("AES/ECB/PKCS5Padding");
			sha=MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} 		
	}

	
	/**
	 * Given a message m, a secretKey skm and a public constant 
	 * it returnes the commitment to the message m.
	 * The commitment is computed as follows:
	 * sak=Encrypt C with skm
	 * h1 = SHA256(m, sak).
	 * h2 = SHA256(m, Encrypt h1 with sak)
	 * the commitment is h1h2 (h1 concatenated with h2)
	 * where E stands for Encrypt.
	 * The encryption scheme used is AES/ECB/NoPadding
	 * 
	 * @param skm - the salt used in the commitment
	 * @param c - the public constant
	 * @param m - the message to be commited to
	 * @return - a commitment to m
	 * @throws Exception
	 */
	protected static byte[] getCommitment(SecretKeySpec skm, byte[] c, byte[] m) throws Exception {

		cipherNoPaddingNoKey.init(Cipher.ENCRYPT_MODE,skm);

		byte[] sak = cipherNoPaddingNoKey.doFinal(c);
		sha.update(m,0,m.length);
		sha.update(sak,0,sak.length);
		byte[] h1 = sha.digest();
		
		SecretKeySpec sakSecretKey = new SecretKeySpec(sak,"AES");
		cipherNoPaddingNoKey.init(Cipher.ENCRYPT_MODE,sakSecretKey);
		byte[] h1c = cipherNoPaddingNoKey.doFinal(h1);
		
		sha.update(m,0,m.length);
		sha.update(h1c,0,h1c.length);
		byte[] h2 = sha.digest();
		byte[] ret = new byte[h1.length+h2.length];
		System.arraycopy(h1,0,ret,0,h1.length);
		System.arraycopy(h2,0,ret,h1.length,h2.length);
		
		return ret;
	}
	
}
