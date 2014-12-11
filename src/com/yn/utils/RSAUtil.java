package com.yn.utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Copyright (C), nanyang205380@sohu-inc.com.
 * @ClassName: RSAUtil   
 * @Description: RSA加密解密
 * @author YangNan(杨楠)
 * @date 2014年12月11日 上午10:58:18 
 */
public final class RSAUtil {
	
	public static final  int KEY_SIZE = 1024;
	
	public static String FILENAME;
	
	static {
		try {
			String path = RSAUtil.class.getClassLoader().getResource("").toURI().getPath();
			FILENAME = path + "RSAKey.txt";
			System.err.println(FILENAME);
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}

	/** 
     * 生成密钥对 
     * @return KeyPair
	 * @throws Exception 
     * @throws EncryptException 
     */
	public static KeyPair generateKeyPair() throws Exception {
		
		KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
		pairGenerator.initialize(KEY_SIZE, new SecureRandom());
		
		KeyPair keyPair = pairGenerator.generateKeyPair();
		saveKeyPair(keyPair);
		
		return keyPair;
	}

	 public static KeyPair getKeyPair()throws Exception{  
	     BufferedInputStream fis = new BufferedInputStream(new FileInputStream(FILENAME));
	     ObjectInputStream oos = new ObjectInputStream(fis);  
	     
	     KeyPair kp= (KeyPair) oos.readObject();  
	     
	     oos.close();  
	     fis.close();  
	     
	     return kp;  
	 }  
	
	/**
	 * @author: YangNan(杨楠)  
	 * @date: 2014年12月11日 上午11:10:37 
	 * @Title: saveKeyPair   
	 * @Description: 保存密钥  
	 * @param keyPair:    (参数说明)   
	 * @return: void    返回类型   
	 * @throws IOException 
	 * @throws:
	 */
	private static void saveKeyPair(KeyPair keyPair) throws IOException {
		
		BufferedOutputStream bos  = new BufferedOutputStream(new FileOutputStream(FILENAME));
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		oos.writeObject(keyPair);
		
		oos.close();
		bos.close();
	}
	
	/** 
     * * 生成公钥 * 
     *  
     * @param modulus * 
     * @param publicExponent * 
     * @return RSAPublicKey * 
	 * @throws Exception 
     * @throws Exception 
     */  
	public static RSAPublicKey generateRSAPublicKey(byte[] modulus,  byte[] publicExponent) throws Exception {
		
		KeyFactory factory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		
		return (RSAPublicKey) factory.generatePublic(publicKeySpec);
	}
	
	 /** 
     * * 生成私钥 * 
     *  
     * @param modulus * 
     * @param privateExponent * 
     * @return RSAPrivateKey * 
     * @throws Exception 
     */  
    public static RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) throws Exception {
    	
    	KeyFactory factory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
		
    	return (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
    }
    
    /** 
     * * 加密 * 
     *  
     * @param key 
     *            加密的密钥
     * @param data 
     *            待加密的明文数据 
     * @return 加密后的数据 
     * @throws Exception 
     */  
    public static byte[] encrypt(PublicKey pk, byte[] data) throws Exception {  
    	
    	Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
    	cipher.init(Cipher.ENCRYPT_MODE, pk);
    	 int blockSize = cipher.getBlockSize();// 获得加密块大小，如：加密前数据为128个byte，而key_size=1024  
         // 加密块大小为127  
         // byte,加密后为128个byte;因此共有2个加密块，第一个127  
         // byte第二个为1个byte  
    	 int outputSize = cipher.getOutputSize(data.length);// 获得加密块加密后块大小  
         int leavedSize = data.length % blockSize;  
         int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;  
         byte[] raw = new byte[outputSize * blocksSize];
         int i = 0;  
         while (data.length - i * blockSize > 0) {  
             if (data.length - i * blockSize > blockSize)  
                 cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);  
             else  
                 cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);  
             // 这里面doUpdate方法不可用，查看源代码后发现每次doUpdate后并没有什么实际动作除了把byte[]放到  
             // ByteArrayOutputStream中，而最后doFinal的时候才将所有的byte[]进行加密，可是到了此时加密块大小很可能已经超出了  
             // OutputSize所以只好用dofinal方法。  
             i++;  
         }  
         
    	return raw;
    }
    
    /** 
     * * 解密 * 
     *  
     * @param key 
     *            解密的密钥
     * @param raw 
     *            已经加密的数据 
     * @return 解密后的明文
     * @throws Exception 
     */  
    public static byte[] decrypt(PrivateKey pk, byte[] raw) throws Exception {
    	 Cipher cipher = Cipher.getInstance("RSA",  
                 new org.bouncycastle.jce.provider.BouncyCastleProvider());  
         cipher.init(Cipher.DECRYPT_MODE, pk);  
         int blockSize = cipher.getBlockSize();  
         ByteArrayOutputStream bout = new ByteArrayOutputStream(64);  
         int j = 0;  

         while (raw.length - j * blockSize > 0) {  
             bout.write(cipher.doFinal(raw, j * blockSize, blockSize));  
             j++;  
         }  
         
         return bout.toByteArray();  
    }
    
    /** 
     * * * 
     *  
     * @param args * 
     * @throws Exception 
     */  
    public static void main(String[] args) throws Exception {  
//    	generateKeyPair();
        String test = "hello world";  
        byte[] en_test = encrypt(getKeyPair().getPublic(),test.getBytes());  
        byte[] de_test = decrypt(getKeyPair().getPrivate(),en_test);
        
        RSAPublicKey rsap = (RSAPublicKey) RSAUtil.getKeyPair().getPublic();  
        RSAPrivateKey privateKey =  (RSAPrivateKey) RSAUtil.getKeyPair().getPrivate();
        
		System.out.println(new String(en_test));
        
//        System.out.println("公钥:"+rsap.getModulus().toString(16));
//        System.out.println("公钥:"+rsap.getPublicExponent().toString(16));
//        
        System.out.println("私钥:" + privateKey.getModulus().toString(16));
        System.out.println("私钥:" + privateKey.getPrivateExponent().toString(16));
        
        System.out.println(new String(de_test));  
    }  
}
