package com.example.client_app1.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

public class AESEncryption {

    private final byte[] key;

    public AESEncryption(){
        this.key = "Y|ixU7e@CLz$r^l8g?L4SoHS3{GLVFIp".getBytes();
    }
    public AESEncryption(String key){
        this.key = key.getBytes();
    }
    public byte[] encrypt(String obj) throws Exception {
        byte[] data = obj.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(data);
    }

    public String decrypt(byte[] encryptedData) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
