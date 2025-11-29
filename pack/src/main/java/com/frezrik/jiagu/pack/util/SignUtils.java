package com.frezrik.jiagu.pack.util;

import com.android.apksig.ApkSigner;
import com.android.apksig.apk.ApkCreatorFactory;
import com.android.apksig.apk.ApkZFileCreator;
import com.android.apksig.apk.ApkZFileCreatorFactory;
import com.android.apksig.zip.ZipFormatException;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collections;

public class SignUtils {

    private SignUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    /**
     * Keep SAME API
     * V1 signing (using ApkSigner V1 mode internally)
     */
    private static String signature(
            File unsignedApk,
            String keyStore,
            String keyPwd,
            String alias,
            String alisaPwd
    ) throws IOException {

        String v1Name = unsignedApk.getAbsolutePath().replace(".apk", "_v1.apk");

        try {
            // Load keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(keyStore)) {
                ks.load(fis, keyPwd.toCharArray());
            }

            PrivateKey key = (PrivateKey) ks.getKey(alias, alisaPwd.toCharArray());
            Certificate[] certs = ks.getCertificateChain(alias);

            ApkSigner.SignerConfig signerConfig =
                    new ApkSigner.SignerConfig.Builder(alias, key, Collections.singletonList(certs[0]))
                            .build();

            // Use ApkSigner to perform V1 signing
            ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(unsignedApk)
                    .setOutputApk(new File(v1Name))
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(false)
                    .setV3SigningEnabled(false)
                    .build();

            signer.sign();

        } catch (Exception e) {
            throw new IOException("V1 signing failed", e);
        }

        return v1Name;
    }

    /**
     * SAME API
     * zipalign 4 bytes using ApkZlib (no external command)
     */
    private static String apkZipalign(String v1Apk) throws IOException {
        String aligned = v1Apk.replace(".apk", "_align.apk");

        try {
            ApkZFileCreatorFactory.ZipFileAlignment alignment =
                    new ApkZFileCreatorFactory.ZipFileAlignment(4);

            ApkZFileCreatorFactory factory = new ApkZFileCreatorFactory();
            ApkCreatorFactory.ApkCreator creator =
                    factory.make(new File(aligned), alignment);

            try (ApkZFileCreatorFactory.ApkZFileCreator z =
                         (ApkZFileCreatorFactory.ApkZFileCreator) creator) {

                z.writeZip(new File(v1Apk));
            }

        } catch (ZipFormatException e) {
            throw new IOException("Zipalign failed", e);
        }

        return aligned;
    }

    /**
     * SAME API
     * Full signing: V1 + V2 + V3
     */
    public static void apkSignature(
            File unsignedApk,
            File signedApk,
            String keyStore,
            String keyPwd,
            String alias,
            String alisaPwd
    ) throws IOException {

        // Step 1: V1 signing
        String v1Apk = signature(unsignedApk, keyStore, keyPwd, alias, alisaPwd);

        // Step 2: zipalign
        String alignedApk = apkZipalign(v1Apk);

        // Step 3: V2 + V3 signing
        try {

            KeyStore ks = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(keyStore)) {
                ks.load(fis, keyPwd.toCharArray());
            }

            PrivateKey key = (PrivateKey) ks.getKey(alias, alisaPwd.toCharArray());
            Certificate[] certs = ks.getCertificateChain(alias);

            ApkSigner.SignerConfig signerConfig =
                    new ApkSigner.SignerConfig.Builder(alias, key, Collections.singletonList(certs[0]))
                            .build();

            ApkSigner signer = new ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(new File(alignedApk))
                    .setOutputApk(signedApk)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build();

            signer.sign();

        } catch (Exception e) {
            throw new IOException("V2+V3 signing failed", e);
        }

        // Cleanup
        new File(alignedApk).delete();
        new File(v1Apk).delete();

        // Remove .idsig (v4 signature)
        File idSig = new File(signedApk.getAbsolutePath() + ".idsig");
        if (idSig.exists()) idSig.delete();
    }
}
