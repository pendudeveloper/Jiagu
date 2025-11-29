package com.frezrik.jiagu.pack.util;

import com.frezrik.jiagu.pack.core.AppManager;

import java.io.File;
import java.io.IOException;

public class SignUtils {

    private SignUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    /**
     * V1签名 (updated for Android 30+)
     */
    private static String signature(File unsignedApk, String keyStore, String keyPwd,
                                    String alias, String alisaPwd)
            throws InterruptedException, IOException {

        String path = unsignedApk.getAbsolutePath();
        String v1Name = path.substring(0, path.indexOf(".apk")) + "_v1.apk";

        // Updated: use SHA256 instead of SHA1 (Android 11+ warning)
        String cmd = AppManager.BIN_RUNNER +
                "jarsigner -sigalg SHA256withRSA -digestalg SHA-256 " +
                "-keystore \"" + keyStore + "\" " +
                "-storepass " + keyPwd +
                " -keypass " + alisaPwd +
                " -signedjar \"" + v1Name + "\" \"" +
                unsignedApk.getAbsolutePath() +
                "\" " + alias;

        CmdUtils.exec("v1 sign", cmd);

        FileUtils.delete(path);

        return v1Name;
    }

    /**
     * zipalign (required for Android 30+)
     * Must ensure resources.arsc is uncompressed & aligned.
     */
    private static String apkZipalign(String v1Apk)
            throws IOException, InterruptedException {

        String zipalignName = v1Apk.substring(0, v1Apk.indexOf(".apk")) + "_align.apk";

        // Updated: -f to force overwrite
        String cmd = AppManager.BIN_RUNNER +
                AppManager.BIN_PATH +
                "zipalign -f -p 4 \"" + v1Apk + "\" \"" + zipalignName + "\"";

        CmdUtils.exec("zipalign", cmd);

        FileUtils.delete(v1Apk);

        return zipalignName;
    }

    /**
     * V2/V3 signature update for Android 11–16 compatibility
     */
    public static void apkSignature(File unsignedApk, File signedApk, String keyStore,
                                    String keyPwd, String alias, String alisaPwd)
            throws IOException, InterruptedException {

        String v1Name = signature(unsignedApk, keyStore, keyPwd, alias, alisaPwd);
        String zipalignName = apkZipalign(v1Name);

        // Updated: include --v3-signing-enabled and --v4-signing-enabled=false
        String cmd = AppManager.CMD_RUNNER +
                AppManager.BIN_PATH +
                "apksigner sign " +
                "--ks \"" + keyStore + "\" " +
                "--ks-pass pass:" + keyPwd + " " +
                "--ks-key-alias " + alias + " " +
                "--key-pass pass:" + alisaPwd + " " +
                "--v1-signing-enabled true " +
                "--v2-signing-enabled true " +
                "--v3-signing-enabled true " +
                "--v4-signing-enabled false " +          // Prevents .idsig issues
                "--out \"" + signedApk.getAbsolutePath() + "\" \"" +
                zipalignName + "\"";

        CmdUtils.exec("v2 sign", cmd);

        FileUtils.delete(zipalignName);
        FileUtils.delete(signedApk.getAbsolutePath() + ".idsig");
    }
}
