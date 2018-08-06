package io.qwil.sensitiveinfo;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;
import io.qwil.sensitiveinfo.util.AppConstants;
import io.qwil.sensitiveinfo.view.fragments.FingerprintAuthenticationDialogFragment;
import io.qwil.sensitiveinfo.view.fragments.FingerprintUiHelper;

public class SensitiveInfoPlugin implements MethodChannel.MethodCallHandler {

    // This must have 'AndroidKeyStore' as value. Unfortunately there is no predefined constant.
    private static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

    // This is the default transformation used throughout this sample project.
    private static final String AES_DEFAULT_TRANSFORMATION = "AES/CBC/PKCS7Padding";

    private static final String KEY_ALIAS_AES = "MyAesKeyAlias";
    private static final String DELIMITER = "]";

    private FingerprintManager mFingerprintManager;
    private KeyStore mKeyStore;
    private CancellationSignal mCancellationSignal;


    private PluginRegistry.Registrar registrar;

    private SensitiveInfoPlugin(PluginRegistry.Registrar registrar) {
        this.registrar = registrar;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprintManager = (FingerprintManager) registrar.context().getSystemService(Context.FINGERPRINT_SERVICE);
            initKeyStore();
        }
    }


    @SuppressWarnings("unchecked")
    @Override
    public void onMethodCall(MethodCall methodCall, MethodChannel.Result result) {
        switch (methodCall.method) {
            case "isHardwareDetected":
                isHardwareDetected(result);
                break;
            case "hasEnrolledFingerprints":
                hasEnrolledFingerprints(result);
                break;
            case "isSensorAvailable":
                isSensorAvailable(result);
                break;
            case "getItem":
                getItem((String) methodCall.argument("key"), (Map<String, Object>) methodCall.arguments, result);
                break;
            case "setItem":
                setItem((String) methodCall.argument("key"), (String) methodCall.argument("value"), (Map<String, Object>) methodCall.arguments, result);
                break;
            case "deleteItem":
                deleteItem((String) methodCall.argument("key"), (Map<String, Object>) methodCall.arguments, result);
                break;
            case "getAllItems":
                getAllItems((Map<String, Object>) methodCall.arguments, result);
                break;
            default:
                result.notImplemented();
        }
    }

    /**
     * Checks whether the device supports fingerprint authentication and if the user has
     * enrolled at least one fingerprint.
     *
     * @return true if the user has a fingerprint capable device and has enrolled
     * one or more fingerprints
     */
    private boolean hasSetupFingerprint() {
        try {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && mFingerprintManager != null && mFingerprintManager.isHardwareDetected() && mFingerprintManager.hasEnrolledFingerprints();
        } catch (SecurityException e) {
            // Should never be thrown since we have declared the USE_FINGERPRINT permission
            // in the manifest file
            return false;
        }
    }

    private void isHardwareDetected(final MethodChannel.Result pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pm.success(mFingerprintManager.isHardwareDetected());
        } else {
            pm.success(false);
        }
    }

    private void hasEnrolledFingerprints(final MethodChannel.Result pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            pm.success(mFingerprintManager.hasEnrolledFingerprints());
        } else {
            pm.success(false);
        }
    }

    private void isSensorAvailable(final MethodChannel.Result promise) {
        if (hasSetupFingerprint()) {
            promise.success("Touch ID");
        } else {
            promise.success("none");
        }
    }

    private void getItem(String key, Map<String, Object> options, MethodChannel.Result pm) {

        String name = sharedPreferences(options);

        String value = prefs(name).getString(key, null);

        if (value != null && options.containsKey("biometric") && (Boolean) options.get("biometric")) {
            boolean showModal = options.containsKey("showModal") && (Boolean) options.get("showModal");
            //noinspection unchecked
            HashMap strings = options.containsKey("strings") ? (HashMap<String, Object>) options.get("strings") : new HashMap();

            decryptWithAes(value, showModal, strings, pm, null);
        } else {
            pm.success(value);
        }
    }

    private void setItem(String key, String value, Map<String, Object> options, MethodChannel.Result pm) {
        String name = sharedPreferences(options);

        if (options.containsKey("biometric") && (Boolean) options.get("biometric")) {
            boolean showModal = options.containsKey("showModal") && (Boolean) options.get("showModal");
            //noinspection unchecked
            HashMap strings = options.containsKey("strings") ? (HashMap<String, Object>) options.get("strings") : new HashMap();

            putExtraWithAES(key, value, prefs(name), showModal, strings, pm, null);
        } else {
            try {
                putExtra(key, value, prefs(name));
                pm.success(value);
            } catch (Exception e) {
                pm.error("SensitiveInfo", e.getMessage(), null);
            }
        }
    }

    private void deleteItem(String key, Map<String, Object> options, MethodChannel.Result pm) {

        String name = sharedPreferences(options);

        SharedPreferences.Editor editor = prefs(name).edit();

        editor.remove(key).apply();

        pm.success(null);
    }

    private void getAllItems(Map<String, Object> options, MethodChannel.Result pm) {

        String name = sharedPreferences(options);

        Map<String, ?> allEntries = prefs(name).getAll();
        HashMap<String, Object> resultData = new HashMap<>();

        for (Map.Entry<String, ?> entry : allEntries.entrySet()) {
            String value = entry.getValue().toString();
            resultData.put(entry.getKey(), value);
        }
        pm.success(resultData);
    }

    @SuppressWarnings("unused")
    public void cancelFingerprintAuth() {
        if (mCancellationSignal != null && !mCancellationSignal.isCanceled()) {
            mCancellationSignal.cancel();
        }
    }

    private SharedPreferences prefs(String name) {
        return registrar.context().getSharedPreferences(name, Context.MODE_PRIVATE);
    }


    private String sharedPreferences(Map<String, Object> options) {
        String name = options.containsKey("sharedPreferencesName") ? (String) options.get("sharedPreferencesName") : "shared_preferences";
        if (name == null) {
            name = "shared_preferences";
        }
        return name;
    }


    private void putExtra(String key, Object value, SharedPreferences mSharedPreferences) {
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        if (value instanceof String) {
            editor.putString(key, (String) value).apply();
        } else if (value instanceof Boolean) {
            editor.putBoolean(key, (Boolean) value).apply();
        } else if (value instanceof Integer) {
            editor.putInt(key, (Integer) value).apply();
        } else if (value instanceof Long) {
            editor.putLong(key, (Long) value).apply();
        } else if (value instanceof Float) {
            editor.putFloat(key, (Float) value).apply();
        }
    }

    /**
     * Generates a new AES key and stores it under the { @code KEY_ALIAS_AES } in the
     * Android Keystore.
     */
    private void initKeyStore() {
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER);
            mKeyStore.load(null);

            // Check if a generated key exists under the KEY_ALIAS_AES .
            if (!mKeyStore.containsAlias(KEY_ALIAS_AES)) {
                prepareKey();
            }
        } catch (Exception ignored) {
        }
    }

    private void prepareKey() throws Exception {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M) {
            return;
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER);

        KeyGenParameterSpec.Builder builder;
        builder = new KeyGenParameterSpec.Builder(
                KEY_ALIAS_AES,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setKeySize(256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                // forces user authentication with fingerprint
                .setUserAuthenticationRequired(true);

        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }

    private void putExtraWithAES(final String key, final String value, final SharedPreferences mSharedPreferences, final boolean showModal, final HashMap strings, final MethodChannel.Result pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M && hasSetupFingerprint()) {
            try {
                if (cipher == null) {
                    SecretKey secretKey = (SecretKey) mKeyStore.getKey(KEY_ALIAS_AES, null);
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);


                    // Retrieve information about the SecretKey from the KeyStore.
                    SecretKeyFactory factory = SecretKeyFactory.getInstance(
                            secretKey.getAlgorithm(), ANDROID_KEYSTORE_PROVIDER);
                    KeyInfo info = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);

                    if (info.isUserAuthenticationRequired() &&
                            info.getUserAuthenticationValidityDurationSeconds() == -1) {

                        if (showModal) {

                            // define class as a callback
                            class PutExtraWithAESCallback implements FingerprintUiHelper.Callback {
                                @Override
                                public void onAuthenticated(FingerprintManager.AuthenticationResult result) {
                                    //noinspection ConstantConditions
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        putExtraWithAES(key, value, mSharedPreferences, true, strings, pm, result.getCryptoObject().getCipher());
                                    }
                                }

                                @Override
                                public void onError(String errorCode, CharSequence errString) {
                                    pm.error(String.valueOf(errorCode), errString.toString(), null);
                                }
                            }

                            // Show the fingerprint dialog
                            FingerprintAuthenticationDialogFragment fragment
                                    = FingerprintAuthenticationDialogFragment.newInstance(strings);
                            fragment.setCryptoObject(new FingerprintManager.CryptoObject(cipher));
                            fragment.setCallback(new PutExtraWithAESCallback());

                            fragment.show(registrar.activity().getFragmentManager(), AppConstants.DIALOG_FRAGMENT_TAG);

                        } else {
                            mCancellationSignal = new CancellationSignal();
                            mFingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher), mCancellationSignal,
                                    0, new FingerprintManager.AuthenticationCallback() {

                                        @Override
                                        public void onAuthenticationFailed() {
                                            super.onAuthenticationFailed();
                                        }

                                        @Override
                                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                                            super.onAuthenticationError(errorCode, errString);
                                            pm.error(String.valueOf(errorCode), errString.toString(), null);
                                        }

                                        @Override
                                        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                            super.onAuthenticationHelp(helpCode, helpString);
                                        }

                                        @Override
                                        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                            super.onAuthenticationSucceeded(result);
                                            //noinspection ConstantConditions
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                                putExtraWithAES(key, value, mSharedPreferences, false, strings, pm, result.getCryptoObject().getCipher());
                                            }
                                        }
                                    }, null);
                        }
                    }
                    return;
                }
                byte[] encryptedBytes = cipher.doFinal(value.getBytes());

                // Encode the initialization vector (IV) and encryptedBytes to Base64.
                String base64IV = Base64.encodeToString(cipher.getIV(), Base64.DEFAULT);
                String base64Cipher = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);

                String result = base64IV + DELIMITER + base64Cipher;

                putExtra(key, result, mSharedPreferences);
                pm.success(value);
            } catch (InvalidKeyException e) {
                try {
                    mKeyStore.deleteEntry(KEY_ALIAS_AES);
                    prepareKey();
                } catch (Exception keyResetError) {
                    pm.error("SensitiveInfo", keyResetError.getCause().getMessage(), null);
                }
                pm.error("SensitiveInfo", e.getMessage(), null);
            } catch (SecurityException e) {
                pm.error("SensitiveInfo", e.getMessage(), null);
            } catch (Exception e) {
                pm.error("SensitiveInfo", e.getMessage(), null);
            }
        } else {
            pm.error("Fingerprint not supported", "Fingerprint not supported", null);
        }
    }

    private void decryptWithAes(final String encrypted, final boolean showModal, final HashMap strings, final MethodChannel.Result pm, Cipher cipher) {

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M
                && hasSetupFingerprint()) {

            String[] inputs = encrypted.split(DELIMITER);
            if (inputs.length < 2) {
                pm.error("DecryptionFailed", "DecryptionFailed", null);
            }

            try {
                byte[] iv = Base64.decode(inputs[0], Base64.DEFAULT);
                byte[] cipherBytes = Base64.decode(inputs[1], Base64.DEFAULT);

                if (cipher == null) {
                    SecretKey secretKey = (SecretKey) mKeyStore.getKey(KEY_ALIAS_AES, null);
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION);
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

                    SecretKeyFactory factory = SecretKeyFactory.getInstance(
                            secretKey.getAlgorithm(), ANDROID_KEYSTORE_PROVIDER);
                    KeyInfo info = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);

                    if (info.isUserAuthenticationRequired() &&
                            info.getUserAuthenticationValidityDurationSeconds() == -1) {

                        if (showModal) {

                            // define class as a callback
                            class DecryptWithAesCallback implements FingerprintUiHelper.Callback {
                                @Override
                                public void onAuthenticated(FingerprintManager.AuthenticationResult result) {
                                    //noinspection ConstantConditions
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        decryptWithAes(encrypted, true, strings, pm, result.getCryptoObject().getCipher());
                                    }
                                }

                                @Override
                                public void onError(String errorCode, CharSequence errString) {
                                    pm.error(String.valueOf(errorCode), errString.toString(), null);
                                }
                            }

                            // Show the fingerprint dialog
                            FingerprintAuthenticationDialogFragment fragment
                                    = FingerprintAuthenticationDialogFragment.newInstance(strings);
                            fragment.setCryptoObject(new FingerprintManager.CryptoObject(cipher));
                            fragment.setCallback(new DecryptWithAesCallback());

                            fragment.show(registrar.activity().getFragmentManager(), AppConstants.DIALOG_FRAGMENT_TAG);

                        } else {
                            mCancellationSignal = new CancellationSignal();
                            mFingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher), mCancellationSignal,
                                    0, new FingerprintManager.AuthenticationCallback() {

                                        @Override
                                        public void onAuthenticationFailed() {
                                            super.onAuthenticationFailed();

                                        }

                                        @Override
                                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                                            super.onAuthenticationError(errorCode, errString);
                                            pm.error(String.valueOf(errorCode), errString.toString(), null);
                                        }

                                        @Override
                                        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                            super.onAuthenticationHelp(helpCode, helpString);
                                        }

                                        @Override
                                        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                            super.onAuthenticationSucceeded(result);
                                            //noinspection ConstantConditions
                                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                                decryptWithAes(encrypted, false, strings, pm, result.getCryptoObject().getCipher());
                                            }
                                        }
                                    }, null);
                        }
                    }
                    return;
                }
                byte[] decryptedBytes = cipher.doFinal(cipherBytes);
                pm.success(new String(decryptedBytes));
            } catch (InvalidKeyException e) {
                try {
                    mKeyStore.deleteEntry(KEY_ALIAS_AES);
                    prepareKey();
                } catch (Exception keyResetError) {
                    pm.error("SensitiveInfo", keyResetError.getCause().getMessage(), null);
                }
                pm.error("SensitiveInfo", e.getMessage(), null);
            } catch (SecurityException e) {
                pm.error("SensitiveInfo", e.getMessage(), null);
            } catch (Exception e) {
                pm.error("SensitiveInfo", e.getMessage(), null);
            }
        } else {
            pm.error("Fingerprint not supported", "Fingerprint not supported", null);
        }
    }

    /**
     * Plugin registration.
     */
    public static void registerWith(PluginRegistry.Registrar registrar) {
        final MethodChannel channel =
                new MethodChannel(registrar.messenger(), "io.qwil/sensitive_info");
        channel.setMethodCallHandler(new SensitiveInfoPlugin(registrar));
    }
}
