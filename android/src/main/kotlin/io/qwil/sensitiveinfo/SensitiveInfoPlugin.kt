@file:Suppress("NAME_SHADOWING")

package io.qwil.sensitiveinfo

import android.content.Context
import android.content.SharedPreferences
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec

class SensitiveInfoPlugin(private val registrar: Registrar) : MethodCallHandler {

    private lateinit var mFingerprintManager: FingerprintManager
    private lateinit var mKeyStore: KeyStore
    private lateinit var mCancellationSignal: CancellationSignal

    init {
        initKeyStore()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprintManager = registrar.context().getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        }
    }


    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "isSensorAvailable" -> isSensorAvailable(result)
            "getItem" -> getItem(call, result)
            "setItem" -> setItem(call, result)
            "deleteItem" -> deleteItem(call, result)
            "getAllItems" -> getAllItems(call, result)
            "cancelFingerprintAuth" -> cancelFingerprintAuth()
            else -> result.notImplemented()
        }
    }

    private fun isSensorAvailable(result: Result) = when {
        hasSetupFingerprint() -> result.success("Touch ID")
        else -> result.success("none")
    }

    private fun getItem(method: MethodCall, result: Result) {
        val name = sharedPreferences(method)
        val key = method.argument<String>("key")

        val value = prefs(name).getString(key, null)
        val biometric = method.argument<Boolean>("biometric")

        if (value != null && biometric != null && biometric) {
            decryptWithAes(value, result, null)
        } else {
            result.success(value)
        }
    }

    private fun setItem(method: MethodCall, result: Result) {
        val name = sharedPreferences(method)

        val biometric = method.argument<Boolean>("biometric")
        val key = method.argument<String>("key")
        val value = method.argument<String>("value")

        if (biometric != null && biometric) {
            putExtraWithAES(key, value, prefs(name), result, null)
        } else {
            try {
                putExtra(key, value, prefs(name))
                result.success(value)
            } catch (e: Exception) {
                Log.d(TAG, e.cause?.message)
                result.error(TAG, e.message, null)
            }

        }
    }

    private fun deleteItem(method: MethodCall, result: Result) {
        val name = sharedPreferences(method)
        val key = method.argument<String>("key")
        val editor = prefs(name).edit()
        editor.remove(key).apply()
        result.success(null)
    }

    private fun getAllItems(method: MethodCall, result: Result) {
        val name = sharedPreferences(method)

        val allEntries = prefs(name).all
        val resultData = HashMap<String, Any>()

        for (entry in allEntries.entries) {
            val value = entry.value.toString()
            resultData[entry.key] = value
        }
        result.success(resultData)
    }

    private fun cancelFingerprintAuth() {
        if (!mCancellationSignal.isCanceled) {
            mCancellationSignal.cancel()
        }
    }


    private fun hasSetupFingerprint(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !(!mFingerprintManager.isHardwareDetected || !mFingerprintManager.hasEnrolledFingerprints())
    }

    private fun prefs(name: String): SharedPreferences {
        return registrar.context().getSharedPreferences(name, Context.MODE_PRIVATE)
    }

    private fun sharedPreferences(methodCall: MethodCall): String {
        val sharedPreferencesName = methodCall.argument<String>("keychainName")
        return sharedPreferencesName ?: "shared_preferences"
    }


    private fun putExtra(key: String, value: Any, mSharedPreferences: SharedPreferences) {
        val editor = mSharedPreferences.edit()
        when (value) {
            is String -> editor.putString(key, value).apply()
            is Boolean -> editor.putBoolean(key, value).apply()
            is Int -> editor.putInt(key, value).apply()
            is Long -> editor.putLong(key, value).apply()
            is Float -> editor.putFloat(key, value).apply()
        }
    }

    private fun initKeyStore() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            mKeyStore.load(null)

            // Check if a generated key exists under the KEY_ALIAS_AES .
            if (!mKeyStore.containsAlias(KEY_ALIAS_AES)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER)

                val builder = KeyGenParameterSpec.Builder(
                        KEY_ALIAS_AES,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)

                builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setKeySize(256)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        // forces user authentication with fingerprint
                        .setUserAuthenticationRequired(true)

                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            }
        } catch (ignored: Exception) {
        }

    }

    private fun putExtraWithAES(key: String, value: String, mSharedPreferences: SharedPreferences, methodResult: Result, cipher: Cipher?) {
        if (hasSetupFingerprint()) {
            try {
                var cipher = cipher
                if (cipher == null) {
                    val secretKey = mKeyStore.getKey(KEY_ALIAS_AES, null) as SecretKey
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    cipher!!.init(Cipher.ENCRYPT_MODE, secretKey)

                    // Retrieve information about the SecretKey from the KeyStore.
                    val factory = SecretKeyFactory.getInstance(secretKey.algorithm, ANDROID_KEYSTORE_PROVIDER)
                    val info = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo

                    if (info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == -1) {
                        mCancellationSignal = CancellationSignal()
                        mFingerprintManager.authenticate(FingerprintManager.CryptoObject(cipher), mCancellationSignal, 0, object : FingerprintManager.AuthenticationCallback() {

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                methodResult.error("FINGERPRINT_AUTHENTICATION_HELP", "Fingerprint not recognized.", null)
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                super.onAuthenticationError(errorCode, errString)
                                methodResult.error(errorCode.toString(), errString.toString(), null)
                            }

                            override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence) {
                                super.onAuthenticationHelp(helpCode, helpString)
                                methodResult.error("FINGERPRINT_AUTHENTICATION_HELP", helpString.toString(), null)
                            }

                            override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                                super.onAuthenticationSucceeded(result)
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                    putExtraWithAES(key, value, mSharedPreferences, methodResult, result.cryptoObject.cipher)
                                }
                            }
                        }, null)
                    }
                    return
                }
                val encryptedBytes = cipher.doFinal(value.toByteArray())

                // Encode the initialization vector (IV) and encryptedBytes to Base64.
                val base64IV = Base64.encodeToString(cipher.iv, Base64.DEFAULT)
                val base64Cipher = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)

                val result = base64IV + DELIMITER + base64Cipher

                putExtra(key, result, mSharedPreferences)
                methodResult.success(value)
            } catch (e: SecurityException) {
                methodResult.error(null, e.message, null)
            } catch (e: Exception) {
                methodResult.error(null, e.message, null)
            }
        } else {
            methodResult.error(null, "Fingerprint not supported", null)
        }
    }

    private fun decryptWithAes(encrypted: String, methodResult: Result, cipher: Cipher?) {
        var cipher = cipher
        if (hasSetupFingerprint()) {

            val inputs = encrypted.split(DELIMITER.toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
            if (inputs.size < 2) {
                methodResult.error(null, "DecryptionFailed", null)
                return
            }

            try {
                val iv = Base64.decode(inputs[0], Base64.DEFAULT)
                val cipherBytes = Base64.decode(inputs[1], Base64.DEFAULT)

                if (cipher == null) {
                    val secretKey = mKeyStore.getKey(KEY_ALIAS_AES, null) as SecretKey
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    cipher!!.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

                    val factory = SecretKeyFactory.getInstance(
                            secretKey.algorithm, ANDROID_KEYSTORE_PROVIDER)
                    val info = factory.getKeySpec(secretKey, KeyInfo::class.java) as KeyInfo

                    if (info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == -1) {

                        mCancellationSignal = CancellationSignal()
                        mFingerprintManager.authenticate(FingerprintManager.CryptoObject(cipher), mCancellationSignal,
                                0, object : FingerprintManager.AuthenticationCallback() {

                            override fun onAuthenticationFailed() {
                                super.onAuthenticationFailed()
                                Log.d(TAG, "onAuthenticationFailed: ")
                                methodResult.error("FINGERPRINT_AUTHENTICATION_HELP", "Fingerprint not recognized.", null)
                            }

                            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                super.onAuthenticationError(errorCode, errString)
                                Log.d(TAG, "onAuthenticationError: $errorCode")
                                methodResult.error(errorCode.toString(), errString.toString(), null)
                            }

                            override fun onAuthenticationHelp(helpCode: Int, helpString: CharSequence) {
                                super.onAuthenticationHelp(helpCode, helpString)
                                Log.d(TAG, "onAuthenticationHelp: $helpCode")
                                methodResult.error("FINGERPRINT_AUTHENTICATION_HELP", helpString.toString(), null)
                            }

                            override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                                super.onAuthenticationSucceeded(result)
                                Log.d(TAG, "onAuthenticationSucceeded: " + result.toString())

                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                    decryptWithAes(encrypted, methodResult, result.cryptoObject.cipher)
                                }
                            }
                        }, null)
                    }
                    return
                }
                val decryptedBytes = cipher.doFinal(cipherBytes)

                Log.d("FlutterSensitiveInfo", String(decryptedBytes) + " sa")

                methodResult.success(String(decryptedBytes))
            } catch (e: SecurityException) {
                methodResult.error(null, e.message, null)
            } catch (e: Exception) {
                methodResult.error(null, e.message, null)
            }

        } else {
            methodResult.error(null, "Fingerprint not supported", null)
        }
    }


    companion object {
        @JvmStatic
        fun registerWith(registrar: Registrar) {
            val channel = MethodChannel(registrar.messenger(), "io.qwil/sensitive_info")
            channel.setMethodCallHandler(SensitiveInfoPlugin(registrar))
        }

        const val TAG = "SensitiveInfoPlugin"

        // This must have 'AndroidKeyStore' as value. Unfortunately there is no predefined constant.
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

        // This is the default transformation used throughout this sample project.
        private const val AES_DEFAULT_TRANSFORMATION = "AES/CBC/PKCS7Padding"

        private const val KEY_ALIAS_AES = "MyAesKeyAlias"
        private const val DELIMITER = "]"
    }

}
