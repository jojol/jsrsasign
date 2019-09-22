//tuki jquery ext
(function ($, undefined) {
    $.decryptAES = function (base64DataStr, key, iv, mode = CryptoJS.mode.CBC, padding = CryptoJS.pad.Pkcs7) {
        let ciphertext = CryptoJS.enc.Base64.parse(base64DataStr);
        key = CryptoJS.enc.Utf8.parse(key);
        iv = CryptoJS.enc.Utf8.parse(iv);
        let decrypted = CryptoJS.AES.decrypt({key, iv, ciphertext}, key, {iv, mode, padding});
        return CryptoJS.enc.Utf8.stringify(decrypted);
    };

    $.encryptAES = function (dateStr, keyStr, ivStr, mode = CryptoJS.mode.CBC, padding = CryptoJS.pad.Pkcs7) {
        let data = CryptoJS.enc.Utf8.parse(dateStr);
        let key = CryptoJS.enc.Utf8.parse(keyStr);
        let iv = CryptoJS.enc.Utf8.parse(ivStr);
        let encryptedHex = CryptoJS.AES.encrypt(data, key, {iv, mode, padding});
        let encryptedWA = CryptoJS.enc.Hex.parse(encryptedHex.toString());
        let encryptedB64 = CryptoJS.enc.Base64.stringify(encryptedWA);
        console.log(encryptedB64);
        console.log($.decryptAES(encryptedB64, keyStr, ivStr));
        return encryptedB64;
    };


    $.signRSA = function (signSrc = 'aaa', prvKey = '-----BEGIN PRIVATE KEY-----...', hashAlg = 'SHA256withRSA') {
        // let rsa = new RSAKey();
        // rsa.readPrivateKeyFromPEMString(document.form1.prvkey1.value);
        // let hashAlg = document.form1.hashalg.value;
        // let hSig = rsa.sign(document.form1.msgsigned.value, hashAlg);
        // document.form1.siggenerated.value = hSig;

        // initialize
        let sig = new KJUR.crypto.Signature({"alg": hashAlg});
        sig.init(prvKey);   // rsaPrivateKey of RSAKey object// initialize for signature generation
        sig.updateString(signSrc);// update data
        return sig.sign();// calculate signature
    };

    $.verifyRSA = function (signSrc = 'aaa', signedStr = '', pubCert = '-----BEGIN CERTIFICATE-----...', hashAlg = 'SHA256withRSA') {
        // let sMsg = document.form1.msgverified.value;
        // let hSig = document.form1.sigverified.value;
        // let pubKey = KEYUTIL.getKey(document.form1.cert.value);
        // let isValid = pubKey.verify(sMsg, hSig);

        // initialize
        let sig = new KJUR.crypto.Signature({"alg": hashAlg}); // initialize for signature validation
        sig.init(pubCert); // signer's certificate
        sig.updateString(signSrc);// update data
        return sig.verify(signedStr); // verify signature
    };


    $.encryptRSA = function (dataStr = 'aaa', pubCert = '-----BEGIN CERTIFICATE-----...') {
        let pub_key = KEYUTIL.getKey(pubCert);
        return KJUR.crypto.Cipher.encrypt(dataStr, pub_key, 'RSA');
    };

    $.decryptRSA = function (cryptData = 'aaa', prvKey = '-----BEGIN PRIVATE KEY-----...') {
        let prv_key = KEYUTIL.getKey(prvKey);
        return KJUR.crypto.Cipher.decrypt(cryptData, prv_key, 'RSA');
    };
})(jQuery);
