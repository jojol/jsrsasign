//jquery ext sign
(function ($, undefined) {
    function is_continuous_indexed_array(src_arr) {
        let keys = [...src_arr.keys()];
        let key_all = Array.from(new Set([...keys, ...keys.keys()]));
        return keys.length === key_all.length;
    }

    $.isSet = d => Boolean(d); //0,"",null,undefined,NaN
    $.isInteger = d => Number.isInteger(d);
    $.isString = d => typeof d === 'string' || d instanceof String;
    $.isNumber = d => typeof d === 'number' || d instanceof Number;
    $.isBoolean = d => typeof d === 'boolean' || d instanceof Boolean;
    $.isSymbol = d => typeof d === 'symbol' || d instanceof Symbol;
    $.isFunction = d => typeof d === 'function';
    $.isEmpty = d => !d; //0,"",null,undefined,NaN
    $.isArray = d => Array.isArray(d);
    $.isObject = d => $.isSet(d) && (typeof d === 'object');
    $.isEmptyArr = d => $.isEmpty(d) || ($.isArray(d) && d.length <= 0); //0,"",null,undefined,NaN
    $.isNotEmptyArr = d => $.isArray(d) && d.length > 0; //0,"",null,undefined,NaN
    $.arrayLength = d => $.isArray(d) ? d.length : 0; //0,"",null,undefined,NaN
    $.isEmptyObj = d => $.isSet(d) && $.isObject(d) && $.isEmptyArr(Object.keys(d)); //0,"",null,undefined,NaN

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
        return CryptoJS.enc.Base64.stringify(encryptedWA);
    };

    $.signRSA = function (signSrc = 'aaa', prvKey = '-----BEGIN PRIVATE KEY-----...', hashAlg = 'SHA256withRSA') {
        //该方式不行 好些私钥会报错
        // let rsa = new RSAKey();
        // rsa.readPrivateKeyFromPEMString(document.form1.prvkey1.value);
        // let hashAlg = document.form1.hashalg.value;
        // let hSig = rsa.sign(document.form1.msgsigned.value, hashAlg);
        // document.form1.siggenerated.value = hSig;

        // 该方法目前验证比较稳定
        let sig = new KJUR.crypto.Signature({"alg": hashAlg});
        sig.init(prvKey);   // rsaPrivateKey of RSAKey object// initialize for signature generation
        updateSigData(sig, signSrc);
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
        updateSigData(sig, signSrc);
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

    //对数据进行排序 生成待签名的字符串
    $.makeSignData = function (data) {
        if ($.isObject(data) || $.isArray(data)) {
            let sortedData = [];
            if ($.isArray(data)) {
                for (let value of data) {
                    if ($.isObject(value) || $.isArray(value)) {
                        sortedData.push($.makeSignData(value));
                    } else {
                        sortedData.push(value.toString());
                    }
                }
                sortedData = sortedData.sort();
            } else {
                let reqKeys = Object.keys(data).sort();
                for (let key of reqKeys) {
                    let value = data[key];
                    if ($.isObject(value) || $.isArray(value)) {
                        sortedData.push($.makeSignData(value));
                    } else {
                        sortedData.push(value.toString());
                    }
                }
            }
            let result = sortedData.join('|');
            console.log(result);
            return result;
        } else {
            return data.toString();
        }
    };

    //获取随机字符串 可用来动态生成AES key 和 iv
    $.randomStr = function (len = 16) {
        let $chars = '+=ABCDEFGHIJKLMNPOQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let maxPos = $chars.length;
        let pwd = '';
        for (let i = len; i > 0; i--) {
            pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
        }
        return pwd;
    };

    //UTF8编码
    $.encodeUtf8 = function (text) {
        const code = encodeURIComponent(text);
        const bytes = [];
        for (let i = 0; i < code.length; i++) {
            const c = code.charAt(i);
            if (c === '%') {
                const hex = code.charAt(i + 1) + code.charAt(i + 2);
                const hexVal = parseInt(hex, 16);
                bytes.push(hexVal);
                i += 2;
            } else bytes.push(c.charCodeAt(0));
        }
        return bytes;
    };

    //UTF8解码
    $.decodeUtf8 = function (bytes) {
        let encoded = "";
        for (let i = 0; i < bytes.length; i++) {
            encoded += '%' + bytes[i].toString(16);
        }
        return decodeURIComponent(encoded);
    };


    const HEX_CHAR = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    //将数组转为16进制的字符串显示
    $.bytesToHexString = function (bytes) {
        let chars = [];
        for (let i = 0; i < bytes.length; i++) {
            chars.push(HEX_CHAR[bytes[i] >>> 4 & 0xf]);
            chars.push(HEX_CHAR[bytes[i] & 0xf]);
        }
        return chars.join('');
    };


    function updateSigData(sig = new KJUR.crypto.Signature({"alg": 'SHA256withRSA'}), signSrc = 'aaa') {
        // // sig.updateString(signSrc);// update data
        // let data = CryptoJS.enc.Utf8.parse(signSrc);
        // // let data = CryptoJS.enc.Hex.parse(signSrc);
        // // sig.updateHex(data.toString());// update data
        // console.log(data.toString());
        // sig.updateString(data.toString());// update data

        let data = $.bytesToHexString($.encodeUtf8(signSrc));
        console.log(data.toString());
        //如果直接传递string js这边是uriEncode -> escapse -> utf8, java 那边是直接utf8 会导致两边签名数据不一样，所以传递utf8后的字符串
        sig.updateString(data.toString());// update data
    }
})(jQuery);
