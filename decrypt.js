importScripts("js/CryptoJS/components/core-min.js",
    "js/CryptoJS/rollups/aes.js",
    "js/CryptoJS/components/cipher-core-min.js",
    "js/CryptoJS/components/enc-base64-min.js",
    "js/CryptoJS/rollups/pbkdf2.js",
    "js/CryptoJS/components/enc-utf16-min.js",
    "js/CryptoJS/components/mode-cfb.js",
    "js/CryptoJS/pad-pkcs7.min.js");

self.addEventListener('fetch', function (event) {
    // console.log("REQUEST:", event.request.url);
    if (isDecryptionRequired(event.request.url)) {
        event.respondWith(
            fetch(event.request).then(function (response) {
                var init = {
                    status: response.status,
                    statusText: response.statusText,
                    headers: {'X-Foo': 'Custom Header'}
                };

                response.headers.forEach(function (v, k) {
                    init.headers[k] = v;
                });
                var ext  = event.request.url.split('.').pop().toLowerCase();
                var isMedia = (ext === 'png') || (ext === 'jpg') || (ext === 'jpeg') || (ext === 'gif');
                return response.text().then(function (body) {
                    return new Response(decryptFile(body, isMedia), init);
                });
            })
        );
    }
});

function b64toBlob(b64Data, contentType, sliceSize) {
    contentType = contentType || '';
    sliceSize = sliceSize || 512;

    var byteCharacters = atob(b64Data);
    var byteArrays = [];

    for (var offset = 0; offset < byteCharacters.length; offset += sliceSize) {
        var slice = byteCharacters.slice(offset, offset + sliceSize);

        var byteNumbers = new Array(slice.length);
        for (var i = 0; i < slice.length; i++) {
            byteNumbers[i] = slice.charCodeAt(i);
        }

        var byteArray = new Uint8Array(byteNumbers);

        byteArrays.push(byteArray);
    }

    var blob = new Blob(byteArrays, {type: contentType});
    return blob;
}


function isDecryptionRequired(filepath) {
    var ext = filepath.substring(filepath.lastIndexOf(".") + 1).toLowerCase();
    if (filepath.indexOf('cds') === -1 || filepath.lastIndexOf('video.html') !== -1) return false;
    return (ext === "html" || ext === "png" || (ext === "jpg" && filepath.indexOf("white-linen-background.jpg") === -1)
        || ext === "jpeg" || ext === "gif"
        || (ext === "js" && (filepath.indexOf("jquery.min.js") === -1 && filepath.indexOf("jquery-ui.js") === -1))
        || (ext === "m3u8"));
}

self.addEventListener('install', function (event) {
    event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', function (event) {
    event.waitUntil(self.clients.claim());
});

var salt = [0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76];
var encryptionKey = "MAYV2SPBNI99212";
var keyIV;

function decryptFile(fileContent, isMedia) {
    if (keyIV===undefined) {
        keyIV = getKeyAndIV(encryptionKey, salt);
        console.log("Key : " + keyIV.key.toString(CryptoJS.enc.Base64));
        console.log("IV : " + keyIV.iv.toString(CryptoJS.enc.Base64));
    }
    var decrypt = CryptoJS.AES.decrypt(fileContent, keyIV.key, {iv: keyIV.iv});
    var decryptedText;
    if(isMedia) {
        decryptedText = CryptoJS.enc.Base64.stringify(decrypt);
        return b64toBlob(decryptedText);
    } else {
        decryptedText = CryptoJS.enc.Utf8.stringify(decrypt)
    }
    var finalText = "";
    for (i = 0; i < decryptedText.length; i++) {
        if (decryptedText.charCodeAt(i) !== 0) {
            finalText += decryptedText[i];
        }
    }
    // console.log("Final Decrypted Text: " + finalText);
    return finalText;
}

function getKeyAndIV(password, salt, iterations) {
    var keyBitLength = 256;
    var ivBitLength = 128;
    iterations = iterations ? iterations : 1000;
    var parseSalt = hexToBase64(salt); // Base64 salt
    parseSalt = CryptoJS.enc.Base64.parse(parseSalt); // Converts base64 input string to word array
    // console.log("Parsed Salt: " + parseSalt);
    var output = CryptoJS.PBKDF2(password, parseSalt, {
        keySize: (keyBitLength + ivBitLength) / 32,
        iterations: iterations
    });
