import { appName, appVersion } from "./configmodule.js"
import * as tbut from "thingy-byte-utils"

############################################################
algoParams = [ ## desired + required algos - all public-key
    { # ed25519 - recommended: strong + fast
        type: "public-key",
        alg: -19,
    },
    { # ed448 - recommended: very strong + slower+ larger keys
        type: "public-key",
        alg: -53,
    },
    { # ES256 - ECDSA with P256 curve and SHA256 - recommended: ~strong + fast
        type: "public-key",
        alg: -9,
    },
    { # EdDSA general ed curves - actually "deprecated"
        type: "public-key",
        alg: -8,
    },
    { # ES256 "deprecated" - replaced by -9
        type: "public-key",
        alg: -7,
    },
    { # RS256 RSASSA-PKCS1-v1_5 using SHA-256 - actually "not recommended"
        type: "public-key",
        alg: -257,
    }
]

############################################################
relayingParty = {
    name: appName,
    id: window.location.hostname,
}

############################################################
# not used - but informative ;-)
# allTransports = ["usb", "ble", "nfc", "hybrid", "internal"]

############################################################
export generateCreateOptions = (authNonceHex, userObj, contextSalt) ->
    user = {
        id: tbut.hexToBytes(userObj.userIdHex)
        name: userObj.userName
        displayName: userObj.displayName || name
    }

    prf = { eval: { first: tbut.utf8ToBytes(contextSalt) } }
        
    publicKey = {
        challenge: tbut.hexToBytes(authNonceHex),
        user: user,
        rp: relayingParty,
        pubKeyCredParams: algoParams,
        extensions: { prf },
        userVerification: "discouraged",
        attestation: "none", # could be used to track users with "direct", "indirect" allows for anonymous attestation - do we need? maybe none by default :-) 
    }

    return { publicKey }

export generateGetOptions = (authNonceHex, idHex, contextSalt) ->
    
    idBytes = tbut.hexToBytes(idHex)
    idBase64 = idBytes.toBase64({alphabet: "base64url", omitPadding: true})
    # console.log idBase64

    ## TODO maybe multiple possible Ids?
    desiredCredentials = [
        {
            id: idBytes, ## must specify an expected credentials ID
            type: "public-key",
            # transports: ... omit it -> only a "hint" without security implications 
        }
    ]


    prf = {evalByCredential:{}}
    prf.evalByCredential[idBase64] = { first: tbut.utf8ToBytes(contextSalt) }
    
    publicKey = {
        challenge: tbut.hexToBytes(authNonceHex)
        rpId: relayingParty.id
        allowCredentials: desiredCredentials
        userVerification: "discouraged"
        extensions: { prf }
    }

    return { publicKey }

