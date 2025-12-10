############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("webauthnexperiment")
#endregion

############################################################
import { encode, decode, decodeSequence } from "cbor2"
############################################################
import * as tbut from "thingy-byte-utils"
import * as secUtl from "secret-manager-crypto-utils"

############################################################
import * as S from "./statemodule.js"
############################################################
import * as srv from "./servermockmodule.js"
import * as account from "./accountmodule.js"
import { 
    generateCreateOptions, generateGetOptions 
} from "./webauthnutils.js"

############################################################
ED_FLAG = 128
AT_FLAG = 64
BS_FLAG = 16
BE_FLAG = 8
UV_FLAG = 4
UP_FLAG = 1

############################################################
## cose Keys
alg_KEY = 3 # algorithm type
kty_KEY = 1 # key type
kid_KEY = 2 # key Id
crv_KEY = -1 # curve type
xco_KEY = -2 # x coordinate on curve 
yco_KEY = -3 # y coordinate on curve
nmo_KEY = -1 # n modulus RSA
exp_KEY = -2 # e exponent RSA

############################################################
kty_TYPE_OKP = 1 # KeyType: Octet Key Pair (includes ed curves)
kty_TYPE_EC = 2 # KeyType: Elliptic curve 
kty_TYPE_RSA = 3 # KeyType: RSA

############################################################
validAlgoDict = {
    "-19": true # Ed25519
    "-53": true # ed448
    "-9": true # ecdsa with p256+sha256
    "-8": true #eddsa - crv specifies curve - deprecated
    "-7": true # ecdsa with sha256 - deprecated
    "-257": true # RS256 RSASSA-PKCS1-v1_5 using SHA-256 - not recommended
}

############################################################
crvFromKey = {
    "1": "P-256"
    "2": "P-384"
    "3": "P-512"
    "4": "X25519"
    "5": "X448"
    "6": "Ed25519"
    "7": "Ed448"
    "8": "secp256k1"
}

############################################################
credentialsAPI = navigator.credentials
webCrypto = crypto.subtle

############################################################
storageObj = null
storageKey = "webauthn-experiment-storage"

############################################################
decoder = new TextDecoder("utf-8")

############################################################
nonceBuf = new Uint8Array(32)
stableNonceHex = null

############################################################
progress = null

############################################################
export initialize = ->
    log "initialize"
    storageObj = S.load(storageKey)
    if !storageObj? 
        storageObj = {}
        S.save(storageKey, storageObj, true)
    
    S.setChangeDetectionFunction(storageKey, (() -> return true))
    olog storageObj
    return

############################################################
save = (obj) ->
    if obj? then storageObj = obj 
    S.save(storageKey, storageObj)
    return

############################################################
generateRandomNonce = ->
    crypto.getRandomValues(nonceBuf)
    return tbut.bytesToHex(nonceBuf)

############################################################
validateAuthorizationData = (creds, authNonce, accData, rpId) ->
    progress = "validateAuthorizationData"
    idHex = tbut.bytesToHex(creds.rawId)
    if !(idHex == accData.credentialsId) then return "Invalid CredentialsId!"
    progress = "valid credentials Id"

    if !creds.response? then return "No Response!"
    resp = creds.response
    progress = "response exists"

    if !(resp instanceof AuthenticatorAssertionResponse)
        return "Invalid Response!"
    progress = "valid Response Object"

    clientExtensionResults = creds.getClientExtensionResults()
    # olog clientExtensionResults
    # console.log()
    progress = "retrieved extensionResults"

    clientDataString = decoder.decode(resp.clientDataJSON)
    clientData = JSON.parse(clientDataString)
    # olog clientData

    if !(clientData.type == "webauthn.get") then return "Error in clientData.type!"
    progress = "validated clientData.type"

    nonceBytes = Uint8Array.fromBase64(clientData.challenge, {alphabet:"base64url"})
    nonceHex = tbut.bytesToHex(nonceBytes)
    if !(nonceHex == authNonce) then return "authNonce did not match!"
    if !(window.location.origin == clientData.origin) then return "origin did not match!"
    ## Don't support cross origin for now
    if clientData.crossOrigin then return "CrossOrigin not allowed here!"
    progress = "validated clientData"

    clientDataHashHex = await secUtl.sha256(resp.clientDataJSON)
    clientDataHash = tbut.hexToBytes(clientDataHashHex)
    sig = new Uint8Array(resp.signature)
    sigHex = tbut.bytesToHex(sig)
    log "sig: "+sigHex
    progress = "retrieved signature and dataHash"
    
    ## reading and checking the binaries...
    authData = new Uint8Array(resp.authenticatorData)
    # signedPayload = new Uint8Array(authData.length + authData.length)
    signedPayload = new Uint8Array([...authData, ...clientDataHash])
    # console.log(signedPayload)
    progress = "constructed signedPayload"

    # log authData.length
    # log clientDataHash.length
    # log signedPayload.length

    rpHashBytes = authData.slice(0, 32)
    flags = authData[32]
    flagsBinaryString = flags.toString(2)

    counterBytes = authData.slice(33, 37)
    counterHex = tbut.bytesToHex(counterBytes)
    counter = parseInt(counterHex, 16)
    progress = "extracted counter, rpHashBytes and flags"

    if counter < accData.sigCounter then return "SigCounter, less then the authenticators!"
    accData.sigCounter = counter
    progress = "validated counter"

    # olog {
    #     flagsBinaryString, counter
    # }

    hasExtensionData = (flags & ED_FLAG) && (flags & ED_FLAG)
    hasAttestationData = (flags & AT_FLAG) && (flags & AT_FLAG)
    setBackupSate = (flags & BS_FLAG) && (flags & BS_FLAG)
    if setBackupSate then return "Backup not supported!"
    progress = "retrieved flags and validated backupState"

    rpHashHex = tbut.bytesToHex(rpHashBytes) 
    rpIdHashHex = await secUtl.sha256(rpId)
    if !(rpIdHashHex == rpHashHex) then return "rpIdHash was not correct!"
    progress = "validated rpHash"

    if !hasExtensionData then return "No Extension Data!"
    if !clientExtensionResults.prf? then return "No PRF extension available!"
    if !clientExtensionResults.prf.results? then return "No PRF Results exist!"
    if !clientExtensionResults.prf.results.first? then return "No prf.results.first exists!"
    progress = "validated extension results"

    secret = clientExtensionResults.prf.results.first    
    secretHex = tbut.bytesToHex(secret)
    progress = "retrieved secret"

    ## Secrec should not be saved - in real implementation it would be used 
    ## to generate the full key and then deleted immediately
    # log "secretHex: "+secretHex
    
    return verifySignature(signedPayload, sig, accData.jwkPubKey)


############################################################
validateCreatedCredentials = (creds, authNonce, rpId, toSave) ->
    progress = "validateCreatedCredentials"

    if !creds.response? then return "No Response!"
    resp = creds.response
    progress = "response available"

    if !(resp instanceof AuthenticatorAttestationResponse)
        return "Invalid Response!"
    progress = "valid response Object"

    clientExtensionResults = creds.getClientExtensionResults()
    olog clientExtensionResults
    if !clientExtensionResults.prf? then return "PRF is not enabled!"
    if !clientExtensionResults.prf.enabled? then return "PRF is not enabled!"

    progress = "prf is correctly enabled!"

    clientDataString = decoder.decode(resp.clientDataJSON)
    clientData = JSON.parse(clientDataString)
    # olog clientData
    progress = "retrieved clientData"

    if !(clientData.type == "webauthn.create") then return "Error in clientData.type!"
    progress = "validated clientData.type"

    nonceBytes = Uint8Array.fromBase64(clientData.challenge, {alphabet:"base64url"})
    nonceHex = tbut.bytesToHex(nonceBytes)
    if !(nonceHex == authNonce) then return "authNonce did not match!"
    if !(window.location.origin == clientData.origin) then return "origin did not match!"
    ## Don't support cross origin for now
    if clientData.crossOrigin then return "CrossOrigin not allowed here!"
    progress = "validated clientData"
    
    clientDataHash = await secUtl.sha256(resp.clientDataJSON)
    progress = "retrieved clientData hash"

    ## Decoding the binaries...
    attestationObjBytes = new Uint8Array(resp.attestationObject)
    decoded = decode(attestationObjBytes)
    # olog decoded
    progress = "decoded attestations"

    authData = decoded.authData
    rpHashBytes = authData.slice(0, 32)
    flags = authData[32]
    counter = authData.slice(33, 37)
    progress = "extracted flags rpHashBytes and counter"

    hasExtensionData = (flags & ED_FLAG) && (flags & ED_FLAG)
    hasAttestationData = (flags & AT_FLAG) && (flags & AT_FLAG)
    setBackupSate = (flags & BS_FLAG) && (flags & BS_FLAG)
    if setBackupSate then return "Backup not supported!"

    progress = "checked flags and validated setBackupState"

    ## We donot care about user-presence or user-verification
    ## We only care about the security key from this factor 
    ## We look at it as a single factor as UP and strength of UV cannot be relied upon 

    rpHashHex = tbut.bytesToHex(rpHashBytes) 
    rpIdHashHex = await secUtl.sha256(rpId)
    if !(rpIdHashHex == rpHashHex) then return "rpIdHash was not correct!"
    progress = "validated rpHash"

    aaguid = tbut.bytesToHex(authData.slice(37,53))

    credIdLengthHex = tbut.bytesToHex(authData.slice(53, 55))
    counterHex = tbut.bytesToHex(counter)
    counter = parseInt(counterHex, 16)
    credIdLength = parseInt(credIdLengthHex, 16)

    # olog {
    #     counter, aaguid, credIdLength, credIdLengthHex
    # }

    credIdBytes = authData.slice(55, 55 + credIdLength)
    credIdHex = tbut.bytesToHex(credIdBytes)
    # log "credIdHex: "+credIdHex
    progress = "extracted credentialsId"

    rest = new Uint8Array(authData.slice(55 + credIdLength))
    # log "rest has a length of: "+rest.length
    
    pubKeyStruct = null
    for await struct from decodeSequence(rest)
        if pubKeyStruct? then break
        pubKeyStruct = struct
        algoCode = struct.get(alg_KEY)
        if !validAlgoDict[algoCode] then return "Invalid algorithm!"

    progress = "decoded rest"

    toSave.clientDataHash = clientDataHash
    toSave.sigCounter = counter
    toSave.credentialsId = credIdHex
    toSave.jwkPubKey = jwkFromPubKeyStruct(pubKeyStruct)
    progress = "created jwkPubKey"
    return

############################################################
jwkFromPubKeyStruct = (struct) ->
    # log "jwkFromPubKeyStruct"
    # console.log(struct)
    keyType = struct.get(kty_KEY)
    keyAlg = struct.get(alg_KEY)

    if keyType == kty_TYPE_OKP
        crv = struct.get(crv_KEY)
        xCoord = new Uint8Array(struct.get(xco_KEY))
        return okpToJwk(crv, xCoord)

    if keyType == kty_TYPE_EC
        crv = struct.get(crv_KEY)
        xCoord = new Uint8Array(struct.get(xco_KEY))
        yCoord = new Uint8Array(struct.get(yco_KEY))
        return ecToJwk(crv, xCoord, yCoord)

    if keyType == kty_TYPE_RSA
        moduloN = new Uint8Array(struct.get(nmo_KEY))
        exponent = new Uint8Array(struct.get(exp_KEY))
        return rsaToJwk(moduloN, exponent)
    
    console.error("Unexpected keyType: "+keyType)
    return

############################################################
okpToJwk = (crvKey, xBytes) ->
    # log "okpToJwk"
    kty = "OKP"
    crv = crvFromKey[crvKey]
    x = xBytes.toBase64({alphabet:"base64url", omitPadding: true})
    ext = true
    key_ops = ["verify"] 
    return {kty, crv, x, ext, key_ops}

ecToJwk = (crvKey, xBytes, yBytes) ->
    # log "ecToJwk"
    kty = "EC"
    crv = crvFromKey[crvKey]
    x = xBytes.toBase64({alphabet:"base64url", omitPadding: true})
    y = yBytes.toBase64({alphabet: "base64url", omitPadding: true})
    ext = true
    key_ops = ["verify"] 
    return {kty, crv, x, y, ext, key_ops}

rsaToJwk = (nBytes, eBytes) ->
    # log "rsaToJwk"
    kty = "RSA"
    n = xBytes.toBase64({alphabet:"base64url", omitPadding: true})
    e = yBytes.toBase64({alphabet: "base64url", omitPadding: true})
    ext = true
    key_ops = ["verify"] 
    return {kty, crv, x, y, ext, key_ops}


############################################################
verifySignature = (signedPayload, sig, jwkPubKey) ->
    log "verifySignature"
    algoObj = getSubtleAlgoObj(jwkPubKey)

    pubKey = await webCrypto.importKey('jwk', jwkPubKey, algoObj, false, ['verify'])
    isValid = await webCrypto.verify(algoObj, pubKey, sig.buffer, signedPayload.buffer)

    if isValid then return
    return "Invalid Signature!"

getSubtleAlgoObj = (jwkKey) ->
    switch jwkKey.kty
        when "OKP" then return { name: jwkKey.crv }
        when "EC" then return { name: "ECDSA", namedCurve: jwkKey.crv }
        when "RSA" then return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
        else throw new Error("Unsopported KeyType  in JWK!")
    return 

# import { base64url } from 'rfc4648'

# async function verify (jwsObject, jwKey) {
#   const jwsSigningInput = jwsObject.split('.').slice(0, 2).join('.')
#   const jwsSignature = jwsObject.split('.')[2]
#   return window.crypto.subtle
#     .importKey('jwk', jwKey, { 
#          name: 'RSASSA-PKCS1-v1_5', 
#          hash: { name: 'SHA-256' } 
#        }, false, ['verify'])
#     .then(key=>
#       window.crypto.subtle.verify(
#         { name: 'RSASSA-PKCS1-v1_5' },
#         key,
#         base64url.parse(jwsSignature, { loose: true }),
#         new TextEncoder().encode(jwsSigningInput))
#       ).then(isValid => alert(isValid ? 'Valid token' : 'Invalid token'))
#     )
# }

############################################################
export run = ->
    log "run"
    try
        progress = "run"

        userObj = account.getCurrentUser()
        # authNonceHex = generateRandomNonce()
        if !stableNonceHex? then stableNonceHex = generateRandomNonce()
        authNonceHex = stableNonceHex

        contextSalt = "contextcontextwhatyouknow"
        rpId =  window.location.hostname

        # olog storageObj.accountData
        if storageObj.accountData? then accPassKeyId = storageObj.accountData.credentialsId
       
        if accPassKeyId?
            alert("Case: Existing credentials!")

            progress = "we have accPassKeyId"
            getOptions = generateGetOptions(authNonceHex, accPassKeyId)
            credentials = await credentialsAPI.get(getOptions)
            progress = "credentials retrieved"
                        
            # console.log(credentials)
            err = await validateAuthorizationData(credentials, authNonceHex, storageObj.accountData, rpId)
            if err then throw new Error(err) 
            progress = "credentials validated"

            if credentials?
                credsJSON = credentials.toJSON() # This would be used to generate the data for the server
                olog credsJSON
                alert("Successfull authorization with given Credentials!\n    "+JSON.stringify(credsJSON, null, 4))
                
                response = await srv.login(credsJSON)
                if response.ok then return
        
        else # no credentials are known -> generate new ones
            alert("Case: No previous credentials!")
            progress = "no credentials Id found!"
            createOptions = generateCreateOptions(authNonceHex, userObj, contextSalt)
            credentials = await navigator.credentials.create(createOptions)
            progress = "credentials created"
            authExtract = {}

            err = await validateCreatedCredentials(credentials, authNonceHex,  rpId, authExtract)
            if err then throw new Error(err)
            progress = "credentials validated"
            alert("Successfully created Credentials on Authenticator!\n    authExtract: "+JSON.stringify(authExtract, null, 4))

            # olog authExtract
            storageObj.accountData = authExtract
            save()

            # console.log(credentials)
            # idHex = tbut.bytesToHex(credentials.rawId)
            # log idHex

            clientDataString = decoder.decode(credentials.response.clientDataJSON)
            clientData = JSON.parse(clientDataString)
            # olog clientData

            credsJSON = credentials.toJSON() # This would be used to generate the data for the server
            olog credsJSON
            
            srv.register(credsJSON)
            # srv.register(authExtract) # but maybe we use our own format :-)

    catch err
        console.error(err) 
        alert("progress state:"+progress)
        alert(err) if typeof err == "string"
        if typeof err == "object" and err instanceof Error
            alert(err.toString())
        else if typeof err == "object"
            alert(JSON.stringify(err, null, 4))
        alert("Your Authenticator seems incompatible - please try with a different authenticator :-)")
    return
