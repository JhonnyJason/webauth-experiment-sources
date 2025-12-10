indexdomconnect = {name: "indexdomconnect"}

############################################################
indexdomconnect.initialize = () ->
    global.webauthPubkey = document.getElementById("webauth-pubkey")
    global.passwordHash = document.getElementById("password-hash")
    global.metamaskSig = document.getElementById("metamask-sig")
    global.thingyCryptoAuth = document.getElementById("thingy-crypto-auth")
    return
    
module.exports = indexdomconnect