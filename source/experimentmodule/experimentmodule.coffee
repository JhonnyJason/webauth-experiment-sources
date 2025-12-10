############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("experimentmodule")
#endregion

############################################################
import * as webauthn from "./webauthnexperiment.js"
import * as password from "./passwordexperiment.js"
import * as metamask from "./metamaskexperiment.js"
import * as thingycrypto from "./thingycryptoexperiment.js"

############################################################
export initialize = ->
    log "initialize"
    await webauthn.initialize()
    await password.initialize()
    await metamask.initialize()
    await thingycrypto.initialize()


    webauthPubkey.addEventListener("click", webauthPubkeyClicked)
    passwordHash.addEventListener("click", passwordHashClicked)
    metamaskSig.addEventListener("click", metamaskSigClicked)
    thingyCryptoAuth.addEventListener("click", thingyCryptoAuthClicked)
    return

############################################################
#region
webauthPubkeyClicked = ->
    log "webauthPubkeyClicked"
    try await webauthn.run()
    catch err then console.error(err)
    return

############################################################
passwordHashClicked = ->
    log "passwordHashClicked"
    try await password.run()
    catch err then console.error(err)
    return

############################################################
metamaskSigClicked = ->
    log "metamaskSigClicked"
    try await metamask.run()
    catch err then console.error(err)
    return

############################################################
thingyCryptoAuthClicked = ->
    log "thingyCryptoAuthClicked"
    try await thingycrypto.run()
    catch err then console.error(err)
    return

#endregion
