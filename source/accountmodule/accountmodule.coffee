############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("accountmodule")
#endregion

############################################################
import * as tbut from "thingy-byte-utils"
import * as S from "./statemodule.js"

############################################################
defaultUserId = "ffffffffff2345678904567894567890"
defaultUserName = "Master Chief"
defaultUserDisplayName = "MasterChief :-)"

############################################################
export initialize = ->
    log "initialize"
    # idBuf = new Uint8Array(16)
    # crypto.getRandomValues(idBuf)
    return

############################################################
export getCurrentUser = ->
    log "getCurrentUser"
    return {
        userIdHex: defaultUserId
        userName: defaultUserName
        displayName: defaultUserDisplayName
    }