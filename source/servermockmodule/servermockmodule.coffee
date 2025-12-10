############################################################
#region debug
import { createLogFunctions } from "thingy-debug"
{log, olog} = createLogFunctions("servermockmodule")
#endregion

############################################################
export initialize = ->
    log "initialize"
    #Implement or Remove :-)
    return


############################################################
export login = (credInfo) ->
    log "login"

    ## TODO implement serverlogic to verify and login

    result = {ok:true}
    return result


export register = (credInfo) ->
    log "register"
    ## TODO implement serverlogic to verify and registr
    return