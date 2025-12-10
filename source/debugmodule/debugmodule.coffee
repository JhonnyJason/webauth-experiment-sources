import { addModulesToDebug } from "thingy-debug"

############################################################
export modulesToDebug = {

    # appcoremodule: true
    # authmodule: true
    # datamodule: true
    experimentmodule: true
    webauthnexperiment: true
    webauthnutils: true

}

addModulesToDebug(modulesToDebug)
