const express = require('express')
const auth = require('./auth')

module.exports = function(server) {

    /*
        ROTAS PROTEGIDAS POT TOKEN JWT
    */

    const protectedApi = express.Router()
    server.use('/api', protectedApi)

    protectedApi.use(auth)

    const BillingCycle = require('../api/billingCycle/billingCycleService')
    BillingCycle.register(protectedApi,'/billingCycle')


    /*
        ROTAS ABERTAS
    */

    const openApi = express.Router()
    server.use('/oapi', openApi)

    const AuthService = require('../api/user/authService')
    openApi.post('/login', AuthService.login)
    openApi.post('/signup', AuthService.signUp)
    openApi.post('/validateToken', AuthService.validateToken)
}