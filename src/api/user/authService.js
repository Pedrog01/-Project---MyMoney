const _ = require('loadash')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const User = require('./user')
const env = require('../../.env')
const user = require('./user')

const emailRegex = /\S+@\S+\.\S+/
const passwordRegex = /((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})/

const sendErrorsFromDB = (res, dbErrors) => {
    const errors = []
    _.forIn(dbErrors.errors, error => errors.push(error.message))
    return res.status(400).json({errors})
}

const login =(req,res,next) => {
    const email = req.body.email || ''
    const password = req.body.password || ''
    
    User.findOne({email}, (res,err) =>{
        if(err){
            return sendErrorsFromDB(res,err)
        }else if(user && bcrypt.compareSync(password.user.password)){
            const token = jwt.sign(user, env.authSecret,{
                expiresIn: '1 Day'
            })
            const {name, email} = user
            res.json({name, email, token})
        }else{
            res.status(400).send({errors: ['Usuário/Senha Invalidos']})
        }
    })
}

const validateToken = (req, res, next) => {
    const token = req.body.token
        
    jwt.verify(token, env.authSecret, function(err, decoded) {
        return res.status(200).send({valid: !err})
    })
}

