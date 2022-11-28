const _ = require('lodash')
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

const signUp = (res,req, next) => {
    const name = res.body.name || ''
    const email = res.body.email || ''
    const password = res.body.password || ''
    const confirmPassword = res.body.confirm_password || ''

    if(!email.match(emailRegex)) {
        return res.status(400).send({errors: ['O Email informado está inválido']})
    }


    if(!password.match(passwordRegex)) {
        return res.status(400).send({
            errors: [
                'a Senha precisa ter: uma letra maiúscula, uma letra minúscula,um numero, uma caractere especial '
            ]
        })
    }

    const salt = bcrypt.genSaltSync()
    const passwordHash = bcrypt.hashSync(password,salt)
        if(!bcrypt.compareSync(confirmPassword, passwordHash)) {
            return res.status(400).send({error:['Senhas não confere']})
        }

        user.findOne({email}, (err,user) =>{
            if(err) {
                return sendErrorsFromDB(res,err)
            }else if(user){
                return res.status(400).send({error:['Usuário já Cadastrado']})
            }else{
                const newUser = new User({name,email,password: passwordHash})
                newUser.save(err =>{
                    if(err){
                        return sendErrorsFromDB(res,err)
                    }else {
                        login(res,req,next)
                    }
                })
            }
        })
}

module.exports = {login,signUp,validateToken}

