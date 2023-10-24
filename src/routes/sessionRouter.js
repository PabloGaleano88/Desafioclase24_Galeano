import { Router } from 'express'
import passport from 'passport'
import { userModel } from '../dao/models/userModel.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import loadUser from '../middlewares/loadUser.js'

const sessionRouter = Router()

sessionRouter.post('/login', async (req, res) => {
    const { email, password } = req.body
    const email_to_lowercase = email.toLowerCase()
    const user = await userModel.findOne({ email:email_to_lowercase}).lean()

    if (!user) {
        return res.redirect('/login?login_fail=true')
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send("password incorrecto")
    }

    const userId = user._id
    const token = jwt.sign({ userId }, 'tokensecreto', { expiresIn: '24h' })

    res.cookie('token', token, {
        maxAge : 1000000,
        httpOnly: true,
    }).send(`estas logeado, prueba ingresando a http://localhost:8080/api/session/current para ver la información de tu token en las cookies`)

})

sessionRouter.get('/current', passport.authenticate('jwt',{session:false}),loadUser, async(req,res)=>{
    res.send(req.user)
})

export default sessionRouter