import { Router } from "express";
import { userModel } from "../dao/models/userModel.js";
import passport from 'passport'

const uRouter = Router()

uRouter.post('/signup', passport.authenticate('register', { failureRedirect: '/failregister' }), async (req, res) => {
    res.redirect('/login')
})

uRouter.post('/login', passport.authenticate('login', { failureRedirect: '/login?login_fail=true' }), async (req, res) => {

    req.user.email === "admincoder@coder.com" ? req.session.admin = true : req.session.admin = false
    req.session.first_name = req.user.first_name
    req.session.last_name = req.user.last_name
    req.session.email = req.user.email
    req.session.age = req.user.age
    req.session.isLogged = true

    res.redirect('/products')
})

uRouter.get('/logout', async (req, res) => {
    req.session.destroy()
    res.redirect('/login')
})

uRouter.get('/github', passport.authenticate('github', { scope: ['user:email'] }))

uRouter.get('/githubcallback', passport.authenticate('github', { failureRedirect: '/login' }), async (req, res) =>  {
    req.user.email === "admincoder@coder.com" ? req.session.admin = true : req.session.admin = false
    req.session.first_name = req.user.first_name
    req.session.last_name = req.user.last_name
    req.session.email = req.user.email
    req.session.age = req.user.age
    req.session.isLogged = true
    
    res.redirect('/products')
}) 

export default uRouter