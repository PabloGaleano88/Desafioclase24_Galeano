import passport from 'passport'
import LocalStrategy from 'passport-local'
import bcrypt from 'bcrypt'
import { userModel } from '../dao/models/userModel.js'
import CartManager from '../dao/MongoDB/CartManager.js'
import GitHubStrategy from 'passport-github2'
import jwt from 'passport-jwt'

const JWTStrategy = jwt.Strategy
const ExtractJWT = jwt.ExtractJwt

const cartManager = new CartManager()

const initializePassport = () => {
    
    passport.use('register', new LocalStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
        const { first_name, last_name, age } = req.body
        try {
            const usernameLowerCase = username.toLowerCase()
            const exists = await userModel.findOne({ email: usernameLowerCase })
            if (exists) {
                return done(null, false)
            }
            const cartId = await cartManager.addCart()
            const user = await userModel.create({
                first_name,
                last_name,
                email: usernameLowerCase,
                age,
                cartId,
                password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
            })

            return done(null, user)
        }
        catch (error) {
            return done(error)
        }
    }))

    passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
        try {
            const usernameLowerCase = username.toLowerCase()
            const user = await userModel.findOne({ email: usernameLowerCase })
            if (!user) {
                return done(null, false)
            }
            if (!bcrypt.compareSync(password, user.password)) {
                return done(null, false)
            }
            return done(null, user)
        }
        catch (error) {
            return done(error)
        }
    }))

    passport.use('github', new GitHubStrategy({
        clientID: 'Iv1.38d55d5765288228',
        clientSecret: '45ebb4e12ac017a896062fde9fa27776743000a3',
        callbackURL: 'http://localhost:8080/api/githubcallback',
        scope: ['user:email']
    }, async (acccesToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails[0].value
            const user = await userModel.findOne({ email })

            if (!user) {
                const newUser = userModel.create({
                    first_name: profile._json.name,
                    last_name: '',
                    age: 18,
                    password: '',
                    email,
                })
            }
            return done(null, user)
        }
        catch (error) {
            return done(error)
        }
    }))

    const cookieExtractor = (req) => {
        let token = null
        
        if(req && req.cookies){
            token = req.cookies['token']
        }
        
        return token
    }


    passport.use('jwt',new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: 'tokensecreto',
    }, async (jwt_payload, done)=>{
        try{
            return done(null,jwt_payload)
        }
        catch(error){
            return done (error)
        }
    })
    )



    passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    passport.deserializeUser(async (id, done) => {
        const user = await userModel.findById(id)
        done(null, user)
    })
}

export default initializePassport