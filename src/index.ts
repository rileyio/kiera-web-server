require('dotenv').config()

import Axios from 'axios'

import * as fs from 'fs'
import * as path from 'path'
import * as redis from 'redis'
import * as https from 'https'
import * as helmet from 'helmet'
import * as express from 'express'
import * as passport from 'passport'
import * as bodyParser from 'body-parser'
import * as connectRedis from 'connect-redis'
import * as cookieParser from 'cookie-parser'
import * as expressSession from 'express-session'
import * as DiscordStrategy from 'passport-discord'
import { RequestExtended } from './objects/server'

export class Server {
  public app = express()
  public appPath: string
  public https: { ca?: Buffer; key: Buffer; cert: Buffer }
  public discordScopes: Array<string> = []
  public redisClient: redis.RedisClient
  public redisStore: connectRedis.RedisStore
  public httpsServer: https.Server

  constructor() {
    this.app = express()
    this.appPath = path.join(__dirname, '../production-app/')
    this.https = {
      ca: process.env.APP_HTTPS_CA ? fs.readFileSync(path.join(process.env.APP_HTTPS_CA as string)) : undefined,
      key: fs.readFileSync(path.join(process.env.APP_HTTPS_KEY as string)),
      cert: fs.readFileSync(path.join(process.env.APP_HTTPS_CRT as string))
    }
    this.discordScopes = ['identify', 'guilds']

    // Sessions
    this.redisStore = connectRedis(expressSession)
    this.redisClient = redis.createClient({
      host: 'localhost',
      port: 6379,
      db: 1
    })
    this.redisClient.unref()
    this.redisClient.on('error', console.log)

    this.app.use(
      expressSession({
        secret: 'mySecretKey',
        store: new this.redisStore({
          client: this.redisClient
        }),
        resave: true,
        saveUninitialized: true
      })
    )

    // Passport
    this.passportConfig()
    this.app.use(passport.initialize())
    this.app.use(passport.session())

    // Middleware
    this.app.use(helmet())
    this.app.use(bodyParser.json())
    this.app.use(
      bodyParser.urlencoded({
        extended: true
      })
    )
    this.app.use(cookieParser())

    // CORS
    this.app.use(function (req, res, next) {
      res.header('Access-Control-Allow-Origin', '*')
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
      next()
    })

    // Static Assets
    this.app.use('/assets', express.static(path.join(__dirname, '../production-app')))

    ////////////////////////////////////////
    // Web Server Routed ///////////////////
    ////////////////////////////////////////

    /**
     * [GET] Login Callback - Redirected from Discord OAuth
     * Route: /callback
     */
    this.app.get(
      '/callback',
      passport.authenticate('discord', {
        successRedirect: '/',
        failureRedirect: '/'
      }),
      (req, res) => {
        console.log('/callback called')
        res.redirect('/info')
      }
    )

    /**
     * [GET] Manual Logout - Logout redirected to or requested by user
     * Route: /logout
     */
    this.app.get('/logout', this.forceLogout, (req, res, next) => {
      ;(req as any).logout()
      res.redirect('/')
    })

    /**
     * [GET] Manual Login - Login redirected to or requested by user
     * Route: /login
     */
    this.app.get(
      '/login',
      passport.authenticate('discord', {
        scope: this.discordScopes
      }),
      (req, res) => {}
    )

    /**
     * [GET] Session Info - Testing
     * Route: /info
     */
    this.app.get('/info', this.checkAuth, (req: express.Request, res: express.Response) => {
      res.json((req as any).user)
    })

    /**
     * [GET] Index
     * Route: /info
     */
    this.app.get('/', this.checkAuth, (req, res) => {
      if (process.env.APP_REDIRECT) res.redirect(process.env.APP_REDIRECT)
      else res.status(200).sendFile(path.join(this.appPath, 'index.html'))
    })

    this.httpsServer = https.createServer(this.https, this.app)
  }

  start() {
    this.listen()
  }

  listen() {
    this.httpsServer.listen(8235, () => {
      console.log(`kiera-web listening`)
    })
  }

  passportConfig() {
    passport.serializeUser(function (user, done) {
      // console.log('SERIALIZE', user)
      done(null, user)
    })
    passport.deserializeUser(function (obj, done) {
      // console.log('DESERIALIZE-USER', obj)
      done(null, obj)
    })

    passport.use(
      new DiscordStrategy.Strategy(
        {
          clientID: process.env.DISCORD_APP_ID as string,
          clientSecret: process.env.DISCORD_APP_SECRET as string,
          callbackURL: process.env.DISCORD_APP_CALLBACK as string,
          scope: this.discordScopes
        },
        async (accessToken, refreshToken, profile, done) => {
          // Talk to Bot for auth
          const resp = await this.loginWithBot(profile)
          if (resp.success) {
            return done(null, resp)
          } else {
            return done(null)
          }
        }
      )
    )
  }

  private checkAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const request = req as RequestExtended
    console.log('checkAuth', request.isAuthenticated())
    if (request.isAuthenticated()) {
      res.cookie('kiera-discord-id', request.user.userID)
      res.cookie('kiera-webToken', encodeURIComponent(request.user.session))
    }
    // res.send('not logged in :(')
    return next()
  }

  private forceLogout(req: express.Request, res: express.Response, next: express.NextFunction) {
    res.cookie('kiera-discord-id', null)
    res.cookie('kiera-webToken', null)
    return next()
  }

  private async loginWithBot(profile: DiscordStrategy.Profile) {
    console.log('Sending login to Kiera-Bot API...')
    const resp = await Axios(`${process.env.BOT_HOST}/web/oauth`, {
      method: 'POST',
      data: {
        id: profile.id,
        username: profile.username,
        discriminator: profile.discriminator,
        avatar: profile.avatar,
        fetchedAt: profile.fetchedAt,
        locale: profile.locale
      },
      headers: {
        secret: process.env.BOT_WEB_APP_SERVER_SECRET
      },
      httpsAgent: process.env.APP_DEV_MODE
        ? new https.Agent({
            rejectUnauthorized: false
          })
        : undefined
    })

    if (resp.status === 200) return resp.data
  }
}
