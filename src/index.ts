require('dotenv').config()

import Axios from 'axios'

import * as fs from 'fs'
import * as redis from 'redis'
import * as http from 'http'
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
  public readonly isHTTPSSet =
    process.env.API_HTTPS_KEY && process.env.API_HTTPS_CRT ? fs.existsSync(process.env.API_HTTPS_KEY as string) && fs.readFileSync(process.env.API_HTTPS_CRT as string) : false
  public server: https.Server | http.Server

  protected readonly https = this.isHTTPSSet
    ? {
        key: fs.readFileSync(process.env.API_HTTPS_KEY as string),
        certificate: fs.readFileSync(process.env.API_HTTPS_CRT as string)
      }
    : {}

  app = express()

  private basePath: string = process.env.API_SERVER_BASE
  private discordScopes: Array<string> = []
  private redisClient: redis.RedisClient
  private redisStore: connectRedis.RedisStore

  constructor() {
    this.app = express()
    this.discordScopes = ['identify', 'guilds']

    if (process.env.API_DEV_MODE) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

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
        store: new this.redisStore({
          client: this.redisClient
        }),
        secret: process.env.API_SERVER_SECRET,
        resave: false,
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

    ////////////////////////////////////////
    // Web Server Routed ///////////////////
    ////////////////////////////////////////

    /**
     * [GET] Login Callback - Redirected from Discord OAuth
     * Route: /callback
     */
    this.app.get(
      `${this.basePath}/callback`,
      passport.authenticate('discord', {
        successRedirect: '/app',
        failureRedirect: '/'
      }),
      (req, res) => {
        console.log('/callback called')
        res.redirect(`${this.basePath}/info`)
      }
    )

    /**
     * [GET] Manual Logout - Logout redirected to or requested by user
     * Route: /logout
     */
    this.app.get(`${this.basePath}/logout`, this.forceLogout, (req, res, next) => {
      ;(req as any).logout()
      res.redirect('/')
    })

    /**
     * [GET] Manual Login - Login redirected to or requested by user
     * Route: /login
     */
    this.app.get(
      `${this.basePath}/login`,
      passport.authenticate('discord', {
        scope: this.discordScopes
      }),
      (req, res) => {}
    )

    /**
     * [GET] Session Info - Testing
     * Route: /info
     */
    this.app.get(`${this.basePath}/info`, this.checkAuth, (req: express.Request, res: express.Response) => {
      res.json((req as any).user)
    })

    /**
     * [GET] Index
     * Route: /info
     */
    this.app.get(`${this.basePath}/`, this.checkAuth, (req, res) => {
      res.redirect(process.env.API_REDIRECT)
    })

    this.server = this.isHTTPSSet ? https.createServer(this.https, this.app) : http.createServer(this.app)
  }

  start() {
    this.listen()
  }

  listen() {
    this.server.listen(8235, () => {
      console.log(`kiera-web listening`, this.isHTTPSSet ? 'https' : 'http')
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
      res.cookie('kiera-sessionToken', encodeURIComponent(request.user.session))
    }
    // res.send('not logged in :(')
    return next()
  }

  private forceLogout(req: express.Request, res: express.Response, next: express.NextFunction) {
    res.cookie('kiera-discord-id', null)
    res.cookie('kiera-sessionToken', null)
    return next()
  }

  private async loginWithBot(profile: DiscordStrategy.Profile) {
    console.log('Sending login to Kiera-Bot API...')
    const resp = await Axios(`${process.env.BOT_HOST}/web/oauth`, {
      method: 'POST',
      data: { id: profile.id },
      headers: {
        secret: process.env.BOT_WEB_APP_SERVER_SECRET
      },
      httpsAgent:
        process.env.API_DEV_MODE && this.isHTTPSSet
          ? new https.Agent({
              rejectUnauthorized: false
            })
          : undefined
    })

    if (resp.status === 200) return resp.data
  }
}
