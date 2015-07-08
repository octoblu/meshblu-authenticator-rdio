express = require 'express'
morgan = require 'morgan'
bodyParser = require 'body-parser'
errorHandler = require 'errorhandler'
cookieParser = require 'cookie-parser'
session = require 'cookie-session'
passport = require 'passport'
Router = require './app/routes'
Config = require './app/config'
MeshbluDB = require 'meshblu-db'
airbrake = require('airbrake').createClient process.env.AIRBRAKE_API_KEY
debug = require('debug')('meshblu-rdio-authenticator:server')

meshbluJSON =
    uuid:   process.env.MESHBLU_RDIO_AUTHENTICATOR_UUID
    token:  process.env.MESHBLU_RDIO_AUTHENTICATOR_TOKEN
    server: process.env.MESHBLU_HOST
    port:   process.env.MESHBLU_PORT

if !meshbluJSON.uuid || !meshbluJSON.token
  try
    meshbluJSON  = require './meshblu.json'

  catch
    debug "I can't find my credentials!"
    process.exit -1

debug 'meshbluJSON', meshbluJSON

meshbluJSON.name = 'Rdio Authenticator'

port = process.env.MESHBLU_RDIO_AUTHENTICATOR_PORT ? 9009

app = express()
app.use morgan('dev')
app.use errorHandler()
app.use airbrake.expressHandler()
app.use bodyParser.json()
app.use bodyParser.urlencoded(extended: true)
app.use cookieParser()

app.use session
  secret: 'super awesome cool secret'
  resave: false
  saveUninitialized: true

app.use passport.initialize()
app.use passport.session()

passport.serializeUser (user, done) =>
  done null, user.id

passport.deserializeUser (user, done) =>
  done null, user

app.engine 'html', require('ejs').renderFile

app.set 'view engine', 'html'

app.set 'views', __dirname + '/app/views'

meshbluDB = new MeshbluDB meshbluJSON

meshbluDB.findOne uuid: meshbluJSON.uuid, (error, device) ->
  meshbluDB.setPrivateKey(device.privateKey) unless meshbluDB.privateKey

config = new Config meshbluDB, meshbluJSON
config.register()

router = new Router app
router.register()

app.listen port, =>
  debug "Meshblu Rdio Authenticator..."
  debug "Listening at localhost:#{port}"
