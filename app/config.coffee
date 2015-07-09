passport = require 'passport'
RdioStrategy = require('passport-rdio-oauth2').Strategy
{DeviceAuthenticator} = require 'meshblu-authenticator-core'
debug = require('debug')('meshblu-rdio-authenticator:config')

rdioOauthConfig =
  # clientID: process.env.RDIO_CLIENT_ID
  # clientSecret: process.env.RDIO_CLIENT_SECRET
  # callbackURL: process.env.RDIO_CALLBACK_URL
  clientID: 'eeuvwjobdjeavcv3ed7ptq4iri'
  clientSecret: 'pQq5n_LQ1eEUSyjC8dZvmg'
  callbackURL: 'http://localhost:8008/oauthcallback'

  passReqToCallback: true


class RdioConfig
  constructor: (@meshbludb, @meshbluJSON) ->

  onAuthentication: (request, accessToken, refreshToken, profile, done) =>
    debug 'PROFILE', profile
    profileId = profile?.id
    fakeSecret = 'rdio-authenticator'
    authenticatorUuid = @meshbluJSON.uuid
    authenticatorName = @meshbluJSON.name
    deviceModel = new DeviceAuthenticator authenticatorUuid, authenticatorName, meshbludb: @meshbludb
    query = {}
    query[authenticatorUuid + '.id'] = profileId
    device =
      name: profile.name
      type: 'octoblu:user'

    getDeviceToken = (uuid) =>
      @meshbludb.generateAndStoreToken uuid, (error, device) =>
        device.id = profileId
        done null, device

    deviceCreateCallback = (error, createdDevice) =>
      return done error if error?
      getDeviceToken createdDevice?.uuid

    deviceFindCallback = (error, foundDevice) =>
      # return done error if error?
      return getDeviceToken foundDevice.uuid if foundDevice?
      deviceModel.create query, device, profileId, fakeSecret, deviceCreateCallback

    deviceModel.findVerified query, fakeSecret, deviceFindCallback

  register: =>
    passport.use new RdioStrategy rdioOauthConfig, @onAuthentication

module.exports = RdioConfig
