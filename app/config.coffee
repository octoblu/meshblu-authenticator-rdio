passport = require 'passport'
GithubStrategy = require('passport-github').Strategy
{DeviceAuthenticator} = require 'meshblu-authenticator-core'
MeshbluDB = require 'meshblu-db'
debug = require('debug')('meshblu-github-authenticator:config')

githubOauthConfig =
  clientID: process.env.GITHUB_CLIENT_ID
  clientSecret: process.env.GITHUB_CLIENT_SECRET
  callbackURL: process.env.GITHUB_CALLBACK_URL
  passReqToCallback: true

class GithubConfig
  constructor: (@meshbluConn, @meshbluJSON) ->
    @meshbludb = new MeshbluDB @meshbluConn

  onAuthentication: (request, accessToken, refreshToken, profile, done) =>
    profileId = profile?.id
    fakeSecret = 'github-authenticator'
    authenticatorUuid = @meshbluJSON.uuid
    authenticatorName = @meshbluJSON.name
    deviceModel = new DeviceAuthenticator authenticatorUuid, authenticatorName, meshblu: @meshbluConn, meshbludb: @meshbludb
    query = {}
    query[authenticatorUuid + '.id'] = profileId
    device =
      name: profile.name
      type: 'octoblu:user'

    getDeviceToken = (uuid) =>
      @meshbluConn.generateAndStoreToken uuid: uuid, (device) =>
        device.id = profileId
        done null, device

    deviceCreateCallback = (error, createdDevice) =>
      getDeviceToken createdDevice?.uuid

    deviceFindCallback = (error, foundDevice) =>
      if foundDevice?
        return getDeviceToken foundDevice.uuid
      deviceModel.create query, device, profileId, fakeSecret, deviceCreateCallback

    deviceModel.findVerified query, fakeSecret, deviceFindCallback

  register: =>
    passport.use new GithubStrategy githubOauthConfig, @onAuthentication

module.exports = GithubConfig
