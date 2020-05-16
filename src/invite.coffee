'use strict'

module.exports = (ndx) ->
  if ndx.settings.HAS_INVITE or process.env.HAS_INVITE
    if typeof btoa is 'undefined'
      global.btoa = (str) ->
        new Buffer(str).toString 'base64'
    if typeof atob is 'undefined'
      global.atob = (b64Encoded) ->
        new Buffer(b64Encoded, 'base64').toString()
    ndx.invite = 
      fetchTemplate: (data, cb) ->
        cb
          subject: "You have been invited"
          body: 'h1 invite\np\n  a(href="#{code}")= code'
          from: "System"
      users: ['admin', 'superadmin']
    ndx.app.post '/invite/accept', (req, res, next) ->
      try
        user = JSON.parse ndx.parseToken(atob(req.body.code), true)
      catch e
        return next e
      ndx.database.select ndx.settings.USER_TABLE,
        where:
          local:
            email: user.local.email
      , (users) ->
        if users and users.length
          return next 'User already exists'
        ndx.extend user, req.body.user
        user.local.password = ndx.generateHash user.local.password
        ndx.database.insert ndx.settings.USER_TABLE, user
        res.end 'OK'
    ndx.app.get '/invite/:code', (req, res, next) ->
      try
        user = JSON.parse ndx.parseToken(atob(req.params.code), true)
      catch e
        return next e
      res.redirect "/invited?#{encodeURIComponent(req.params.code)}"
    ndx.app.post '/api/get-invite-code', ndx.authenticate(ndx.invite.users), (req, res, next) ->
      ndx.database.select ndx.settings.USER_TABLE,
        where:
          local:
            email: req.body.local.email
      , (users) ->
        if users and users.length
          return next 'User already exists'
        token = encodeURIComponent(btoa(ndx.generateToken(JSON.stringify(req.body), req.ip, 4 * 24, true)))
        host = process.env.HOST or ndx.settings.HOST or "#{req.protocol}://#{req.hostname}"
        token = "#{host}/invite/#{token}"
        ndx.invite.fetchTemplate req.body, (inviteTemplate) ->
          if ndx.email
            ndx.email.send
              to: req.body.local.email
              from: inviteTemplate.from
              subject: inviteTemplate.subject
              body: inviteTemplate.body
              code: token
          res.end token
