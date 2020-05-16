'use strict'

module.exports = (ndx) ->
  if ndx.settings.HAS_FORGOT or process.env.HAS_FORGOT
    ndx.forgot =
      fetchTemplate: (data, cb) ->
        cb
          subject: "forgot password"
          body: 'h1 forgot password\np\n  a(href="#{code}")= code'
          from: "System"
    ndx.setForgotTemplate = (template) ->
      forgotTemplate = template
    ndx.app.post '/get-forgot-code', (req, res, next) ->
      ndx.database.select ndx.settings.USER_TABLE,
        where:
          local:
            email: req.body.email
      , (users) ->
        if users and users.length
          token = encodeURIComponent(ndx.generateToken(JSON.stringify(req.body), req.ip, 4 * 24, true))
          token = "#{req.protocol}://#{req.hostname}/forgot?#{token}"
          ndx.forgot.fetchTemplate req.body, (forgotTemplate) ->
            if ndx.email
              ndx.email.send
                to: req.body.email
                from: forgotTemplate.from
                subject: forgotTemplate.subject
                body: forgotTemplate.body
                code: token
                user: users[0]
            res.end token
        else
          return next 'No user found'
    ndx.app.post '/forgot-update/:code', (req, res, next) ->
      user = JSON.parse ndx.parseToken(req.params.code, true)
      if req.body.password
        where = 
          local:
            email: user.email
        ndx.database.update ndx.settings.USER_TABLE,
          local:
            email: user.email
            password: ndx.generateHash req.body.password
        , where
        res.end 'OK'
      else
        next 'No password'