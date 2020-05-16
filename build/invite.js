(function() {
  'use strict';
  module.exports = function(ndx) {
    if (ndx.settings.HAS_INVITE || process.env.HAS_INVITE) {
      if (typeof btoa === 'undefined') {
        global.btoa = function(str) {
          return new Buffer(str).toString('base64');
        };
      }
      if (typeof atob === 'undefined') {
        global.atob = function(b64Encoded) {
          return new Buffer(b64Encoded, 'base64').toString();
        };
      }
      ndx.invite = {
        fetchTemplate: function(data, cb) {
          return cb({
            subject: "You have been invited",
            body: 'h1 invite\np\n  a(href="#{code}")= code',
            from: "System"
          });
        },
        users: ['admin', 'superadmin']
      };
      ndx.app.post('/invite/accept', function(req, res, next) {
        var e, error, user;
        try {
          user = JSON.parse(ndx.parseToken(atob(req.body.code), true));
        } catch (error) {
          e = error;
          return next(e);
        }
        return ndx.database.select(ndx.settings.USER_TABLE, {
          where: {
            local: {
              email: user.local.email
            }
          }
        }, function(users) {
          if (users && users.length) {
            return next('User already exists');
          }
          ndx.extend(user, req.body.user);
          user.local.password = ndx.generateHash(user.local.password);
          ndx.database.insert(ndx.settings.USER_TABLE, user);
          return res.end('OK');
        });
      });
      ndx.app.get('/invite/:code', function(req, res, next) {
        var e, error, user;
        try {
          user = JSON.parse(ndx.parseToken(atob(req.params.code), true));
        } catch (error) {
          e = error;
          return next(e);
        }
        return res.redirect("/invited?" + (encodeURIComponent(req.params.code)));
      });
      return ndx.app.post('/api/get-invite-code', ndx.authenticate(ndx.invite.users), function(req, res, next) {
        return ndx.database.select(ndx.settings.USER_TABLE, {
          where: {
            local: {
              email: req.body.local.email
            }
          }
        }, function(users) {
          var host, token;
          if (users && users.length) {
            return next('User already exists');
          }
          token = encodeURIComponent(btoa(ndx.generateToken(JSON.stringify(req.body), req.ip, 4 * 24, true)));
          host = process.env.HOST || ndx.settings.HOST || (req.protocol + "://" + req.hostname);
          token = host + "/invite/" + token;
          return ndx.invite.fetchTemplate(req.body, function(inviteTemplate) {
            if (ndx.email) {
              ndx.email.send({
                to: req.body.local.email,
                from: inviteTemplate.from,
                subject: inviteTemplate.subject,
                body: inviteTemplate.body,
                code: token
              });
            }
            return res.end(token);
          });
        });
      });
    }
  };

}).call(this);

//# sourceMappingURL=invite.js.map
