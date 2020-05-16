(function() {
  'use strict';
  module.exports = function(ndx) {
    if (ndx.settings.HAS_FORGOT || process.env.HAS_FORGOT) {
      ndx.forgot = {
        fetchTemplate: function(data, cb) {
          return cb({
            subject: "forgot password",
            body: 'h1 forgot password\np\n  a(href="#{code}")= code',
            from: "System"
          });
        }
      };
      ndx.setForgotTemplate = function(template) {
        var forgotTemplate;
        return forgotTemplate = template;
      };
      ndx.app.post('/get-forgot-code', function(req, res, next) {
        return ndx.database.select(ndx.settings.USER_TABLE, {
          where: {
            local: {
              email: req.body.email
            }
          }
        }, function(users) {
          var token;
          if (users && users.length) {
            token = encodeURIComponent(ndx.generateToken(JSON.stringify(req.body), req.ip, 4 * 24, true));
            token = req.protocol + "://" + req.hostname + "/forgot?" + token;
            return ndx.forgot.fetchTemplate(req.body, function(forgotTemplate) {
              if (ndx.email) {
                ndx.email.send({
                  to: req.body.email,
                  from: forgotTemplate.from,
                  subject: forgotTemplate.subject,
                  body: forgotTemplate.body,
                  code: token,
                  user: users[0]
                });
              }
              return res.end(token);
            });
          } else {
            return next('No user found');
          }
        });
      });
      return ndx.app.post('/forgot-update/:code', function(req, res, next) {
        var user, where;
        user = JSON.parse(ndx.parseToken(req.params.code, true));
        if (req.body.password) {
          where = {
            local: {
              email: user.email
            }
          };
          ndx.database.update(ndx.settings.USER_TABLE, {
            local: {
              email: user.email,
              password: ndx.generateHash(req.body.password)
            }
          }, where);
          return res.end('OK');
        } else {
          return next('No password');
        }
      });
    }
  };

}).call(this);

//# sourceMappingURL=forgot.js.map
