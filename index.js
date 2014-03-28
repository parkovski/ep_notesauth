var request = require('request');

var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

var authTokenHost = 'http://127.0.0.1:4000';
var tokenUrlPart = '/ajax/token/';

// Etherpad tries to provide a whitelist in node_modules/ep_etherpad-lite/node/hooks/express/webaccess.js.
// Unfortunately it is not all inclusive. Anything that should be available to
// logged out users should be listed here.
var whitelist = [
  '/locales.json'
];
function isWhitelisted(path) {
  return whitelist.some(function(resource) {
    return path === resource;
  });
}

function getUserForToken(token, callback) {
  if (!token) {
    return callback(null, null);
  }
  request(authTokenHost + tokenUrlPart + token, function(err, response, body) {
    if (err) {
      return callback(err);
    }
    if (response.statusCode !== 200) {
      return callback(null, null);
    }
    var user = null;
    try {
      user = JSON.parse(body);
    } catch (e) {
    }
    callback(null, user);
  });
}

module.exports = {
  authenticate: function(hook, context, callback) {
    getUserForToken(context.req.query.token, function(err, user) {
      if (err) {
        console.error(err);
        return callback([false]);
      }
      if (!user || !user.name || !user.displayname || !user.id) {
        return callback([false]);
      }
      
      context.req.session.user = {
        id: user.id,
        username: user.name,
        displayName: user.displayname,
        is_admin: false
      };
      // how do I set the author here?
      callback([true]);
    });
  },
  authorize: function(hook, context, callback) {
    if (isWhitelisted(context.resource)) {
      return callback([true]);
    }
    // Always authorize for readonly pads (for now).
    if (context.resource.match(/^\/p\/r\./)) {
      return callback([true]);
    }
    if (!context.req.session.user) {
      return callback([false]);
    }
    if (context.resource.match(/^\/admin/)) {
      return callback([context.req.session.user.is_admin]);
    }
    callback([true]);
  },
  authFailure: function(hook, context, callback) {
    console.log('Auth failure for ' + context.req.path);
    context.res.send(401, 'Not authorized. Please <a href="http://www.uanotes.com/login">log in at uanotes.com</a> to continue.');
    callback([true]);
  }
};