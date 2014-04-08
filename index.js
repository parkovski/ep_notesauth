var request = require('request');

var ERR = require('async-stacktrace');
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

// setUsername and handleMessage from ep_sotauth/ep_ldapauth.
function setUsername(token, username) {
  console.debug('ep_notesauth.setUsername: getting authorid for token %s', token);
  authorManager.getAuthor4Token(token, function(err, author) {
    if(ERR(err)) {
      console.debug('ep_notesauth.setUsername: error getting author for token %s', token);
      return;
    } else {
      if(author) {
        console.debug('ep_notesauth.setUsername: have authorid %s, setting username to %s', author, username);
        authorManager.setAuthorName(author, username);
      } else {
        console.debug('ep_notesauth.setUsername: could not get authorid for token %s', token);
      }
    }
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
    console.warn('Auth failure for ' + context.req.path);
    context.res.send(401, 'Not authorized. Please <a href="http://www.uanotes.com/login">log in at uanotes.com</a> to continue.');
    callback([true]);
  },
  handleMessage: function(hook_name, context, cb) {
    if(context.message.type == "CLIENT_READY") {
      if(!context.message.token) {
        console.debug('ep_notesauth.handleMessage: intercepted CLIENT_READY message has no token!');
      } else {
        var client = context.client;
        var client_id = client.id;
        var client_handshaken = client.manager.handshaken[client_id];
        var express_sid = client_handshaken.sessionID;
        var username;
        if (client_handshaken.session.user) {
          var username = client_handshaken.session.user.displayName;
          console.debug('ep_notesauth.handleMessage: intercepted CLIENT_READY message for client_id = %s express_sid = %s, setting username for token %s to %s', client_id, express_sid, context.message.token, username);
          setUsername(context.message.token, username);
        }
      }
    } else if(context.message.type == "COLLABROOM" && context.message.data.type == "USERINFO_UPDATE") {
      console.debug('ep_notesauth.handleMessage: intercepted USERINFO_UPDATE and dropping it!');
      return cb([null]);
    }
    return cb([context.message]);
  }
};