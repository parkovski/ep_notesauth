var request = require('request');

var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

var authTokenHost = 'http://127.0.0.1:4000';
var tokenUrlPart = '/ajax/token/';

function getUserForToken(token, callback) {
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
      console.log('getUserForToken');
      console.log(user && user.displayname);
      if (err) {
        console.error(err);
        return callback([false]);
      }
      if (!user || !user.name || !user.displayname || !user.id) {
        return callback([false]);
      }
      
      context.req.session.user = {
        username: user.name,
        displayName: user.displayname,
        is_admin: false
      };
      console.log('#*($&#(*$&#(*$&(*#&$(*#$#($&#*($&#($');
      console.dir(context.req.session);
      // how do I get the author here?
      callback([true]);
    });
  },
  authorize: function(hook, context, callback) {
    if (!context.req.session.user) {
      return callback([false]);
    }
    if (context.resource.match(/^\/admin/)) {
      return callback([context.req.session.user.is_admin]);
    }
    callback([true]);
  }
};