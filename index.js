var settings = require('ep_etherpad-lite/node/utils/Settings');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');

var authTokenHost = '127.0.0.1:4000';

module.exports = {
  authenticate: function(hook, context, callback) {
    context.req.session.user = 'A G as shit gangster';
    callback([true]);
  },
  authorize: function(hook, context, callback) {
    callback([!!context.req.session.user]);
  }
};