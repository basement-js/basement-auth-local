// require npm modules
var LocalStrategy   = require("passport-local").Strategy;
var bcrypt          = require("bcrypt");

function LocalAuth(vars) {
    // create default tables if they don't exist
    vars.knex.createTableIfNotExists("auth_local", function (table) {
        table.increments();
        table.string("email", 254).collate("utf8_unicode_ci");
        table.string("username", 32).collate("utf8_unicode_ci");
        table.string("password").specificType("CHAR", 60).collate("latin1_bin");
    });

    // get user model
    var User = vars.bookshelf.model("User");

    // get salt rounds
    // defaults to 12 if not specified in basement config
    var saltRounds = vars.config.get("plugins:auth:local:saltRounds") || 12;

    // register passport strategy
    vars.passport.use("local_username", new LocalStrategy(
        function (username, password, done) {
            new User({username: username})
            .fetch({require: true})
            .tap(function (user) {
                bcrypt.genSalt(saltRounds, function (err, salt) {
                    if (err) {
                        throw err;
                    }

                    bcrypt.hash(password, salt, function (err, hash) {
                        if (err) {
                            throw err;
                        }

                        if (hash === user.get("password")) {
                            done(null, user);
                        } else {
                            // TODO: language
                            done(null, false, {
                                message: "Invalid password."
                            });
                        }
                    });
                });
            })
            .catch(User.NotFoundError, function (e) {
                // TODO: language
                done(null, false, {
                    message: "User not found."
                });
            });

            // this should never be called
            // it is a fallback
            done(null, false);
        }
    ));
}

module.exports = LocalAuth;