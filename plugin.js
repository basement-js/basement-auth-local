// require npm modules
var LocalStrategy   = require("passport-local").Strategy;
var bcrypt          = require("bcrypt");

function LocalAuth(vars) {
    this.info = {
        name: "local",
        prettyName: "Local transport"
    };
    
    // create default tables if they don't exist
    vars.knex.schema.hasTable("auth_local")
    .then(function (exists) {
        if (!exists) {
            return vars.knex.schema.createTable("auth_local", function (table) {
                table.increments();
                // uses a hacky way to collate until this gets merged:
                // https://github.com/tgriesser/knex/pull/1147
                table.string("email", 254).unique().notNullable().comment("' collate 'utf8_unicode_ci");
                table.string("username", 32).unique().notNullable().comment("' collate 'utf8_unicode_ci");
                table.specificType("password", "char(60)").notNullable().comment("' collate 'latin1_bin");
            });
        }
    });

    // get user model
    var User = vars.bookshelf.model("User");

    // get salt rounds
    // defaults to 12 if not specified in basement config
    var saltRounds = vars.config.get("plugins:auth:local:saltRounds") || 12;

    // register passport strategy
    vars.passport.use("local_username", new LocalStrategy({
            usernameField: 'username',
            passwordField: 'password'
        },
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