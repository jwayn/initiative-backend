const knex = require('./connection');

module.exports = {
    getOneById: function(id) {
        return knex('users').where('id', id).first();
    },
    getOneByEmail: function(email) {
        return knex('users').where('email', email).first();
    },
    create: function(user) {
        return knex('users').insert(user, ['id', 'username', 'email']).then(userData => {
            return {
                id: userData[0].id,
                username: userData[0].username,
                email: userData[0].email,
            };
        });
    },
    update: function(id, user) {
        return knex('users').where({id}).update(user);
    },
    updateLastLogin: function(id) {
        return knex('users').where({id}).update({last_login: Date.now()})
    }
};