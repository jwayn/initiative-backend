const knex = require('./connection');
const moment = require('moment');

module.exports = {
    getOneById: function(id) {
        return knex('users').select('id', 'username', 'email', 'created', 'last_login').where({id}).first();
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
        console.log('Updating last login');
        console.log(moment.utc(Date.now()).format());
        return knex('users').where({id}).update({last_login: moment.utc(Date.now()).format()})
    },
    createVerification: function(user_id, token) {
        console.log('Creating verification');
        return knex('users_verification').insert({user_id, token}).returning('token');
    },
    getVerificationByToken(token) {
        console.log('Grabbing verification record for "' + token + '" .');
        return knex('users_verification').where({token}).first();
    },
    getVerificationByUserId(user_id) {
        return knex('users_verification').where({user_id}).first();
    },
    deleteVerificationRecord(user_id) {
        console.log('Deleting verification record for user_id "' + user_id + '".');
        return knex('users_verification').where({user_id}).delete();
    },
    createResetPassToken: function(user_id, token) {
        console.log('Creating reset pass token');
        return knex('users_reset_pass').insert({user_id, token});
    },
    getResetPassToken: function(token) {
        return knex('users_reset_pass').where({token}).first();
    },
    getResetPassTokenByUser: function(user_id) {
        return knex('users_reset_pass').where({user_id}).first();
    },
    deleteResetPassToken: function(token) {
        console.log('Deleting reset pass record with token ' + token);
        return knex('users_reset_pass').where({token}).delete();
    },
    delete: function(id) {
        return knex('users').where({id}).delete();
    },
};