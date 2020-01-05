const knex = require('./connection');
const uuidv4 = require('uuid/v4');

module.exports = {
    getOneById: function(id) {
        return knex('users').where('id', id).first();
    },
    getAllByUser: function(id) {
        return knex('encounters').where('owner_id', id);
    },
    create: function() {
        const id = uuidv4();
        return knex('encounters').insert()
    },
    delete: function(id) {
        
    },
    addEncounterActor: function(actor_id) {

    },
    removeEncounterActors: function(actor_id) {

    },
};