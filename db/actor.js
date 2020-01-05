const knex = require('./connection');
const uuidv4 = require('uuid/v4');

module.exports = {
    getOneById: function(id) {
        return knex('actors').where('id', id).first();
    },
    getAllByUser: function(owner) {
        return knex('actors').select().where({owner});
    },
    create: function(user_id, actor) {
        actor.owner = user_id;
        actor.id = actor.id || uuidv4();
        const now = new Date();
        actor.created = now;
        actor.updated = now;
        return knex('actors').insert(actor).returning('*');
    },
    delete: function(id) {
        return knex('actors').where('id', id).del();
    },
    update: function(id, actor) {
        let newActor = {};
        Object.assign(newActor, actor);
        newActor.updated = new Date();
        return knex('actors').where('id', id).update(newActor).returning('*');
    },
};