const express = require('express');
const router = express.Router();
const createError = require('http-errors');
const Actor = require('../db/actor')

const verifyToken = require('../middleware/verify-token');

/* GET actors listing. */
router.get('/', verifyToken, async (req, res, next) => {
    try {
        const userId = req.tokenData.user_id;
        const actors = await Actor.getAllByUser(userId);

        if(actors.length) {
            res.json(actors);
        } else {
            console.error('404 yo')
            next(createError(404));
        }
    } catch(err) {
        next(err);
    }
});

/* Create new actor */
router.post('/', verifyToken, async (req, res, next) => {
    const userId = req.tokenData.user_id;
    const actor = req.body.actor;

    try {
        const returnedActor = await Actor.create(userId, actor);
        res.json({returnedActor});
    } catch (err) {
        next(err);
    }

});

router.delete('/', verifyToken, async (req, res, next) => {
    const userId = req.tokenData.user_id;
    const actor_id = req.body.actor_id;
    
    try {
        const existingActor = await Actor.getOneById(actor_id);
        if(existingActor && existingActor.owner === userId) {
            await Actor.delete(actor_id);
            res.sendStatus(200);
        } else {
            res.send(403);
        }
    } catch (err) {
        next(err);
    }
})

router.put('/', verifyToken, async (req, res, next) => {
    const userId = req.tokenData.user_id;
    const actor_id = req.body.actor.id;
    const actor = req.body.actor;
    
    try {
        const existingActor = await Actor.getOneById(actor_id);
        if(existingActor && existingActor.owner === userId) {
            const updatedActor = await Actor.update(actor_id, actor);
            res.json({updatedActor});
        } else {
            res.send(403);
        }
    } catch (err) {
        next(err);
    }
})

module.exports = router;
