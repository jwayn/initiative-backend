const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const createError = require('http-errors');
const uuidv4 = require('uuid/v4');
require('dotenv').config();

const User = require('../db/user')

const router = express.Router();


// Function for testing slow api response
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}


//Ensure that email/password is valid
function validUser(user) {
    const validEmail = typeof user.email == 'string' && 
                        user.email.trim() != '';
    const validPassword = typeof user.password == 'string' && 
                        user.password.trim() != '' &&
                        user.password.trim().length >= 6;

    return validEmail && validPassword;
}

router.post('/signin', async (req, res, next) => {
    try{
        //await sleep(3000);
        if(validUser(req.body)) {
            const user = await User.getOneByEmail(req.body.email);
            if(user) {
                const result = await bcrypt.compare(req.body.password, user.password);
                // If the password matches
                if(result){
                    User.updateLastLogin(user.id);
                    console.log(process.env.JWT_SECRET)
                    if(process.env.JWT_SECRET) {
                        jwt.sign({user_id: user.id, username: user.username, email: user.email}, process.env.JWT_SECRET, {expiresIn: '1d'}, (err, token) => {
                            res.json({
                                token
                            });
                        });
                    } else {
                        next(createError(500))
                    }
                } else {
                    next(createError(401, 'Incorrect email or password'));
                }
            } else {
                next(createError(401, 'A user with that email does not exist.'));
            };
        };
    } catch (err) {
        next(err)
    }
});

router.post('/signup', async (req, res, next) => {
    if(validUser(req.body)) {
        const user = await User.getOneByEmail(req.body.email)
        if(!user) {
            const hash = await bcrypt.hash(req.body.password, 10);
            const userId = await uuidv4();
            const user = {
                id: userId,
                username: req.body.username,
                email: req.body.email,
                password: hash,
            };

            const newUser = await User.create(user);

            await jwt.sign({user_id: newUser.id, email: newUser.email, username: newUser.username}, process.env.JWT_SECRET, {expiresIn: '1d'}, (err, token) => {
                res.json({
                    token
                });
            });

        } else {
            next(createError(401, 'A user with that email address already exists.'))
        }
    } else {
        next(createError(401, 'Invalid email or password.'))
    }
});


module.exports = router;