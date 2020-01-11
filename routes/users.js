const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const createError = require('http-errors');
const uuidv4 = require('uuid/v4');
const verifyToken = require('../middleware/verify-token');
const nodemailer = require('nodemailer');
const mg = require('nodemailer-mailgun-transport');

require('dotenv').config();

const User = require('../db/user')

const router = express.Router();

const auth = {
    auth: {
      api_key: process.env.MG_API_KEY,
      domain: process.env.MG_DOMAIN,
    },
  }

const nodemailerMailgun = nodemailer.createTransport(mg(auth));
 
function sendEmail(recipient, subject, html, text) {
    nodemailerMailgun.sendMail({
        from: 'Roll Initiative <info@rollinitiative.app>',
        to: recipient,
        subject,
        html: html ? html : '',
        text,
    }, (err, info) => {
        if (err) {
            console.log(`Error: ${err}`);
        }
        else {
            console.log(`Response: ${info}`);
        }
    });
}


// Function for testing slow api response
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Generate pseudo-random strings
function generateToken(length) {
    let token = "";
    let possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for(let i = 0; i < length; i++) {
        token += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return token;
};


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
            console.log(user);
            if(user) {
                //If the user is active
                if(user.active === true) {
                    const result = await bcrypt.compare(req.body.password, user.password);
                    // If the password matches
                    if(result){
                        await User.updateLastLogin(user.id);
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
                    next(createError(401, 'Account is not verified.'));
                };
            } else {
                next(createError(401, 'A user with that email does not exist.'));
            }
        } else {
            next(createError(401, 'Incorrect email or password.'))
        };
    } catch (err) {
        next(err)
    }
});

// Get user
router.get('/', verifyToken, async (req, res, next) => {
    if(req.tokenData) {
        const user = await User.getOneById(req.tokenData.user_id);
        console.log(user);
        res.json({user});
    } else {
        next(createError(401));
    }
});

router.post('/requestpassreset', async (req, res, next) => {
    console.log(req.body);
    try {
        if(req.body.email) {
            console.log('Checking if user exists.')
            // Check if user exists in users by email
            const user = await User.getOneByEmail(req.body.email).catch(err => {next(err)});
            if(user) {
                console.log(user);
                // Create a record in the reset pass table with an auth key.
                const token = generateToken(40);
                //Check to see if user have a token already
                const existingToken = await User.getResetPassTokenByUser(user.id);
                //If they do, delete it.
                if(existingToken) {
                    console.log(existingToken);
                    await User.deleteResetPassToken(existingToken.token);
                };
                //Insert a pass reset record in DB
                await User.createResetPassToken(user.id, token).catch(err => {next(err)});
                // Email the user a link to the frontend 
                const link = `${req.protocol}://${req.headers.host}/resetpassword?token=${token}`;
                sendEmail(
                    `${user.username} <${user.email}>`,
                    'Reset your RollInitiative password.',
                    `Please click <a href="${link}">here</a> to reset your password.`,
                    `Please click ${link} to reset your password.`
                );
                res.sendStatus(200);
            } else {
                res.sendStatus(204);
            }
    
        }
    } catch (err) {
        next(err);
    }
});

router.post('/changepass', async (req, res, next) => {
    if(req.query.token) {
        //Check the database for that token
        const resetRecord = await User.getResetPassToken(req.query.token);
        if(resetRecord) {
            if(req.body.password) {
                const hash = await bcrypt.hash(req.body.password, 10).catch(err => {next(err)});
                await User.update(resetRecord.user_id, {password: hash}).catch(err => {next(err)});
                await User.deleteResetPassToken(resetRecord.token);
                res.sendStatus(200);
            } else {
                res.sendStatus(402);
            }
        } else {
            res.sendStatus(401);
        }
    }
});

router.post('/resendverification', async (req, res, next) => {
    if(req.query.email) {
        const user = User.getOneByEmail(req.query.email).catch(err => {next(err)});
        if(user) {
            const verificationRecord = await User.getVerificationByUserId(user.id).catch(err => {next(err)});

            if(verificationRecord) {
                //Delete our existing verification record and create a new one.
                await User.deleteVerificationRecord(verificationRecord.user_id).catch(err => {next(err)});
                const verificationToken = await User.createVerification(newUser.id, generateToken(40)).catch(err => {next(err)});
            
                console.log(verificationToken);
                await sendEmail(
                    `${newUser.username} <${newUser.email}>`,
                    'Please verify your RollInitiative account.',
                    `Please <a href="${req.protocol}://${req.headers.host}/verify?token=${verificationToken}">verify your RollInitiative account</a>.`,
                    `Please verify your RollInitiative account at ${req.protocol}://${req.headers.host}/verify?token=${verificationToken}`
                ).catch(err => {next(err)});
    
                res.sendStatus(200);
            }

        }
    };
});

router.get('/verify', async (req, res, next) => {
    if(req.query.token) {
        //check for token in database
        const verificationRecord = await User.getVerificationByToken(req.query.token).catch(err => {next(err)});

        if(verificationRecord) {
            await User.update(verificationRecord.user_id, {active: true}).catch(err => {next(err)});
            await User.deleteVerificationRecord(verificationRecord.user_id);
            // Log user in
            const user = await User.getOneById(verificationRecord.user_id).catch(err => {next(err)});
            if(user) {
                await User.updateLastLogin(user.id);
                console.log(user);
                jwt.sign({user_id: user.id, username: user.username, email: user.email}, process.env.JWT_SECRET, {expiresIn: '1d'}, (err, token) => {
                    console.log('Logging in user with email "' + user.email + '".')
                    // If we were successful we log return the JWT token
                    res.json({
                        token
                    });
                });
            } else {
                res.sendStatus(402)
            }
        } else {
            res.sendStatus(401);
        }
    }
});

router.delete('/', verifyToken, async (req, res, next) => {
    await User.delete(req.tokenData.user_id).catch(err => {next(err)});
    res.sendStatus(200);
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

            const verificationToken = await User.createVerification(newUser.id, generateToken(40));
            console.log(verificationToken);
            await sendEmail(
                `${newUser.username} <${newUser.email}>`,
                'Please verify your RollInitiative account.',
                `Please <a href="${req.protocol}://${req.headers.host}/verify?token=${verificationToken}">verify your RollInitiative account</a>.`,
                `Please verify your RollInitiative account at ${req.protocol}://${req.headers.host}/verify?token=${verificationToken}`
            );

            res.sendStatus(200);
            // await jwt.sign({user_id: newUser.id, email: newUser.email, username: newUser.username}, process.env.JWT_SECRET, {expiresIn: '1d'}, (err, token) => {
            //     res.json({
            //         token
            //     });
            // });

        } else {
            next(createError(401, 'A user with that email address already exists.'))
        }
    } else {
        next(createError(401, 'Invalid email or password.'))
    }
});


module.exports = router;