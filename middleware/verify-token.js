const jwt = require('jsonwebtoken');
const createError = require('http-errors');

module.exports = (req, res, next) => {
    try {
        if(req.headers.authorization) {
            const token = req.headers.authorization.split(' ')[1];
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
            req.tokenData = decodedToken;
        } else {
            console.log('Token is no good.');
            res.sendStatus(401);
        }
    } catch (err) {
        console.log(err);
        next(err);
    }
    next();
}