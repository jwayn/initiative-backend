var express = require('express');
var router = express.Router();

const verifyToken = require('../middleware/verify-token');

/* GET users listing. */
router.get('/', verifyToken, function(req, res, next) {
    
});

module.exports = router;
