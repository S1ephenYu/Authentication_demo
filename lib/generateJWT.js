const jwt = require('jsonwebtoken');


require('dotenv').config();
module.exports.generateAccessJWT = (user) => {
    return jwt.sign(
        { userId: user.id }, 
        process.env.JWT_SECRET, 
        { expiresIn: '1h',  
        });
};

module.exports.generateRefreshJWT = (userId_uuid) => {
    return jwt.sign(
        { userId: userId_uuid.userId }, 
        process.env.JWT_SECRET, 
        { expiresIn: '7d' ,
          subject: userId_uuid.UUID
        });
};
