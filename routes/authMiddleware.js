const jwt = require('jsonwebtoken');
const RefreshTokenTable = require('../config/database').models.RefreshTokenTable;
const User = require('../config/database').models.User;
const {generateAccessJWT} = require('../lib/generateJWT');


const getAccessTokenByRefreshToken = (refreshToken, req, res, next) => {
    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            req.isAuthenticated = () => false;
            next();
        } else {
            req.isAuthenticated = () => true;
            user_id = decoded.userId;
            UUID = decoded.sub;
            
            // check if the UUID is valid
            // find the refresh token for the user
            RefreshTokenTable.findOne({userId: user_id})
            .then((userId_uuid) => {
                if(!userId_uuid){
                    req.isAuthenticated = () => false;
                    next();
                }
                req.isAuthenticated = () => true;
                // generate new access token
                User.findOne({ _id: user_id })
                .then((user) => {
                    if(!user){
                        req.isAuthenticated = () => false;
                        next();
                    }
                    const accessToken = generateAccessJWT(user);
                    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true });
                    next();
                })
                .catch((err)=> {
                    console.log(err);
                    req.isAuthenticated = () => false;
                    next();
                });
            })
            .catch((err)=>{
                
                req.isAuthenticated = () => false;
                next();
            });
        }
    });
}

module.exports.setIsAuthenticated = (req, res, next) => {
    // check if there is access token
    const accessToken = req.cookies.accessToken;
    // if exist, decode jwt
    if(accessToken){
        jwt.verify(accessToken, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                // check if there is refresh token
                const refreshToken = req.cookies.refreshToken;
                if(refreshToken){
                    getAccessTokenByRefreshToken(refreshToken, req, res, next);
                } else {
                    req.isAuthenticated = () => false;
                    next();
                }
            } else {
                req.isAuthenticated = () => true;
                // console.log it later
                console.log(decoded);
                req.user = decoded;
                next();
            }
        });
    }
    // if not exist, check if there is refresh token
    if(!accessToken){
        const refreshToken = req.cookies.refreshToken;
        
        if(refreshToken){
            getAccessTokenByRefreshToken(refreshToken, req, res, next);
            
        } else {
            req.isAuthenticated = () => false;
            next();
        }
    }
};

module.exports.isAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        next();
    } else {
        res.status(401).json({ msg: 'You are not authorized to view this resource because you are not logged in.' });
    }
}

module.exports.isAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.admin) {
        next();
    } else {
        res.status(401).json({ msg: 'You are not authorized to view this resource because you are not an admin.' });
    }
}