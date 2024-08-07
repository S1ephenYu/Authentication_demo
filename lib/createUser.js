const connection = require('../config/database');
const User = connection.models.User;
const RefreshTokenTable = connection.models.RefreshTokenTable;
const { v4: uuidv4 } = require('uuid');
const {generateRefreshJWT} = require('./generateJWT');
// return a promise
exports.createUser = async (newUser) => {
    const session = await connection.startSession();
    session.startTransaction();

    return new Promise(async (resolve, reject) => {
        try {
            const userId_uuid = new RefreshTokenTable({
                userId: newUser._id,
                UUID: uuidv4(),
                refreshToken: null,
            });
            userId_uuid.RefreshTokenTable = generateRefreshJWT(userId_uuid);

            await newUser.save();
            await userId_uuid.save();
    
            await session.commitTransaction();
            session.endSession();
            resolve(`User ${newUser.username} registered successfully`);

        } catch (err) {
            await session.abortTransaction();
            session.endSession();
            reject(err);
        }
    });
    
};