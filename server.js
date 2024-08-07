const express = require('express');
const mongoose = require('mongoose');
var passport = require('passport');
var crypto = require('crypto');
var routes = require('./routes');
const cookieParser = require('cookie-parser');
const connection = require('./config/database');
const setIsAuthenticated = require('./routes/authMiddleware').setIsAuthenticated;


/**
 * -------------- GENERAL SETUP ----------------
 */

// Gives us access to variables set in the .env file via `process.env.VARIABLE_NAME` syntax
require('dotenv').config();

// Create the Express application
var app = express();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({extended: true}));



/**
 * -------------- PASSPORT AUTHENTICATION ----------------
 */

// Need to require the entire Passport config module so app.js knows about it
require('./config/passport');

app.use(passport.initialize());
app.use(setIsAuthenticated);


/**
 * -------------- ROUTES ----------------
 */

// Imports all of the routes from ./routes/index.js
app.use(routes);


/**
 * -------------- SERVER ----------------
 */

// Server listens on http://localhost:3000
app.listen(3000);