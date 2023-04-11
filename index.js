const express = require('express');
var cookieParser = require('cookie-parser');
const app = express();
var session = require('express-session')
const mongoose = require('mongoose');
require('dotenv').config();
const cors = require('cors');
const passport = require("passport");
const port = process.env.PORT || 5000;
const authRoute = require('./routes/Auth');
const passportSetup = require("./Passport");


app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
  }));

app.use(cors({
    origin: true, //included origin as true
    credentials: true, //included credentials as true
}
));

app.use(express.json());
app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.authenticate('session'));


app.use(['/api/auth','/valid','/users', '/api/admin'], authRoute);

mongoose.connect(process.env.MONGO_URL)
.then(console.log('MongoDB Connected'))
.catch((err) => console.log(err));

app.listen(port, () => {
    console.log("Server is running on " +port);
});