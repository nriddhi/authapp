const User = require('../models/AuthD');
const Token = require('../models/mailToken');
const sendEmail = require('../utils/sendEmail');
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const emailValidator = require('email-validator');
const bcrypt = require('bcrypt');


  const login =  async(req, res, next)=> {

    try {

    if(emailValidator.validate(req.body.userData))
    {
      const email = await User.findOne({ email: req.body.userData });
      if(!email) return res.status(404).json({code:'le404',msg:'Email not Registered'});

      const verified = await User.findOne({ email: req.body.userData });
      if(!verified.verified) return res.status(404).json({code:'lv404',msg:'User not Verified'});

      const validated = await bcrypt.compare(req.body.password, email.password);
      if(!validated) return res.status(404).json({code:'lw404',msg:'Wrong credentials!'});

      const accessToken = jwt.sign({
         uId : email._id
      }, process.env.JWT_SECRET, {
        expiresIn: "3500s",
      });

      if (req.cookies['ecom_token']) {
        req.cookies['ecom_token'] = "";
      }
      
      res.cookie('ecom_token', accessToken, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        secure:false
      });

      return res
      .status(200)
      .json({ message: "Logged In Successfully", code:'l200' });
    }
    else if(!emailValidator.validate(req.body.userData)) {

      const uname = await User.findOne({ username: req.body.userData });
      if(!uname) return res.status(404).json({code:'lu404', msg:'Username Not Found'});

      const verified = await User.findOne({ username: req.body.userData });
      if(!verified.verified) {
      const etoken = await new Token({
        userId: verified._id,
        token : crypto.randomBytes(24).toString('hex')
       }).save();
      
      const msg= 'SignUp Verfication<nayeemriddhi.info>';
      const url = `${process.env.BASE_URL}/users/${etoken.userId}/verify/${etoken.token}`;
      const htmlmsg =`<p>Please click the link for Verify your Email ${url}Thank you and regards</p>`;
      await sendEmail(verified.email, msg, htmlmsg ); 
      return res.status(404).json({code:'lv404',msg:'User not Verified'});
    }
   else if(verified.verified)
   {
    const validated = await bcrypt.compare(req.body.password, verified.password);
    if(!validated) return res.status(404).json({code:'lw404',msg:'Wrong credentials!'});

    const accessToken = jwt.sign({
      uId : verified._id
   }, process.env.JWT_SECRET, {
    expiresIn: "3500s",
  });

   if (req.cookies['ecom_token']) {
     req.cookies['ecom_token'] = "";
   }
   
   res.cookie('ecom_token', accessToken, {
     path: "/",
     httpOnly: true,
     sameSite: "lax",
     secure:false
   });

    res.status(200).json({ message: "Logged In Successfully", code:'l200'});

   }   }

    else {
      res.status(404).json('Not Found');
    }

  }
  catch(err){
     res.status(500).json('Server Not Responding');
  }

  };

  const verifyToken = (req, res, next) => {
    const token = req.cookies.ecom_token;
  
    if (!token) {
      return res.status(404).json({ code:'lo400', message: "No token found" });
    }
    jwt.verify(String(token), process.env.JWT_SECRET, (error, user) => {
      if (error) {
        return res.status(400).json({code:'lou400', message: "Invalid Token" });
      }
      req.uId = user.uId;
    });
    next();
  };
  
  const refreshToken = (req, res, next) => {
    const cookieToken = req.cookies.ecom_token; 
    if (!cookieToken) {
      return res.status(400).json({ code:'lo400', message: "Couldn't find token" });
    }
    jwt.verify(String(cookieToken), process.env.JWT_SECRET, (err, user) => {
      if (err) {
        res.clearCookie('ecom_token');
        return res.status(403).json({ code:'lou400', message: "Authentication failed" });
      }
      res.clearCookie('ecom_token');
      
      const token = jwt.sign({ uId: user.uId }, process.env.JWT_SECRET, {
        expiresIn: "3500s",
      } );
  
      res.cookie('ecom_token', token, {
        path: "/",
        httpOnly: true,
        sameSite: "lax",
        //secure:false
      });
  
      req.uId = user.uId;
      next();
    });
  };

  const getUser = async (req, res, next) => {
    const userId = req.uId;
    let user;
    try {
      user = await User.findById({_id: userId});
    } catch (error) {
      return new Error(error);
    }
    if (!user) {
      return res.status(400).json({ code:'lo400', message: "Logout && No User with this id" });
    }
    else {
    return res.status(200).json({ code:'lpr200', msg:'Login persist' });
  }
  };

  const logout = (req, res, next) => {
    const token = req.cookies.ecom_token;
    if (!token) {
      return res.status(400).json({ message: "Couldn't find token" });
    }
    jwt.verify(String(token), process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: "Authentication failed" });
      }
      res.clearCookie('ecom_token');
      req.cookies['ecom_token'] = "";
      return res.status(200).json({code: 'logoutscs200', message: "Successfully Logged Out" });
  })};
  
  exports.verifyToken = verifyToken;
  exports.getUser = getUser;
  exports.refreshToken = refreshToken;
  exports.logout = logout;
  exports.login = login;