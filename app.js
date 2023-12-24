//jshint esversion:6
import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import passportlocal from "passport-local";
import passportgglauth20 from "passport-google-oauth20";

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "secrets",
    password: process.env.DBPASS,
    port: 5432,
});
db.connect();

var user = {
    username:""
};

const LocalStrategy = passportlocal.Strategy;
const GoogleStrategy = passportgglauth20.Strategy;

passport.use("local-register" , new LocalStrategy( async(username, password, done) => {
    try{
        const hash_password = await db.query("SELECT * from users WHERE username=$1",[username]);
        if(hash_password.rowCount == 0){
          bcrypt.hash(password, 10, async (err, hash) => {
            if(err){
              return done(err);
            }else{
              await db.query("INSERT INTO users(username,password) VALUES($1,$2);",[username,hash]);
              user.username=username;
              return done(null,user);
            }
          });
        }else{
          return done(null, false);
        }
    }catch(err){
      return done(err);
    }
  }
));
 
passport.use("local-login" , new LocalStrategy( async(username, password, done) => {
    try{
        const hash_password = await db.query("SELECT * from users WHERE username=$1",[username]);
        if(hash_password.rowCount == 0){
          return done(null,false,{message:"User name or password is incorrect."});
        }else{
          bcrypt.compare(password,hash_password.rows[0].password, (err,result)=>{
            if(err){
            return done(err);
            }
            else if(result==false){
            return done(null,false,{message:"User name or password is incorrect."});
            }else{
            return done(null, hash_password.rows[0]);
            }
          });
        }
    }catch(err){
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
    done(null, user.username);
});
  
passport.deserializeUser( async(username, done) => {
const result = await db.query("SELECT * FROM users WHERE username=$1",[username]);
done(null, result.rows[0]);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  async (accessToken, refreshToken, profile, cb) => {
    try{
        const result = await db.query("SELECT * FROM users WHERE username=$1",[profile.id]);
        if(result.rowCount > 0){
          return cb(null, result.rows[0]);
        }else{
          await db.query("INSERT INTO users (username) VALUES ($1)",[profile.id]);
          user.username=profile.id;
          return cb(null,user);
        }
    }catch (err) {
      return cb(err);
    }
}
));

app.get("/", (req, res) =>{
  if(req.isAuthenticated()){
    res.redirect("/secrets");
  }else{
    res.render("home");
  }
});

app.get("/register", (req, res) =>{
    res.render("register")
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get("/submit", (req, res) =>{
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", async(req, res) =>{
    const secret = req.body.secret;
    const user = req.user;
    var username = user.username;
    await db.query("INSERT INTO secret_table (secret_text, username) VALUES ($1, $2) ",[secret, username]);
    res.redirect("/secrets");
});

app.get('/auth/google/secrets', passport.authenticate('google', { 
    failureRedirect: '/login', 
    successRedirect: '/secrets'
    }),
);

app.post("/register",passport.authenticate("local-register", {
    successRedirect: '/secrets',  // Redirect to secrets page on successful registration
    failureRedirect: '/register'   // Redirect back to the registration page if there is an error
  })
);

app.get("/login", (req, res) =>{
    res.render("login")
});

app.post("/login", passport.authenticate("local-login", {
    successRedirect: '/secrets',
    failureRedirect: '/login'
})
);

app.get("/logout", (req, res)=>{
    req.logout(function(err) {
        if(err){ 
            return next(err); 
        }else{
            res.redirect('/');
        }
      });
});

app.get("/secrets", async(req, res)=> {
    if(req.isAuthenticated()) {
        var user = req.user;
        var username = user.username;
        var your_secrets = (await db.query("SELECT * FROM secret_table WHERE username=$1",[username])).rows;
        var all_secrets = (await db.query("SELECT secret_text FROM secret_table WHERE username!=$1",[username])).rows;
        res.render("secrets", {userSecrets:your_secrets, allSecrets:all_secrets});
    }else {
        res.redirect("login")
    }
});


app.listen(3000, function(){
    console.log(`server started on port 3000`);
})