import express from "express";
import jwt  from "jsonwebtoken";

import { Users } from "./data.js";

const app = express();
app.use(express.json())

const PORT = 5000;

app.get('/' , (req , res) => {
    res.send('Hello From Homepage!');
})

let refreshTokens = [];

app.post('/api/refresh' , (req , res) => {
    
    //take refresh token from the body.
    const refreshToken = req.body.token;

    //check refresh token.
    if(!refreshToken){res.status(401).json('You are not authenticated!')}
    if(!refreshTokens.includes(refreshToken)){res.status(403).json('refresh token is invalid')}
    jwt.verify(refreshToken , "secretRefreshkey"  , (err , user) => {
        err && console.log(err);

        refreshTokens = refreshTokens.filter((token) => (token != refreshToken));

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);

        res.status(200).json({
            accessToken:newAccessToken,
            refreshToken:newRefreshToken,
        })
    } )
})

const generateAccessToken = (user) => {
    return jwt.sign({id:user.id , isAdmin:user.isAdmin} , "secretkey" , {expiresIn:"60s"});
}

const generateRefreshToken = (user) => {
    return jwt.sign({id:user.id , isAdmin:user.isAdmin} , "secretRefreshkey");
}


app.post('/api/login' , (req , res) => {

    const {username , password} = req.body;
    
    const user = Users.find((user) => (user.username ===username && user.password ===password));
    
    if(user){
        const accessToken = generateAccessToken(user); 
        const refreshToken = generateRefreshToken(user);

        refreshTokens.push(refreshToken);

        res.json({
            username: user.username,
            isAdmin:user.isAdmin,
            accessToken,
            refreshToken
        });
    }else{
        res.status(400).json('usernam or password incorrect');
    }
})

function verify(req , res , next){

    const authHeaders = req.headers.authorization;

    if(authHeaders){

        const token = authHeaders.split(" ")[1];
        jwt.verify(token , "secretkey" , (err , user) => {

            if(err){
                return res.status(403).json('Invaild Token... ');
            }
            req.user = user;
            next();
        });
    }else{
        res.status(401).json('You are not authenticated!');
    }
}

app.delete('/api/users/:userID' , verify , (req , res) => {
    if(req.user.id === req.params.userID || req.user.isAdmin){    
        res.status(200).json('User has been deleted...')
    }else{
        res.status(403).json('Acsess Denied...')
    }
});

app.post('/api/logout' , verify , (req ,res) => {

    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token) => (token != refreshToken));
    res.status(200).json('logged out successfully!');
})

app.listen(PORT , () => {
    console.log(`BACK-END SERVER RUNNING ON PORT:    http://localhost:${PORT}`);
})