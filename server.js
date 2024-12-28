const express = require('express')
const fs = require('node:fs')
const path = require('node:path')
const server = express()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const cors = require('cors')

require('dotenv').config()

server.use(express.json())
server.use(cors())

const getUsers = () => {
    return JSON.parse(fs.readFileSync(path.join(__dirname, 'data/users.json'), 'utf-8'))
}
const setUsers = (data) => {
    fs.writeFileSync(path.join(__dirname, 'data/users.json'), JSON.stringify(data))
}

const secret_key = 'secretKey'
const createJWT = (payload) => {
    const token = jwt.sign(payload, secret_key, {expiresIn: 100000})
    return token
}

const registerValid = (req, res, next) => {
    const users = getUsers()

    if(users.some(elm => elm.username === req.body.username)){
        return res.status(400).json({message:"user with that username already exist"})
    }
    next()
}

const comparePasswords = async(password, hashed) => {
    try {
        const areSame = await bcrypt.compare(password, hashed)
        return areSame
    } catch {
        return false
    }
}

server.post('/register', registerValid, async(req, res ) => {
    const users = getUsers()

    const {username, password} = req.body
    const hashedPassword = await bcrypt.hash(password, 10)

    users.push({username, password:hashedPassword})
    setUsers(users)
    res.status(200).json({message:"registrated succesfully"})
} )

server.post('/login', async(req, res) => {
    const users = getUsers()
    const {username, password} = req.body
    
    const found = users.find(elm => elm.username === username)

    if(!found){
        return res.status(404).json({message:"User not found"})
    }
    if(await comparePasswords(password, found.password)){
        const token = createJWT({username:username})
        return res.status(200).json({token:token})
    } else {
        return res.status(404).json({message:"User not found"})
    }
})

const authorization = (req, res, next) => {
    const users = getUsers()
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    
    if(!token){
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const {username} = jwt.verify(token, secret_key)
        const users = getUsers();
        if (!users.some(elm => elm.username === username)) {
            return res.status(401).json({ message: "Not authorized" });
        }

        req.username = username
        next()
    } catch {
        return res.status(401).json({message:"not valid"})
    }

}

server.get('/protected',authorization, (req, res) => {

    return res.status(200).json({message: `
        Authorized successfully !
        ${req.username}
        `})
})

const PORT = process.env.PORT
server.listen(PORT, () => {
    console.log('server is running')
})