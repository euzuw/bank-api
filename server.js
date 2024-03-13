require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()
const userBalance = 0;

// Config CORS to accept requests from React app
app.use(cors({ origin: 'http://localhost:3000' }))

// Config JSON response
app.use(express.json())

// Models
const User = require('./Models/Users')

// Public route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Teste"})
})

// Private route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // Check if user exists
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: "User not Found"})
    }

    res.status(200).json({user})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'Unauthorized'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({msg: 'Invalid token'})
    }
}

// Register user    
app.post('/auth/register', async(req, res) => {
    const {name, cpf, email, password} = req.body

    // Validations
    if(!name) {
        return res.status(422).json({msg:'O nome é obrigatório'})
    }
    if(!cpf) {
        return res.status(422).json({msg: 'O cpf é obrigatório'})

    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatório'})
    }

    }
    if(!password) {
        return res.status(422).json({msg:'A senha é obrigatório'})
    }

    // Check if user exists
    const userExists = await User.findOne({name : name})

    if(userExists) {
        return res.status(422).json({msg: "Usuário já existe"})
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create user
    const user = new User ({
        name,
        email,
        cpf,
        password: passwordHash,
    })

    try {

    await user.save()
    res.status(201).json({msg: "User created"})

    } catch(error) {
        res.status(500).json({msg: error})
    }
})

// Login User
app.post('/auth/login', async (req, res) => {
    const {name, password} = req.body

// Validations

if(!name) {
    return res.status(422).json({msg:'O nome é obrigatório'})
}
if(!password) {
    return res.status(422).json({msg:'A senha é obrigatório'})
}

// Check if user exists
const user = await User.findOne({name : name})

if(!user) {
    return res.status(404).json({msg: "User not found"})
}

// Check if password match
const checkPassword = await bcrypt.compare(password, user.password)

if (!checkPassword) {
    return res.status(402).json({msg: "Invalid password"})
}

try {
    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user._id,
    },
    secret,
    )
    res.status(200).json({msg: "Auth sucessfuly", token})
}
catch(err) {
    console.log(error)
    res.status(500).json({msg: error})
}

app.get('/auth/balance', checkToken, async (req, res) => {
    const id = req.user.id;
  
 // Check if user exists
const user = await User.findById(id);
  
if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }
  
    res.status(200).json({ balance: user.balance });
  });

//search all registered users
app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, '-password'); 
        res.status(200).json(users);
    } catch (error) {
        console.error('Erro ao buscar usuários:', error);
        res.status(500).json({ msg: 'Erro ao buscar usuários' });
    }
});

})

// Connect to MongoDB
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@project.fueuroi.mongodb.net/?retryWrites=true&w=majority&appName=project`
).then(() => {

    app.listen(3001)
    console.log("Connected to Database")
}).catch((err) => console.log(err))
