const express = require('express');
const joi = require('joi');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const port = 3300;

app.use(express.json());

const users = [];
let tasks = [
    {id:1, name:'1st task', description:'The description for the first task'},
    {id:2, name:'2nd task', description:'The description for the second task'}
];

// Secret key for JWT
const JWT_SECRET = 'TheSecretKey';

//Joi schemas
const taskSchema = joi.object({
    name: joi.string().min(3).required(),
    description: joi.string().min(10).required()
});

const userSchema = joi.object({
    username: joi.string().min(3).required(),
    password: joi.string().min(6).required(),
    role: joi.string().valid('user', 'admin').default('user')
});

//Dat validation middleware
function validateTask(req, res, next) {
    const { error } = taskSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    next();
}
  
function validateUser(req, res, next) {
    const { error } = userSchema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    next();
}

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
            req.user = user;
            next();
    });
}

// Middleware for role-based authorization
function authorize(roles = []) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Unauthorized' });
        }
        next();
    }
}

// User registration
app.post('/register', validateUser, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { 
            id: users.length + 1,
            username: req.body.username, 
            password: hashedPassword,
            role: req.body.role || 'user'
        };
        users.push(user);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

// User login
app.post('/login', async (req, res) => {
    const user = users.find(user => user.username === req.body.username);
    if (!user) return res.status(400).json({ error: 'User not found' });
  
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ accessToken: accessToken });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error logging in' });
    }
});

//GET all tasks
app.get('/api/task', authenticateToken, (req, res) => {
    const userTasks = tasks.filter(task => task.userId === req.user.id);
    res.json(userTasks);
});
  
//GET specific task
app.get('/api/task/:id', authenticateToken, (req, res) => {
    const task = tasks.find(t => t.id === parseInt(req.params.id) && t.userId === req.user.id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
});
  
//Create new task
app.post('/api/task', authenticateToken, validateTask, (req, res) => {
    const task = {
        id: tasks.length + 1,
        name: req.body.name,
        description: req.body.description,
        userId: req.user.id
    };
    tasks.push(task);
    res.status(201).json(task);
});
  
//Update task
app.put('/api/task/:id', authenticateToken, validateTask, (req, res) => {
    const task = tasks.find(t => t.id === parseInt(req.params.id) && t.userId === req.user.id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
  
    task.name = req.body.name;
    task.description = req.body.description;
    res.json(task);
});
  
//DELETE task
app.delete('/api/task/:id', authenticateToken, (req, res) => {
    const taskIndex = tasks.findIndex(t => t.id === parseInt(req.params.id) && t.userId === req.user.id);
    if (taskIndex === -1) return res.status(404).json({ error: 'Task not found' });
  
    tasks.splice(taskIndex, 1);
    res.json({ message: 'Task deleted successfully' });
});
  
//Admin route to get all tasks, including for other users'
app.get('/api/admin/task', authenticateToken, authorize(['admin']), (req, res) => {
    res.json(tasks);
});
  
//Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});
  

app.listen(port, ()=>{
    console.log(`Server is running on port http://localhost:${port}`);
})
