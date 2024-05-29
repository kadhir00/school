const express = require("express");
const mongoose = require("mongoose");
require('dotenv').config();
const { check, validationResult } = require('express-validator');
const bcrypt = require("bcryptjs");
const jwtToken = require("jsonwebtoken");

const app = express();

app.use(express.json());
mongoose.connect('mongodb://127.0.0.1:27017/traning2').catch(error => console.error(error));
mongoose.connection.on("connected", () => {
    console.log("connected to mongo");
});

const Schema = mongoose.Schema;

// Teacher schema
const teacherSchema = new Schema({
    name: { type: String, trim: true },
    email: { type: String, trim: true, unique: true },
    password: { type: String, trim: true },
    address: { type: String, trim: true },
    status: { type: String, default: "ACTIVE", enum: ["ACTIVE", "INACTIVE"] }
});
const Teacher = mongoose.model("teachers", teacherSchema);

// Student schema
const studentSchema = new Schema({
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    classId: { type: mongoose.Schema.Types.ObjectId, ref: 'classes' },
    parentName: { type: String, trim: true },
    address: { type: String, trim: true },
    city: { type: String, trim: true }
});
const Student = mongoose.model("students", studentSchema);

// Class schema
const classSchema = new Schema({
    standard: { type: String, required: true },
    section: { type: String, required: true },
    status: { type: String, default: "ACTIVE", enum: ["ACTIVE", "INACTIVE"] },
    teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'teachers' }
});
const Class = mongoose.model("classes", classSchema);

// Validators

// Teacher registration validator
const teacherRegistrationValidator = [
    check("name", "Name is required").not().isEmpty(),
    check("email", "Email is required").not().isEmpty(),
    check("email", "Email is invalid").isEmail(),
    check("password", "Password is required").not().isEmpty(),
    check("password", "Password must be at least 8 characters long").isLength({ min: 8 })
];

// Teacher login validator
const teacherLoginValidator = [
    check("email", "Email is required").not().isEmpty(),
    check("email", "Email is invalid").isEmail(),
    check("password", "Password is required").not().isEmpty()
];

// Middleware for authenticating token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Access Denied: No Token Provided" });

    try {
        const verified = jwtToken.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ message: "Invalid Token" });
    }
};

// API Endpoints

// Teacher registration
app.post("/register", teacherRegistrationValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, email, password, address } = req.body;

        // Check if email already exists
        const existingTeacher = await Teacher.findOne({ email });
        if (existingTeacher) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newTeacher = new Teacher({
            name,
            email,
            password: hashedPassword,
            address
        });

        await newTeacher.save();
        res.send({ user: newTeacher, message: "Registration is done successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

// Teacher login
app.post("/login", teacherLoginValidator, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;

        const teacher = await Teacher.findOne({ email });
        if (!teacher) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, teacher.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const token = jwtToken.sign({ id: teacher._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.send({ user: teacher, token, message: "Login successful" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

// Class management
app.post("/class", authenticateToken, async (req, res) => {
    try {
        const { standard, section, teacherId } = req.body;
        const newClass = new Class({ standard, section, teacherId });
        await newClass.save();
        res.send({ class: newClass, message: "Class added successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.put("/class/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updatedClass = await Class.findByIdAndUpdate(id, req.body, { new: true });
        res.send({ class: updatedClass, message: "Class updated successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.delete("/class/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Class.findByIdAndDelete(id);
        res.send({ message: "Class deleted successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.get("/classes", authenticateToken, async (req, res) => {
    try {
        const classes = await Class.find().populate('teacherId');
        res.send(classes);
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

// Student management
app.post("/student", authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, classId, parentName, address, city } = req.body;
        const newStudent = new Student({ firstName, lastName, classId, parentName, address, city });
        await newStudent.save();
        res.send({ student: newStudent, message: "Student added successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.put("/student/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updatedStudent = await Student.findByIdAndUpdate(id, req.body, { new: true });
        res.send({ student: updatedStudent, message: "Student updated successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.delete("/student/:id", authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Student.findByIdAndDelete(id);
        res.send({ message: "Student deleted successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.get("/students", authenticateToken, async (req, res) => {
    try {
        const students = await Student.find().populate({
            path: 'classId',
            populate: { path: 'teacherId' }
        });
        res.send(students);
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

// Public student list with class and teacher details
app.get("/public/students", async (req, res) => {
    try {
        const students = await Student.find().populate({
            path: 'classId',
            populate: { path: 'teacherId' }
        });
        res.send(students);
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.listen(8000, () => {
    console.log("Server is running on port 8000");
});
