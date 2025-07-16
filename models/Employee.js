// models/Employee.js
const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  empCode: { type: String, required: true, unique: true },
  name: String,
  payrollCompany: String,
  division: String,
  location: String,
  designation: String,
  homePractice: String,
  practiceManager: String,
  project: String
});

module.exports = mongoose.model('Employee', employeeSchema);
