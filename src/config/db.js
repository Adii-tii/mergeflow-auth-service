const mongoose = require('mongoose')

const connectDB = async () => {
    try {
        const mongoURI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/prtracker";
        await mongoose.connect(mongoURI);
        console.log('MongoDB connected');
    }
    catch (err) {
        console.error(err.message);
    }
}

module.exports = connectDB;
