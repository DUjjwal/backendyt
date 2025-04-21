import connectDB from "./db/index.js";




connectDB()

/*
function connectDB() {

}

connectDB()

( async () => {
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
    }
    catch(error) {
        console.log(error)
        throw error
    }
})()
*/