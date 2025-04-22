import cloudinary from "cloudinary"
import fs from "fs"

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_KEY,
    api_secret: process.env.CLOUDINARY_SECRET
})

const uploadOnCloudinary = async (localFilePath) => {
    try {
        
        if(!localFilePath)
            return null
        
        //upload the file on clouindyar
        const response = await cloudinary.v2.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        
        //file has been uploaded successfully
        console.log("File is uploaded on cloudinary", response.url)
        return response
    }
    catch(error) {
        //remove file from the server
        fs.unlinkSync(localFilePath)
        return null
    }
}

export {uploadOnCloudinary}