import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId)
    
        const accessToken = await user.generateAccessToken()
        const refreshToken = await user.generateRefreshToken()
    
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
    
        return {accessToken, refreshToken}

    }
    catch(error) {
        throw new ApiError(400, "Something went wrong")
    }
}


export const registerUser = asyncHandler(async (req, res, next) => {
    //get user details from frontend
    //validation - not empty
    //check if user already exists - username, email
    //check for files - avatar(required), coverImage
    //upload them to cloudinary, avatar
    //create user object - create entry in DB
    //remove password and response token from response
    //check for user creation - return response

    const { username, fullName ,email, password } = req.body
    if(!username || !fullName || !email || !password) {
        throw new ApiError(400, "Please provide all the field")
    }

    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if(existingUser) {
        throw new ApiError(409, "User already exits")
    }
    
    //first property is object
    const avatarLocalPath = req.files?.avatar[0]?.path
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0)
        coverImageLocalPath = req.files.coverImage[0].path

    if(!avatarLocalPath) {
        throw new ApiError(409, "Please provide avatar")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar) {
        throw new ApiError(409, "Please provide avatar")
    }

    const user = await User.create({
        username: username.toLowerCase(),
        fullName,
        password,
        email,
        avatar: avatar.url,
        coverImage: coverImage?.url || ""
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser) {
        throw new ApiError(500, "Something went wrong while creating the user")
    }

    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registered Successfully")
    )

})

export const loginUser = asyncHandler(async (req, res, next) => {
    //get the username or email and password
    //check if user exists and check password
    //access and refresh token 
    //send cookie
    const { username, email, password } = req.body

    if(!username && !email) {
        throw new ApiError(400, "please provide email or username")
    }

    if(!password) {
        throw new ApiError(400, "please provide the password")
    }

    const user = await User.findOne({
        $or: [{ email }, { username }]
    })

    if(!user) {
        throw new ApiError(400, "user does not exist")
    }

    const validPassword = await user.isPasswordCorrect(password)
    
    if(!validPassword) {
        throw new ApiError(400, "incorrect password")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    //cannot be modified using frontend
    const options = {
        httpOnly: true,
        secure: true,
    }

    //if cookie not set as in mobile application
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200, {
            user: loggedInUser,
            accessToken,
            refreshToken
        }, "user logged in successfully")
    )
})

export const logoutUser = asyncHandler(async (req, res, next) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true // to get updated user
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "logout Successfull"))
})

export const refreshAccessToken = asyncHandler(async (req, res, next) => {
    //refreshToken from cookie
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    
    if(!incomingRefreshToken) {
        throw new ApiError(400, "unauthorised access")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user) {
            throw new ApiError(400, "user not found")
        }
    
        if(incomingRefreshToken !== user?.refreshAccessToken) {
            throw new ApiError(400, "refresh token expired or used")
        }
    
        const { access, refresh } = await generateAccessAndRefreshToken(user._id)
    
        const options = {
            httpOnly: true,
            secure: true
        }
        
        return res
               .status(200)
               .cookie("accessToken", accessToken, options)
               .cookie("refreshToken", refreshToken, options)
               .json(
                new ApiResponse(200, {accessToken: access, refreshToken: refresh}, "access token refreshed")
               )  
    } catch (error) {
        throw new ApiError(400, error?.message || "something went wrong")
    }         
})

export const changeCurrentPassword = asyncHandler(async (req, res, next) => {
    const { currentPassword, newPassword } = req.body
    
    if(!currentPassword || !newPassword) {
        throw new ApiError(400, "please provide password")
    }

    const user = await User.findById(req.user._id)

    const validPassword = await user.isPasswordCorrect(currentPassword)

    if(!validPassword) {
        throw new ApiError(400, "password incorrect")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
           .status(200)
           .json(
            new ApiResponse(200, {}, "password changed success")
           )


    
})

export const getCurrentUser = asyncHandler(async (req, res, next) => {
    return res
           .status(200)
           .json(
            new ApiResponse(200, req.user, "current user fetched successfully")
           )
})

export const updateAccountDetails = asyncHandler(async (req, res, next) => {
    const {fullName, email} = req.body
    
    if(!fullName || !email) {
        throw new ApiError(400, "provide all details")
    }

    const user = await User.findByIdAndUpdate(req.user._id, {
        $set: {
            fullName,
            email
        }
    },{new: true}).select("-password")

    return res
           .status(200)
           .json(
            new ApiResponse(200, user, "user updated success")
           )

})

export const updateUserAvatar = asyncHandler(async (req, res, next) => {
    const avatarLocalPath = req.files?.avatar[0]?.path

    if(!avatarLocalPath) {
        throw new ApiError(400, "avatar not found")
    }

    const response = await uploadOnCloudinary(avatarLocalPath)

    if(!response.url) {
        throw new ApiError(400, "error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(req.user._id, {
        $set: {
            avatar: response.url
        }
    },{new: true}).select("-password")

    return res
           .status(200)
           .json(
            new ApiResponse(200, user, "avatar updated success")
           )
})

export const updateUsercoverImage = asyncHandler(async (req, res, next) => {
    const coverImageLocalPath = req.files?.coverImage[0]?.path

    if(!coverImageLocalPath) {
        throw new ApiError(400, "coverImage not found")
    }

    const response = await uploadOnCloudinary(coverImageLocalPath)

    if(!response.url) {
        throw new ApiError(400, "error while uploading coverImage")
    }

    const user = await User.findByIdAndUpdate(req.user._id, {
        $set: {
            coverImage: response.url
        }
    },{new: true}).select("-password")

    return res
           .status(200)
           .json(
            new ApiResponse(200, user, "coverImage updated success")
           )
})

