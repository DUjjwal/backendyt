import express from "express"
import { changeCurrentPassword, getCurrentUser, getUserChannelProfile, getWatchHistory, loginUser, logoutUser, refreshAccessToken, registerUser, updateUserAvatar, updateUsercoverImage } from "../controllers/user.controller.js"
import { upload } from "../middleware/multer.middleware.js"
import { verifyJwt } from "../middleware/auth.middleware.js"

const router = express.Router()


router.route("/register").post(
    upload.fields([
        {
            name: 'avatar',
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser)

router.route("/login").post(loginUser)

//secured routes
router.route("/logout").post(verifyJwt, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/change-password").post(verifyJwt, changeCurrentPassword)
router.route("/current-user").get(verifyJwt, getCurrentUser)
router.route("/update-account").patch(verifyJwt, changeCurrentPassword)
router.route("/avatar").post(verifyJwt, upload.single('avatar'),updateUserAvatar)
router.route("/coverimage").post(verifyJwt, upload.single('coverImage'),updateUsercoverImage)
router.route("/c/:username").get(verifyJwt, getUserChannelProfile)
router.route("/history").post(verifyJwt, getWatchHistory)




export default router