const asyncHandler = (requestHandler) => {
    (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next)).catch((error) => next(error))
    }
}




export {asyncHandler}
// const asyncHandler = (fn) => async (res, res, next) => {
//     try {
//         await fn(res, res, next) 
//     }
//     catch(error) {
//         res.status(error.code || 500).json({
//             success: false,
//             message: error.message
//         })
//     }
// }

// export default asyncHandler