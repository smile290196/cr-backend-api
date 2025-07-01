// middleware/auth.js
const jwt = require('jsonwebtoken');
const config = require('config'); // Import the config package

module.exports = function (req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    console.log('Auth Middleware: Received token:', token ? 'Token received' : 'No token'); // Log if token is received
    if (token) {
        // Log a snippet of the token, just the first 20 chars to avoid clutter
        console.log('Auth Middleware: Token snippet:', token.substring(0, 20) + '...');
    }


    // Check if not token
    if (!token) {
        console.log('Auth Middleware: No token, denying authorization.');
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const jwtSecret = config.get('jwtSecret');
        console.log('Auth Middleware: JWT Secret loaded:', jwtSecret ? 'Secret loaded' : 'Secret NOT loaded!');
        // console.log('Auth Middleware: Actual JWT Secret:', jwtSecret); // CAUTION: Only uncomment temporarily in dev, never in production!

        // Verify token
        const decoded = jwt.verify(token, jwtSecret);
        console.log('Auth Middleware: Token successfully decoded!');
        console.log('Auth Middleware: Decoded payload (req.user):', decoded.user); // Log the decoded user object

        req.user = decoded.user;
        next(); // Move to the next middleware or route handler
    } catch (err) {
        console.error('Auth Middleware Error:', err.message); // Log the specific error message from jwt.verify
        res.status(401).json({ msg: 'Token is not valid' });
    }
};