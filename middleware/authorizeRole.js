// middleware/authorizeRole.js

module.exports = (...allowedRoles) => {
    return (req, res, next) => {
        // req.user.role should be set by the auth middleware
        if (!req.user || !req.user.role) {
            return res.status(401).json({ msg: 'Not authorized: User role not found' });
        }

        const { role } = req.user;

        if (!allowedRoles.includes(role)) {
            return res.status(403).json({ msg: `Forbidden: You do not have the required role (${allowedRoles.join(', ')}) to access this resource.` });
        }
        next();
    };
};