function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated && req.isAuthenticated()) {
        return next();
    }

    return res.status(401).send("Unauthorized. Please log in first.");
}

module.exports = ensureAuthenticated;