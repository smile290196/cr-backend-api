// server.js
require('dotenv').config(); // Ensure environment variables are loaded
const express = require('express'); // Import the Express framework
const cors = require('cors'); // Import cors for handling cross-origin requests
const pool = require('./db'); // Import our database connection pool
const bcrypt = require('bcryptjs'); // Import bcrypt for password hashing
const jwt = require('jsonwebtoken'); // Import jsonwebtoken for creating and verifying JWTs
const auth = require('./middleware/auth'); // Import our custom authentication middleware
const authorizeRole = require('./middleware/authorizeRole'); // Import the new authorization middleware
const config = require('config'); // Import the config package here too

const app = express(); // Create an Express application instance

// Middleware - IMPORTANT: These must come BEFORE your routes
app.use(cors({
    origin: '*' // Temporarily allows requests from any origin
}));
app.use(express.json()); // Allows us to parse JSON bodies from incoming requests

const PORT = process.env.PORT || 5000; // Define the port the server will listen on

// Basic route for testing server status
app.get('/', (req, res) => {
    res.send('Cycle Repair Backend API is running!');
});

// --- User Authentication Routes ---

// POST a new user (Registration) - This route is public. Newly registered users are 'customer' by default.
app.post('/users', async (req, res) => {
    try {
        const { username, email, first_name, last_name, password } = req.body;

        // Check if user already exists
        const userExists = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json('Username or Email already exists.');
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Default role for new users is 'customer'. Cannot register as admin/employee directly.
        const role = 'customer';

        // Insert new user into the database
        const newUser = await pool.query(
            'INSERT INTO users (username, email, first_name, last_name, password_hash, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, email, first_name, last_name, role',
            [username, email, first_name, last_name, hashedPassword, role]
        );

        res.status(201).json({ message: 'User registered successfully!', user: newUser.rows[0] });
    } catch (err) {
        console.error('Registration Error:', err.message); // More descriptive logging
        res.status(500).send('Server Error during registration');
    }
});

// POST user login - Handles password verification and JWT generation (Public route)
app.post('/auth', async (req, res) => {
    try {
        console.log('Login attempt received.');
        // CHANGE: Revert to expecting 'username' from the request body
        const { username, password } = req.body;

        // Add logging for received credentials (for debugging, remove in production)
        console.log('Received username:', username); // CHANGE: Log 'username' again
        // console.log('Received password:', password); // DO NOT LOG PASSWORDS IN PRODUCTION

        // 1. Check if user exists
        console.log('Querying database for user by username...'); // CHANGE: Updated log message
        // CHANGE: Query by 'username' column again
        const user = await pool.query('SELECT id, username, password_hash, role FROM users WHERE username = $1', [username]);
        console.log('User query result:', user.rows);

        if (user.rows.length === 0) {
            console.log('User not found.');
            return res.status(400).json('Invalid Credentials');
        }

        // 2. Check password
        console.log('Comparing passwords...');
        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        console.log('Password comparison result:', validPassword);

        if (!validPassword) {
            console.log('Invalid password.');
            return res.status(400).json('Invalid Credentials');
        }

        // 3. Generate JWT Token
        console.log('Generating JWT token...');
        const payload = {
            user: {
                id: user.rows[0].id,
                role: user.rows[0].role
            }
        };

        const jwtSecret = config.get('jwtSecret');
        console.log('JWT Secret retrieved (first 5 chars):', jwtSecret ? jwtSecret.substring(0, 5) + '...' : 'Not found');


        jwt.sign(
            payload,
            jwtSecret,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) {
                    console.error('JWT Signing Error:', err);
                    throw err;
                }
                console.log('JWT token generated successfully.');
                res.json({ message: 'Logged in successfully!', token: token, user: { id: user.rows[0].id, username: user.rows[0].username, role: user.rows[0].role } });
            }
        );
    } catch (err) {
        console.error('Login Error: An unhandled exception occurred during login.', err);
        res.status(500).send('Server Error during login');
    }
});

// --- Protected User Routes (Require JWT) ---

// GET current user's profile - PROTECTED (any authenticated user)
app.get('/users/me', auth, async (req, res) => {
    try {
        // req.user contains the decoded JWT payload (id, role) from the auth middleware
        const user = await pool.query('SELECT id, username, email, first_name, last_name, role FROM users WHERE id = $1', [req.user.id]);
        if (user.rows.length === 0) {
            return res.status(404).json('User not found');
        }
        res.json(user.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error fetching user profile');
    }
});

// GET all users - PROTECTED (Admin and Employee only)
app.get('/users', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const allUsers = await pool.query('SELECT id, username, email, first_name, last_name, role FROM users'); // Don't expose password_hash
        res.json(allUsers.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single user by ID - PROTECTED (Admin and Employee, or user themselves)
app.get('/users/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        // Allow admin to view any user, or a user to view their own profile
        if (req.user.role !== 'admin' && req.user.id !== parseInt(id)) {
            return res.status(403).json('Forbidden: You can only view your own profile unless you are an admin.');
        }

        const user = await pool.query('SELECT id, username, email, first_name, last_name, role FROM users WHERE id = $1', [id]);

        if (user.rows.length === 0) {
            return res.status(404).json('User not found');
        }
        res.json(user.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// PUT (update) a user by ID - PROTECTED (Admin only can change roles; user can update their own non-role info)
app.put('/users/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;
        const { username, email, first_name, last_name, password, role } = req.body;

        // Authorization check
        // If the user is trying to update someone else's profile AND they are not an admin
        if (req.user.id !== parseInt(id) && req.user.role !== 'admin') {
            return res.status(403).json('Authorization denied: You can only update your own profile.');
        }

        // If a non-admin user tries to change the role field
        if (req.user.role !== 'admin' && role && role !== req.user.role) {
            return res.status(403).json('Forbidden: Only administrators can change user roles.');
        }

        let hashedPassword = null;
        if (password) { // If a new password is provided, hash it
            const salt = await bcrypt.genSalt(10);
            hashedPassword = await bcrypt.hash(password, salt);
        }

        let queryText = 'UPDATE users SET username = $1, email = $2, first_name = $3, last_name = $4';
        let queryParams = [username, email, first_name, last_name];
        let paramIndex = 5;

        if (hashedPassword) {
            queryText += `, password_hash = $${paramIndex}`;
            queryParams.push(hashedPassword);
            paramIndex++;
        }

        // Only allow admin to update the 'role' field
        if (req.user.role === 'admin' && role) {
            queryText += `, role = $${paramIndex}`;
            queryParams.push(role);
            paramIndex++;
        }

        queryText += ` WHERE id = $${paramIndex} RETURNING id, username, email, first_name, last_name, role`; // Return updated role
        queryParams.push(id);

        const updateUser = await pool.query(queryText, queryParams);

        if (updateUser.rows.length === 0) {
            return res.status(404).json('User not found');
        }
        res.json(updateUser.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during user update');
    }
});

// DELETE a user by ID - PROTECTED (Admin only)
app.delete('/users/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent admin from deleting themselves (optional but good practice)
        if (req.user.id === parseInt(id) && req.user.role === 'admin') {
            return res.status(403).json('Forbidden: Admins cannot delete their own account via this endpoint.');
        }

        const deleteUser = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);

        if (deleteUser.rows.length === 0) {
            return res.status(404).json('User not found');
        }
        res.json({ message: 'User deleted successfully', deletedUser: deleteUser.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during user deletion');
    }
});

// --- Bike Routes ---

// GET all bikes (Public for Browse)
app.get('/bikes', async (req, res) => {
    try {
        const allBikes = await pool.query('SELECT * FROM bikes');
        res.json(allBikes.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single bike by ID (Keeping public for Browse)
app.get('/bikes/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const bike = await pool.query('SELECT * FROM bikes WHERE id = $1', [id]);

        if (bike.rows.length === 0) {
            return res.status(404).json('Bike not found');
        }
        res.json(bike.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new bike - PROTECTED (Admin or Employee)
app.post('/bikes', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            make, model, year, frame_size, wheel_size, bike_type,
            condition, price, description, image_url, is_for_sale,
            is_second_hand, stock_quantity
        } = req.body;

        const newBike = await pool.query(
            'INSERT INTO bikes (make, model, year, frame_size, wheel_size, bike_type, condition, price, description, image_url, is_for_sale, is_second_hand, stock_quantity) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *',
            [make, model, year, frame_size, wheel_size, bike_type, condition, price, description, image_url, is_for_sale, is_second_hand, stock_quantity]
        );
        res.status(201).json(newBike.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during bike creation');
    }
});

// PUT (update) a bike by ID - PROTECTED (Admin or Employee)
app.put('/bikes/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            make, model, year, frame_size, wheel_size, bike_type,
            condition, price, description, image_url, is_for_sale,
            is_second_hand, stock_quantity
        } = req.body;

        const updateBike = await pool.query(
            'UPDATE bikes SET make = $1, model = $2, year = $3, frame_size = $4, wheel_size = $5, bike_type = $6, condition = $7, price = $8, description = $9, image_url = $10, is_for_sale = $11, is_second_hand = $12, stock_quantity = $13 WHERE id = $14 RETURNING *',
            [make, model, year, frame_size, wheel_size, bike_type, condition, price, description, image_url, is_for_sale, is_second_hand, stock_quantity, id]
        );

        if (updateBike.rows.length === 0) {
            return res.status(404).json('Bike not found');
        }
        res.json(updateBike.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during bike update');
    }
});

// DELETE a bike by ID - PROTECTED (Admin only)
app.delete('/bikes/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteBike = await pool.query('DELETE FROM bikes WHERE id = $1 RETURNING *', [id]);

        if (deleteBike.rows.length === 0) {
            return res.status(404).json('Bike not found');
        }
        res.json({ message: 'Bike deleted successfully', deletedBike: deleteBike.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during bike deletion');
    }
});

// --- Part Routes ---

// GET all parts (Keeping public for Browse)
app.get('/parts', async (req, res) => {
    try {
        const allParts = await pool.query('SELECT * FROM parts');
        res.json(allParts.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single part by ID (Keeping public for Browse)
app.get('/parts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const part = await pool.query('SELECT * FROM parts WHERE id = $1', [id]);

        if (part.rows.length === 0) {
            return res.status(404).json('Part not found');
        }
        res.json(part.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new part - PROTECTED (Admin or Employee)
app.post('/parts', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            name, description, category, price,
            stock_quantity, manufacturer, part_number, image_url
        } = req.body;

        const newPart = await pool.query(
            'INSERT INTO parts (name, description, category, price, stock_quantity, manufacturer, part_number, image_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [name, description, category, price, stock_quantity, manufacturer, part_number, image_url]
        );
        res.status(201).json(newPart.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during part creation');
    }
});

// PUT (update) a part by ID - PROTECTED (Admin or Employee)
app.put('/parts/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            name, description, category, price,
            stock_quantity, manufacturer, part_number, image_url
        } = req.body;

        const updatePart = await pool.query(
            'UPDATE parts SET name = $1, description = $2, category = $3, price = $4, stock_quantity = $5, manufacturer = $6, part_number = $7, image_url = $8 WHERE id = $9 RETURNING *',
            [name, description, category, price, stock_quantity, manufacturer, part_number, image_url, id]
        );

        if (updatePart.rows.length === 0) {
            return res.status(404).json('Part not found');
        }
        res.json(updatePart.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during part update');
    }
});

// DELETE a part by ID - PROTECTED (Admin only)
app.delete('/parts/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deletePart = await pool.query('DELETE FROM parts WHERE id = $1 RETURNING *', [id]);

        if (deletePart.rows.length === 0) {
            return res.status(404).json('Part not found');
        }
        res.json({ message: 'Part deleted successfully', deletedPart: deletePart.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during part deletion');
    }
});

// --- Repair Routes ---

// GET all repairs (Public for now)
app.get('/repairs', async (req, res) => {
    try {
        const allRepairs = await pool.query('SELECT * FROM repairs');
        res.json(allRepairs.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single repair by ID (Public for now)
app.get('/repairs/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const repair = await pool.query('SELECT * FROM repairs WHERE id = $1', [id]);

        if (repair.rows.length === 0) {
            return res.status(404).json('Repair not found');
        }
        res.json(repair.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new repair - PROTECTED (Admin or Employee)
app.post('/repairs', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            customer_name, customer_email, customer_phone, bike_make,
            bike_model, issue_description, status, estimated_cost,
            final_cost, booked_date, completion_date, notes, assigned_to_user_id
        } = req.body;

        const newRepair = await pool.query(
            'INSERT INTO repairs (customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, status, estimated_cost, final_cost, booked_date, completion_date, notes, assigned_to_user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *',
            [customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, status, estimated_cost, final_cost, booked_date, completion_date, notes, assigned_to_user_id]
        );
        res.status(201).json(newRepair.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair creation');
    }
});

// PUT (update) a repair by ID - PROTECTED (Admin or Employee)
app.put('/repairs/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            customer_name, customer_email, customer_phone, bike_make,
            bike_model, issue_description, status, estimated_cost,
            final_cost, booked_date, completion_date, notes, assigned_to_user_id
        } = req.body;

        const updateRepair = await pool.query(
            'UPDATE repairs SET customer_name = $1, customer_email = $2, customer_phone = $3, bike_make = $4, bike_model = $5, issue_description = $6, status = $7, estimated_cost = $8, final_cost = $9, booked_date = $10, completion_date = $11, notes = $12, assigned_to_user_id = $13 WHERE id = $14 RETURNING *',
            [customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, status, estimated_cost, final_cost, booked_date, completion_date, notes, assigned_to_user_id, id]
        );

        if (updateRepair.rows.length === 0) {
            return res.status(404).json('Repair not found');
        }
        res.json(updateRepair.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair update');
    }
});

// DELETE a repair by ID - PROTECTED (Admin only)
app.delete('/repairs/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteRepair = await pool.query('DELETE FROM repairs WHERE id = $1 RETURNING *', [id]);

        if (deleteRepair.rows.length === 0) {
            return res.status(404).json('Repair not found');
        }
        res.json({ message: 'Repair deleted successfully', deletedRepair: deleteRepair.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair deletion');
    }
});

// --- Quote Routes ---

// GET all quotes (Public for now)
app.get('/quotes', async (req, res) => {
    try {
        const allQuotes = await pool.query('SELECT * FROM quotes');
        res.json(allQuotes.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single quote by ID (Public for now)
app.get('/quotes/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const quote = await pool.query('SELECT * FROM quotes WHERE id = $1', [id]);

        if (quote.rows.length === 0) {
            return res.status(404).json('Quote not found');
        }
        res.json(quote.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new quote - PROTECTED (Admin or Employee)
app.post('/quotes', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            customer_name, customer_email, customer_phone, bike_make,
            bike_model, issue_description, total_estimated_cost, quote_date, status
        } = req.body;

        const newQuote = await pool.query(
            'INSERT INTO quotes (customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, total_estimated_cost, quote_date, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
            [customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, total_estimated_cost, quote_date, status]
        );
        res.status(201).json(newQuote.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote creation');
    }
});

// PUT (update) a quote by ID - PROTECTED (Admin or Employee)
app.put('/quotes/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            customer_name, customer_email, customer_phone, bike_make,
            bike_model, issue_description, total_estimated_cost, quote_date, status
        } = req.body;

        const updateQuote = await pool.query(
            'UPDATE quotes SET customer_name = $1, customer_email = $2, customer_phone = $3, bike_make = $4, bike_model = $5, issue_description = $6, total_estimated_cost = $7, quote_date = $8, status = $9 WHERE id = $10 RETURNING *',
            [customer_name, customer_email, customer_phone, bike_make, bike_model, issue_description, total_estimated_cost, quote_date, status, id]
        );

        if (updateQuote.rows.length === 0) {
            return res.status(404).json('Quote not found');
        }
        res.json(updateQuote.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote update');
    }
});

// DELETE a quote by ID - PROTECTED (Admin only)
app.delete('/quotes/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteQuote = await pool.query('DELETE FROM quotes WHERE id = $1 RETURNING *', [id]);

        if (deleteQuote.rows.length === 0) {
            return res.status(404).json('Quote not found');
        }
        res.json({ message: 'Quote deleted successfully', deletedQuote: deleteQuote.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote deletion');
    }
});

// --- Quote Item Routes ---

// GET all quote items (Public for now)
app.get('/quote_items', async (req, res) => {
    try {
        const allQuoteItems = await pool.query('SELECT * FROM quote_items');
        res.json(allQuoteItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single quote item by ID (Public for now)
app.get('/quote_items/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const quoteItem = await pool.query('SELECT * FROM quote_items WHERE id = $1', [id]);

        if (quoteItem.rows.length === 0) {
            return res.status(404).json('Quote item not found');
        }
        res.json(quoteItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET quote items for a specific quote (by quote_id) - Public for now
app.get('/quotes/:quote_id/items', async (req, res) => {
    try {
        const { quote_id } = req.params;
        const quoteItems = await pool.query('SELECT * FROM quote_items WHERE quote_id = $1', [quote_id]);
        res.json(quoteItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error fetching quote items by quote_id');
    }
});


// POST a new quote item - PROTECTED (Admin or Employee)
app.post('/quote_items', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            quote_id, item_type, item_name, quantity, unit_price, part_id
        } = req.body;

        const newQuoteItem = await pool.query(
            'INSERT INTO quote_items (quote_id, item_type, item_name, quantity, unit_price, part_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [quote_id, item_type, item_name, quantity, unit_price, part_id]
        );
        res.status(201).json(newQuoteItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote item creation');
    }
});

// PUT (update) a quote item by ID - PROTECTED (Admin or Employee)
app.put('/quote_items/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            quote_id, item_type, item_name, quantity, unit_price, part_id
        } = req.body;

        const updateQuoteItem = await pool.query(
            'UPDATE quote_items SET quote_id = $1, item_type = $2, item_name = $3, quantity = $4, unit_price = $5, part_id = $6 WHERE id = $7 RETURNING *',
            [quote_id, item_type, item_name, quantity, unit_price, part_id, id]
        );

        if (updateQuoteItem.rows.length === 0) {
            return res.status(404).json('Quote item not found');
        }
        res.json(updateQuoteItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote item update');
    }
});

// DELETE a quote item by ID - PROTECTED (Admin only)
app.delete('/quote_items/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteQuoteItem = await pool.query('DELETE FROM quote_items WHERE id = $1 RETURNING *', [id]);

        if (deleteQuoteItem.rows.length === 0) {
            return res.status(404).json('Quote item not found');
        }
        res.json({ message: 'Quote item deleted successfully', deletedQuoteItem: deleteQuoteItem.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during quote item deletion');
    }
});

// --- Repair Routes ---

// GET all repair items (Public for now)
app.get('/repair_items', async (req, res) => {
    try {
        const allRepairItems = await pool.query('SELECT * FROM repair_items');
        res.json(allRepairItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single repair item by ID (Public for now)
app.get('/repair_items/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const repairItem = await pool.query('SELECT * FROM repair_items WHERE id = $1', [id]);

        if (repairItem.rows.length === 0) {
            return res.status(404).json('Repair item not found');
        }
        res.json(repairItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET repair items for a specific repair (by repair_id) - Public for now
app.get('/repairs/:repair_id/items', async (req, res) => {
    try {
        const { repair_id } = req.params;
        const repairItems = await pool.query('SELECT * FROM repair_items WHERE repair_id = $1', [repair_id]);
        res.json(repairItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error fetching repair items by repair_id');
    }
});

// POST a new repair item - PROTECTED (Admin or Employee)
app.post('/repair_items', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            repair_id, item_type, item_name, quantity, unit_price, part_id
        } = req.body;

        const newRepairItem = await pool.query(
            'INSERT INTO repair_items (repair_id, item_type, item_name, quantity, unit_price, part_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [repair_id, item_type, item_name, quantity, unit_price, part_id]
        );
        res.status(201).json(newRepairItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair item creation');
    }
});

// PUT (update) a repair item by ID - PROTECTED (Admin or Employee)
app.put('/repair_items/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            repair_id, item_type, item_name, quantity, unit_price, part_id
        } = req.body;

        const updateRepairItem = await pool.query(
            'UPDATE repair_items SET repair_id = $1, item_type = $2, item_name = $3, quantity = $4, unit_price = $5, part_id = $6 WHERE id = $7 RETURNING *',
            [repair_id, item_type, item_name, quantity, unit_price, part_id, id]
        );

        if (updateRepairItem.rows.length === 0) {
            return res.status(404).json('Repair item not found');
        }
        res.json(updateRepairItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair item update');
    }
});

// DELETE a repair item by ID - PROTECTED (Admin only)
app.delete('/repair_items/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteRepairItem = await pool.query('DELETE FROM repair_items WHERE id = $1 RETURNING *', [id]);

        if (deleteRepairItem.rows.length === 0) {
            return res.status(404).json('Repair item not found');
        }
        res.json({ message: 'Repair item deleted successfully', deletedRepairItem: deleteRepairItem.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during repair item deletion');
    }
});

// --- Transaction Routes ---

// GET all transactions (Public for now)
app.get('/transactions', async (req, res) => {
    try {
        const allTransactions = await pool.query('SELECT * FROM transactions');
        res.json(allTransactions.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single transaction by ID (Public for now)
app.get('/transactions/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const transaction = await pool.query('SELECT * FROM transactions WHERE id = $1', [id]);

        if (transaction.rows.length === 0) {
            return res.status(404).json('Transaction not found');
        }
        res.json(transaction.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new transaction - PROTECTED (Admin or Employee)
app.post('/transactions', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            transaction_date, total_amount, payment_method, employee_id, customer_name, notes
        } = req.body;

        const newTransaction = await pool.query(
            'INSERT INTO transactions (transaction_date, total_amount, payment_method, employee_id, customer_name, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [transaction_date, total_amount, payment_method, employee_id, customer_name, notes]
        );
        res.status(201).json(newTransaction.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction creation');
    }
});

// PUT (update) a transaction by ID - PROTECTED (Admin or Employee)
app.put('/transactions/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            transaction_date, total_amount, payment_method, employee_id, customer_name, notes
        } = req.body;

        const updateTransaction = await pool.query(
            'UPDATE transactions SET transaction_date = $1, total_amount = $2, payment_method = $3, employee_id = $4, customer_name = $5, notes = $6 WHERE id = $7 RETURNING *',
            [transaction_date, total_amount, payment_method, employee_id, customer_name, notes, id]
        );

        if (updateTransaction.rows.length === 0) {
            return res.status(404).json('Transaction not found');
        }
        res.json(updateTransaction.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction update');
    }
});

// DELETE a transaction by ID - PROTECTED (Admin only)
app.delete('/transactions/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteTransaction = await pool.query('DELETE FROM transactions WHERE id = $1 RETURNING *', [id]);

        if (deleteTransaction.rows.length === 0) {
            return res.status(404).json('Transaction not found');
        }
        res.json({ message: 'Transaction deleted successfully', deletedTransaction: deleteTransaction.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction deletion');
    }
});

// --- Transaction Item Routes ---

// GET all transaction items (Public for now)
app.get('/transaction_items', async (req, res) => {
    try {
        const allTransactionItems = await pool.query('SELECT * FROM transaction_items');
        res.json(allTransactionItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single transaction item by ID (Public for now)
app.get('/transaction_items/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const transactionItem = await pool.query('SELECT * FROM transaction_items WHERE id = $1', [id]);

        if (transactionItem.rows.length === 0) {
            return res.status(404).json('Transaction item not found');
        }
        res.json(transactionItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET transaction items for a specific transaction (by transaction_id) - Public for now
app.get('/transactions/:transaction_id/items', async (req, res) => {
    try {
        const { transaction_id } = req.params;
        const transactionItems = await pool.query('SELECT * FROM transaction_items WHERE transaction_id = $1', [transaction_id]);
        res.json(transactionItems.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error fetching transaction items by transaction_id');
    }
});

// POST a new transaction item - PROTECTED (Admin or Employee)
app.post('/transaction_items', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            transaction_id, item_type, item_id, item_name, quantity, unit_price, total_price
        } = req.body;

        const newTransactionItem = await pool.query(
            'INSERT INTO transaction_items (transaction_id, item_type, item_id, item_name, quantity, unit_price, total_price) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [transaction_id, item_type, item_id, item_name, quantity, unit_price, total_price]
        );
        res.status(201).json(newTransactionItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction item creation');
    }
});

// PUT (update) a transaction item by ID - PROTECTED (Admin or Employee)
app.put('/transaction_items/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            transaction_id, item_type, item_id, item_name, quantity, unit_price, total_price
        } = req.body;

        const updateTransactionItem = await pool.query(
            'UPDATE transaction_items SET transaction_id = $1, item_type = $2, item_id = $3, item_name = $4, quantity = $5, unit_price = $6, total_price = $7 WHERE id = $8 RETURNING *',
            [transaction_id, item_type, item_id, item_name, quantity, unit_price, total_price, id]
        );

        if (updateTransactionItem.rows.length === 0) {
            return res.status(404).json('Transaction item not found');
        }
        res.json(updateTransactionItem.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction item update');
    }
});

// DELETE a transaction item by ID - PROTECTED (Admin only)
app.delete('/transaction_items/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteTransactionItem = await pool.query('DELETE FROM transaction_items WHERE id = $1 RETURNING *', [id]);

        if (deleteTransactionItem.rows.length === 0) {
            return res.status(404).json('Transaction item not found');
        }
        res.json({ message: 'Transaction item deleted successfully', deletedTransactionItem: deleteTransactionItem.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during transaction item deletion');
    }
});

// --- Custom Build Routes ---

// GET all custom builds (Public for now)
app.get('/custom_builds', async (req, res) => {
    try {
        const allCustomBuilds = await pool.query('SELECT * FROM custom_builds');
        res.json(allCustomBuilds.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single custom build by ID (Public for now)
app.get('/custom_builds/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const customBuild = await pool.query('SELECT * FROM custom_builds WHERE id = $1', [id]);

        if (customBuild.rows.length === 0) {
            return res.status(404).json('Custom build not found');
        }
        res.json(customBuild.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// POST a new custom build - PROTECTED (Admin or Employee)
app.post('/custom_builds', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            customer_name, customer_email, customer_phone,
            total_cost, status, request_date, completion_date, notes
        } = req.body;

        const newCustomBuild = await pool.query(
            'INSERT INTO custom_builds (customer_name, customer_email, customer_phone, total_cost, status, request_date, completion_date, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [customer_name, customer_email, customer_phone, total_cost, status, request_date, completion_date, notes]
        );
        res.status(201).json(newCustomBuild.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build creation');
    }
});

// PUT (update) a custom build by ID - PROTECTED (Admin or Employee)
app.put('/custom_builds/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            customer_name, customer_email, customer_phone,
            total_cost, status, request_date, completion_date, notes
        } = req.body;

        const updateCustomBuild = await pool.query(
            'UPDATE custom_builds SET customer_name = $1, customer_email = $2, customer_phone = $3, total_cost = $4, status = $5, request_date = $6, completion_date = $7, notes = $8 WHERE id = $9 RETURNING *',
            [customer_name, customer_email, customer_phone, total_cost, status, request_date, completion_date, notes, id]
        );

        if (updateCustomBuild.rows.length === 0) {
            return res.status(404).json('Custom build not found');
        }
        res.json(updateCustomBuild.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build update');
    }
});

// DELETE a custom build by ID - PROTECTED (Admin only)
app.delete('/custom_builds/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteCustomBuild = await pool.query('DELETE FROM custom_builds WHERE id = $1 RETURNING *', [id]);

        if (deleteCustomBuild.rows.length === 0) {
            return res.status(404).json('Custom build not found');
        }
        res.json({ message: 'Custom build deleted successfully', deletedCustomBuild: deleteCustomBuild.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build deletion');
    }
});

// --- Custom Build Component Routes ---

// GET all custom build components (Public for now)
app.get('/custom_build_components', async (req, res) => {
    try {
        const allCustomBuildComponents = await pool.query('SELECT * FROM custom_build_components');
        res.json(allCustomBuildComponents.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET a single custom build component by ID (Public for now)
app.get('/custom_build_components/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const customBuildComponent = await pool.query('SELECT * FROM custom_build_components WHERE id = $1', [id]);

        if (customBuildComponent.rows.length === 0) {
            return res.status(404).json('Custom build component not found');
        }
        res.json(customBuildComponent.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// GET custom build components for a specific custom build (by custom_build_id) - Public for now
app.get('/custom_builds/:custom_build_id/components', async (req, res) => {
    try {
        const { custom_build_id } = req.params;
        const customBuildComponents = await pool.query('SELECT * FROM custom_build_components WHERE custom_build_id = $1', [custom_build_id]);
        res.json(customBuildComponents.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error fetching custom build components by custom_build_id');
    }
});

// POST a new custom build component - PROTECTED (Admin or Employee)
app.post('/custom_build_components', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const {
            custom_build_id, part_id, component_name, chosen_part_name, quantity, unit_price
        } = req.body;

        const newCustomBuildComponent = await pool.query(
            'INSERT INTO custom_build_components (custom_build_id, part_id, component_name, chosen_part_name, quantity, unit_price) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [custom_build_id, part_id, component_name, chosen_part_name, quantity, unit_price]
        );
        res.status(201).json(newCustomBuildComponent.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build component creation');
    }
});

// PUT (update) a custom build component by ID - PROTECTED (Admin or Employee)
app.put('/custom_build_components/:id', auth, authorizeRole('admin', 'employee'), async (req, res) => {
    try {
        const { id } = req.params;
        const {
            custom_build_id, part_id, component_name, chosen_part_name, quantity, unit_price
        } = req.body;

        const updateCustomBuildComponent = await pool.query(
            'UPDATE custom_build_components SET custom_build_id = $1, part_id = $2, component_name = $3, chosen_part_name = $4, quantity = $5, unit_price = $6 WHERE id = $7 RETURNING *',
            [custom_build_id, part_id, component_name, chosen_part_name, quantity, unit_price, id]
        );

        if (updateCustomBuildComponent.rows.length === 0) {
            return res.status(404).json('Custom build component not found');
        }
        res.json(updateCustomBuildComponent.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build component update');
    }
});

// DELETE a custom build component by ID - PROTECTED (Admin only)
app.delete('/custom_build_components/:id', auth, authorizeRole('admin'), async (req, res) => {
    try {
        const { id } = req.params;
        const deleteCustomBuildComponent = await pool.query('DELETE FROM custom_build_components WHERE id = $1 RETURNING *', [id]);

        if (deleteCustomBuildComponent.rows.length === 0) {
            return res.status(404).json('Custom build component not found');
        }
        res.json({ message: 'Custom build component deleted successfully', deletedCustomBuildComponent: deleteCustomBuildComponent.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error during custom build component deletion');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});