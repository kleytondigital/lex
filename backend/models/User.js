const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const config = require('../src/config/config');

const pool = mysql.createPool({
    host: config.database.host,
    user: config.database.user,
    password: config.database.password,
    database: config.database.database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

class User {
    static async create(userData) {
        const hashedPassword = await bcrypt.hash(userData.password, 10);

        const [result] = await pool.query(
            `INSERT INTO users (
                name, email, password, role, digital_name
            ) VALUES (?, ?, ?, ?, ?)`, [
                userData.name,
                userData.email,
                hashedPassword,
                userData.role || 'user',
                userData.digitalName
            ]
        );

        return result.insertId;
    }

    static async updateProfile(userId, profileData) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            if (profileData.password) {
                const hashedPassword = await bcrypt.hash(profileData.password, 10);
                await conn.query(
                    'UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]
                );
            }

            await conn.query(
                `UPDATE users SET
                    name = ?,
                    email = ?,
                    digital_name = ?,
                    profile_complete = true
                WHERE id = ?`, [
                    profileData.name,
                    profileData.email,
                    profileData.digitalName,
                    userId
                ]
            );

            await conn.commit();
            return true;
        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }

    static async findByEmail(email) {
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE email = ?', [email]
        );
        return rows[0];
    }

    static async findById(userId) {
        const [rows] = await pool.query(
            'SELECT id, name, email, avatar, role, created_at FROM users WHERE id = ?', [userId]
        );
        return rows[0];
    }

    static async checkDigitalNameAvailable(digitalName, excludeUserId = null) {
        let query = 'SELECT COUNT(*) as count FROM users WHERE digital_name = ?';
        const params = [digitalName];

        if (excludeUserId) {
            query += ' AND id != ?';
            params.push(excludeUserId);
        }

        const [rows] = await pool.query(query, params);
        return rows[0].count === 0;
    }

    static async validatePassword(userId, password) {
        const [rows] = await pool.query(
            'SELECT password FROM users WHERE id = ?', [userId]
        );

        if (!rows.length) return false;

        return bcrypt.compare(password, rows[0].password);
    }

    static async getCompletedCourses(userId) {
        const [rows] = await pool.query(`
            SELECT 
                c.id,
                c.name,
                c.thumbnail,
                up.completed_at as completedAt
            FROM courses c
            INNER JOIN user_progress up ON c.id = up.course_id
            WHERE up.user_id = ? AND up.completed = true
            ORDER BY up.completed_at DESC
        `, [userId]);
        return rows;
    }

    static async getStats(userId) {
        const [rows] = await pool.query(`
            SELECT 
                COUNT(DISTINCT c.id) as totalCourses,
                COUNT(DISTINCT CASE WHEN up.completed = true THEN c.id END) as completedCourses,
                COALESCE(SUM(up.time_watched), 0) as studyHours,
                COUNT(DISTINCT CASE WHEN up.completed = true THEN c.id END) as certificates
            FROM courses c
            LEFT JOIN user_progress up ON c.id = up.course_id
            WHERE up.user_id = ?
        `, [userId]);

        return rows[0] || {
            totalCourses: 0,
            completedCourses: 0,
            studyHours: 0,
            certificates: 0
        };
    }
}

module.exports = User;