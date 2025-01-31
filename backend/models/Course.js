const mysql = require('mysql2/promise');
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

class Course {
    static async create(courseData) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            // Inserir o curso
            const [result] = await conn.query(
                `INSERT INTO courses (
                    name, description, instructor, thumbnail, 
                    price, type, category, duration, level, 
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')`, [
                    courseData.title,
                    courseData.description,
                    courseData.instructor,
                    courseData.thumbnail,
                    courseData.price,
                    courseData.type,
                    courseData.category,
                    courseData.duration,
                    courseData.level
                ]
            );

            const courseId = result.insertId;

            // Inserir requisitos
            if (courseData.requirements && courseData.requirements.length > 0) {
                const requirementValues = courseData.requirements.map(req => [courseId, req]);
                await conn.query(
                    'INSERT INTO course_requirements (course_id, requirement) VALUES ?', [requirementValues]
                );
            }

            // Inserir objetivos
            if (courseData.learningGoals && courseData.learningGoals.length > 0) {
                const goalValues = courseData.learningGoals.map(goal => [courseId, goal]);
                await conn.query(
                    'INSERT INTO course_learning_goals (course_id, goal) VALUES ?', [goalValues]
                );
            }

            // Inserir módulos e aulas
            if (courseData.modules && courseData.modules.length > 0) {
                for (let i = 0; i < courseData.modules.length; i++) {
                    const module = courseData.modules[i];

                    // Inserir módulo
                    const [moduleResult] = await conn.query(
                        'INSERT INTO course_modules (course_id, title, position) VALUES (?, ?, ?)', [courseId, module.title, i]
                    );

                    const moduleId = moduleResult.insertId;

                    // Inserir aulas
                    if (module.lessons && module.lessons.length > 0) {
                        const lessonValues = module.lessons.map((lesson, index) => [
                            moduleId,
                            lesson.title,
                            lesson.description,
                            lesson.duration,
                            lesson.videoUrl,
                            index
                        ]);

                        await conn.query(
                            `INSERT INTO module_lessons (
                                module_id, title, description, duration, 
                                video_url, position
                            ) VALUES ?`, [lessonValues]
                        );
                    }
                }
            }

            await conn.commit();
            return courseId;

        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }

    static async findAll() {
        const [rows] = await pool.query(`
            SELECT 
                c.*, 
                COUNT(DISTINCT e.id) as enrollments,
                COUNT(DISTINCT m.id) as total_modules,
                COUNT(DISTINCT l.id) as total_lessons
            FROM courses c
            LEFT JOIN user_progress e ON e.course_id = c.id
            LEFT JOIN course_modules m ON m.course_id = c.id
            LEFT JOIN module_lessons l ON l.module_id = m.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        `);
        return rows;
    }

    static async findById(id) {
        const [courses] = await pool.query('SELECT * FROM courses WHERE id = ?', [id]);
        if (!courses.length) return null;

        const course = courses[0];

        // Buscar requisitos
        const [requirements] = await pool.query(
            'SELECT requirement FROM course_requirements WHERE course_id = ?', [id]
        );

        // Buscar objetivos
        const [goals] = await pool.query(
            'SELECT goal FROM course_learning_goals WHERE course_id = ?', [id]
        );

        // Buscar módulos e aulas
        const [modules] = await pool.query(
            'SELECT * FROM course_modules WHERE course_id = ? ORDER BY position', [id]
        );

        for (const module of modules) {
            const [lessons] = await pool.query(
                'SELECT * FROM module_lessons WHERE module_id = ? ORDER BY position', [module.id]
            );
            module.lessons = lessons;
        }

        return {
            ...course,
            requirements: requirements.map(r => r.requirement),
            learningGoals: goals.map(g => g.goal),
            modules
        };
    }

    static async update(id, courseData) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            await conn.query(
                `UPDATE courses SET 
                    name = ?, description = ?, instructor = ?,
                    thumbnail = ?, price = ?, type = ?,
                    category = ?, duration = ?, level = ?
                WHERE id = ?`, [
                    courseData.title,
                    courseData.description,
                    courseData.instructor,
                    courseData.thumbnail,
                    courseData.price,
                    courseData.type,
                    courseData.category,
                    courseData.duration,
                    courseData.level,
                    id
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

    static async delete(id) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            await conn.query('DELETE FROM module_lessons WHERE module_id IN (SELECT id FROM course_modules WHERE course_id = ?)', [id]);
            await conn.query('DELETE FROM course_modules WHERE course_id = ?', [id]);
            await conn.query('DELETE FROM course_requirements WHERE course_id = ?', [id]);
            await conn.query('DELETE FROM course_learning_goals WHERE course_id = ?', [id]);
            await conn.query('DELETE FROM courses WHERE id = ?', [id]);

            await conn.commit();
            return true;

        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }
}

module.exports = Course;