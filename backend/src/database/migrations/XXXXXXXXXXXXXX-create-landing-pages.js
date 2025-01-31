module.exports = {
    up: async(queryInterface, Sequelize) => {
        await queryInterface.createTable('landing_pages', {
            id: {
                type: Sequelize.INTEGER,
                primaryKey: true,
                autoIncrement: true,
                allowNull: false,
            },
            digital_name: {
                type: Sequelize.STRING,
                allowNull: false,
                unique: true,
            },
            objective: {
                type: Sequelize.ENUM('client', 'consultant'),
                allowNull: false,
                defaultValue: 'client',
            },
            template: {
                type: Sequelize.STRING,
                defaultValue: 'default',
            },
            content: {
                type: Sequelize.JSON,
                defaultValue: {},
            },
            published: {
                type: Sequelize.BOOLEAN,
                defaultValue: false,
            },
            user_id: {
                type: Sequelize.INTEGER,
                allowNull: false,
                references: { model: 'users', key: 'id' },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE',
            },
            created_at: {
                type: Sequelize.DATE,
                allowNull: false,
            },
            updated_at: {
                type: Sequelize.DATE,
                allowNull: false,
            },
        });
    },

    down: async(queryInterface) => {
        await queryInterface.dropTable('landing_pages');
    },
};