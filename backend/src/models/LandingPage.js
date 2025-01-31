const { Model, DataTypes } = require('sequelize');

class LandingPage extends Model {
    static init(sequelize) {
        super.init({
            digitalName: {
                type: DataTypes.STRING,
                allowNull: false,
                unique: true,
                validate: {
                    notEmpty: true
                }
            },
            objective: {
                type: DataTypes.ENUM('client', 'consultant'),
                allowNull: false,
                defaultValue: 'client'
            },
            template: {
                type: DataTypes.STRING,
                defaultValue: 'default'
            },
            content: {
                type: DataTypes.JSON,
                defaultValue: {
                    headline: '',
                    subheadline: '',
                    features: [],
                    buttonText: 'Quero saber mais'
                }
            },
            published: {
                type: DataTypes.BOOLEAN,
                defaultValue: false
            }
        }, {
            sequelize,
            tableName: 'landing_pages'
        });
    }

    static associate(models) {
        this.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
    }
}

module.exports = LandingPage;

class LandingPage extends Model {
    static init(sequelize) {
        super.init({
            digitalName: {
                type: DataTypes.STRING,
                allowNull: false,
                unique: true,
                validate: {
                    notEmpty: true
                }
            },
            objective: {
                type: DataTypes.ENUM('client', 'consultant'),
                allowNull: false,
                defaultValue: 'client'
            },
            template: {
                type: DataTypes.STRING,
                defaultValue: 'default'
            },
            content: {
                type: DataTypes.JSON,
                defaultValue: {
                    headline: '',
                    subheadline: '',
                    features: [],
                    buttonText: 'Quero saber mais'
                }
            },
            published: {
                type: DataTypes.BOOLEAN,
                defaultValue: false
            }
        }, {
            sequelize,
            tableName: 'landing_pages'
        });
    }

    static associate(models) {
        this.belongsTo(models.User, { foreignKey: 'userId', as: 'user' });
    }
}

module.exports = LandingPage;