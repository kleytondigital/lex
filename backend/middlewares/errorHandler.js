const ApiError = require('../utils/ApiError');

const errorHandler = (err, req, res, next) => {
    console.error(err);

    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message,
            details: err.details
        });
    }

    // Erro de validação do MySQL
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({
            status: 'fail',
            message: 'Registro duplicado',
            details: err.sqlMessage
        });
    }

    // Erro genérico
    return res.status(500).json({
        status: 'error',
        message: 'Erro interno do servidor'
    });
};

module.exports = errorHandler;