async updateStatus(req, res) {
    try {
        const { id } = req.params;
        const { status } = req.body;

        // Validar status
        if (!['draft', 'published'].includes(status)) {
            return res.status(400).json({ error: 'Status inválido' });
        }

        // Verificar se o treinamento existe
        const [training] = await db.execute(
            'SELECT id FROM trainings WHERE id = ? AND deleted_at IS NULL', [id]
        );

        if (!training.length) {
            return res.status(404).json({ error: 'Treinamento não encontrado' });
        }

        // Atualizar status
        await db.execute(
            'UPDATE trainings SET status = ? WHERE id = ?', [status, id]
        );

        res.json({ message: 'Status atualizado com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
}