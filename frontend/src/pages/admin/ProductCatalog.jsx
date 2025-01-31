import React, { useState, useEffect } from 'react';
import { Box, Button, Container, Typography, Grid, Card, CardContent, IconButton, Dialog, DialogTitle, DialogContent, DialogActions, TextField, Select, MenuItem, FormControl, InputLabel } from '@mui/material';
import { PlusIcon, PencilIcon, TrashIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import api from '../../services/api';

const ProductCatalog = () => {
    const [products, setProducts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [openDialog, setOpenDialog] = useState(false);
    const [selectedProduct, setSelectedProduct] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        description: '',
        price: '',
        type: 'landpage',
        features: [],
        thumbnail: '',
        status: 'active'
    });

    // Carregar produtos
    const loadProducts = async () => {
        try {
            const response = await api.get('/admin/products');
            setProducts(response.data.products);
        } catch (error) {
            toast.error('Erro ao carregar produtos');
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadProducts();
    }, []);

    // Manipular mudanças no formulário
    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name === 'features') {
            setFormData(prev => ({
                ...prev,
                features: value.split('\n').filter(f => f.trim())
            }));
        } else {
            setFormData(prev => ({
                ...prev,
                [name]: value
            }));
        }
    };

    // Abrir diálogo para criar/editar
    const handleOpenDialog = (product = null) => {
        if (product) {
            setFormData({
                ...product,
                features: Array.isArray(product.features) 
                    ? product.features.join('\n')
                    : ''
            });
            setSelectedProduct(product);
        } else {
            setFormData({
                name: '',
                description: '',
                price: '',
                type: 'landpage',
                features: [],
                thumbnail: '',
                status: 'active'
            });
            setSelectedProduct(null);
        }
        setOpenDialog(true);
    };

    // Salvar produto
    const handleSave = async () => {
        try {
            const data = {
                ...formData,
                price: Number(formData.price),
                features: Array.isArray(formData.features) 
                    ? formData.features 
                    : formData.features.split('\n').filter(f => f.trim())
            };

            if (selectedProduct) {
                await api.put(`/admin/products/${selectedProduct.id}`, data);
                toast.success('Produto atualizado com sucesso');
            } else {
                await api.post('/admin/products', data);
                toast.success('Produto criado com sucesso');
            }

            setOpenDialog(false);
            loadProducts();
        } catch (error) {
            toast.error('Erro ao salvar produto');
            console.error(error);
        }
    };

    // Deletar produto
    const handleDelete = async (id) => {
        if (!window.confirm('Tem certeza que deseja deletar este produto?')) return;

        try {
            await api.delete(`/admin/products/${id}`);
            toast.success('Produto deletado com sucesso');
            loadProducts();
        } catch (error) {
            toast.error('Erro ao deletar produto');
            console.error(error);
        }
    };

    if (loading) {
        return <Box p={3}>Carregando...</Box>;
    }

    return (
        <Container maxWidth="lg">
            <Box py={4}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={4}>
                    <Typography variant="h4" className="text-white">Catálogo de Produtos</Typography>
                    <Button
                        variant="contained"
                        color="primary"
                        startIcon={<PlusIcon className="w-5 h-5" />}
                        onClick={() => handleOpenDialog()}
                    >
                        Novo Produto
                    </Button>
                </Box>

                <Grid container spacing={3}>
                    {products.map(product => (
                        <Grid item xs={12} sm={6} md={4} key={product.id}>
                            <Card>
                                <CardContent>
                                    <Box display="flex" justifyContent="space-between">
                                        <Typography variant="h6" gutterBottom>
                                            {product.name}
                                        </Typography>
                                        <Box>
                                            <IconButton 
                                                size="small" 
                                                onClick={() => handleOpenDialog(product)}
                                            >
                                                <PencilIcon className="w-5 h-5" />
                                            </IconButton>
                                            <IconButton 
                                                size="small" 
                                                onClick={() => handleDelete(product.id)}
                                            >
                                                <TrashIcon className="w-5 h-5" />
                                            </IconButton>
                                        </Box>
                                    </Box>
                                    <Typography color="textSecondary" gutterBottom>
                                        R$ {Number(product.price).toFixed(2)}
                                    </Typography>
                                    <Typography variant="body2">
                                        {product.description}
                                    </Typography>
                                    <Box mt={1}>
                                        <Typography variant="caption" color="textSecondary">
                                            Status: {product.status}
                                        </Typography>
                                    </Box>
                                </CardContent>
                            </Card>
                        </Grid>
                    ))}
                </Grid>
            </Box>

            {/* Diálogo de Criar/Editar */}
            <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
                <DialogTitle>
                    {selectedProduct ? 'Editar Produto' : 'Novo Produto'}
                </DialogTitle>
                <DialogContent>
                    <Box py={2}>
                        <Grid container spacing={2}>
                            <Grid item xs={12}>
                                <TextField
                                    fullWidth
                                    label="Nome"
                                    name="name"
                                    value={formData.name}
                                    onChange={handleChange}
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <TextField
                                    fullWidth
                                    multiline
                                    rows={3}
                                    label="Descrição"
                                    name="description"
                                    value={formData.description}
                                    onChange={handleChange}
                                />
                            </Grid>
                            <Grid item xs={12} sm={6}>
                                <TextField
                                    fullWidth
                                    label="Preço"
                                    name="price"
                                    type="number"
                                    value={formData.price}
                                    onChange={handleChange}
                                />
                            </Grid>
                            <Grid item xs={12} sm={6}>
                                <FormControl fullWidth>
                                    <InputLabel>Tipo</InputLabel>
                                    <Select
                                        name="type"
                                        value={formData.type}
                                        onChange={handleChange}
                                        label="Tipo"
                                    >
                                        <MenuItem value="landpage">Landing Page</MenuItem>
                                        <MenuItem value="training">Treinamento</MenuItem>
                                        <MenuItem value="other">Outro</MenuItem>
                                    </Select>
                                </FormControl>
                            </Grid>
                            <Grid item xs={12}>
                                <TextField
                                    fullWidth
                                    label="Thumbnail URL"
                                    name="thumbnail"
                                    value={formData.thumbnail}
                                    onChange={handleChange}
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <TextField
                                    fullWidth
                                    multiline
                                    rows={4}
                                    label="Recursos (um por linha)"
                                    name="features"
                                    value={Array.isArray(formData.features) ? formData.features.join('\n') : formData.features}
                                    onChange={handleChange}
                                    helperText="Digite um recurso por linha"
                                />
                            </Grid>
                            <Grid item xs={12}>
                                <FormControl fullWidth>
                                    <InputLabel>Status</InputLabel>
                                    <Select
                                        name="status"
                                        value={formData.status}
                                        onChange={handleChange}
                                        label="Status"
                                    >
                                        <MenuItem value="active">Ativo</MenuItem>
                                        <MenuItem value="inactive">Inativo</MenuItem>
                                    </Select>
                                </FormControl>
                            </Grid>
                        </Grid>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpenDialog(false)}>Cancelar</Button>
                    <Button onClick={handleSave} variant="contained" color="primary">
                        Salvar
                    </Button>
                </DialogActions>
            </Dialog>
        </Container>
    );
};

export default ProductCatalog; 