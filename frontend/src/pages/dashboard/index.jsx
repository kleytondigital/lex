import React from 'react';
import { Container, Typography, Box, Grid, Paper } from '@mui/material';
import PremiumProducts from '../../components/PremiumProducts';
import useProductAccess from '../../hooks/useProductAccess';
import { RocketLaunchIcon, DocumentDuplicateIcon, LockClosedIcon } from '@heroicons/react/24/outline';

const Dashboard = () => {
    const { hasAccess: hasLandpageAccess, loading } = useProductAccess('landpage');

    if (loading) {
        return (
            <Container maxWidth="lg">
                <Box py={4}>
                    <Typography>Carregando...</Typography>
                </Box>
            </Container>
        );
    }

    return (
        <Container maxWidth="lg">
            <Box py={4}>
                {/* Seção de Boas-vindas */}
                <Box mb={6}>
                    <Typography variant="h4" gutterBottom className="text-white">
                        Bem-vindo ao seu Dashboard
                    </Typography>
                    <Typography variant="body1" color="textSecondary">
                        Gerencie seus produtos e acompanhe seu progresso
                    </Typography>
                </Box>

                {/* Status dos Produtos */}
                <Box mb={6}>
                    <Typography variant="h5" gutterBottom className="text-white">
                        Seus Produtos
                    </Typography>
                    <Grid container spacing={3}>
                        <Grid item xs={12} sm={6} md={4}>
                            <Paper className="p-4 bg-gray-800 text-white">
                                <Box display="flex" alignItems="center" mb={2}>
                                    <DocumentDuplicateIcon className="w-6 h-6 mr-2" />
                                    <Typography variant="h6">Landing Pages</Typography>
                                </Box>
                                <Box display="flex" alignItems="center" justifyContent="space-between">
                                    <Typography variant="body2" color="textSecondary">
                                        Status:
                                    </Typography>
                                    <Box display="flex" alignItems="center">
                                        {hasLandpageAccess ? (
                                            <span className="text-green-500 flex items-center">
                                                <RocketLaunchIcon className="w-4 h-4 mr-1" />
                                                Ativo
                                            </span>
                                        ) : (
                                            <span className="text-gray-400 flex items-center">
                                                <LockClosedIcon className="w-4 h-4 mr-1" />
                                                Bloqueado
                                            </span>
                                        )}
                                    </Box>
                                </Box>
                            </Paper>
                        </Grid>
                    </Grid>
                </Box>

                {/* Produtos Premium - Sempre mostra quando não tem acesso */}
                <Box mt={4}>
                    <Typography variant="h5" gutterBottom className="text-white">
                        Produtos Premium
                    </Typography>
                    <Typography variant="body1" color="textSecondary" paragraph>
                        Conheça nossos produtos premium e expanda suas possibilidades
                    </Typography>
                    <PremiumProducts variant="dashboard" />
                </Box>
            </Box>
        </Container>
    );
};

export default Dashboard; 