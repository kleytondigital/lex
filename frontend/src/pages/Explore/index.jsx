import React from 'react';
import { Container, Typography, Box } from '@mui/material';
import PremiumProducts from '../../components/PremiumProducts';

const Explore = () => {
    return (
        <Container maxWidth="lg">
            <Box py={4}>
                <Typography variant="h4" gutterBottom>
                    Explore Nossos Produtos
                </Typography>
                <Typography variant="body1" color="textSecondary" paragraph>
                    Descubra nossa seleção de produtos premium e escolha o melhor para você
                </Typography>

                <Box mt={4}>
                    <PremiumProducts variant="explore" />
                </Box>
            </Box>
        </Container>
    );
};

export default Explore; 