import { useState, useEffect } from 'react';
import api from '../services/api';

export const useProductAccess = (productType) => {
    const [hasAccess, setHasAccess] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const checkAccess = async() => {
            try {
                // Buscar produtos do usuário
                const response = await api.get('/user/products/my-products');
                const products = response.data.products || [];

                // Verificar se tem acesso ao tipo de produto
                const hasProductAccess = products.some(
                    product => product.type === productType &&
                    (!product.expires_at || new Date(product.expires_at) > new Date())
                );

                setHasAccess(hasProductAccess);
            } catch (error) {
                console.error('Erro ao verificar acesso:', error);
                setHasAccess(false);
            } finally {
                setLoading(false);
            }
        };

        checkAccess();
    }, [productType]);

    return { hasAccess, loading };
};

export default useProductAccess;