import ProductCatalog from '../pages/Admin/ProductCatalog';

const adminRoutes = [
    // ... existing routes ...
    {
        path: '/admin/products',
        element: <ProductCatalog />,
        title: 'Catálogo de Produtos',
        icon: <ShoppingCartIcon />
    },
    // ... existing code ...
]; 