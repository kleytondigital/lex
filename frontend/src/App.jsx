import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { Toaster } from 'react-hot-toast';
import store from './store';
import { AuthProvider } from './hooks/useAuth';
import Login from './pages/Login';
import Register from './pages/Register';
import AdminRoute from './components/AdminRoute';
import PrivateRoute from './components/PrivateRoute';
import AdminLayout from './components/AdminLayout';
import DashboardLayout from './components/DashboardLayout';
import AdminDashboard from './pages/admin/Dashboard';
import AdminUsers from './pages/admin/Users';
import AdminSettings from './pages/admin/Settings';
import LandingPage from './pages/landpage/LandingPage';
import RootRedirect from './components/RootRedirect';
import LandingPages from './pages/dashboard/landpage/LandingPages';
import NewLandingPage from './pages/dashboard/landpage/NewLandingPage';
import LandingPageConfig from './pages/dashboard/landpage/LandingPageConfig';
import Leads from './pages/dashboard/Leads';
import AdminTrainings from './pages/admin/Trainings';
import CreateTraining from './pages/admin/CreateTraining';
import TrainingConfig from './pages/admin/TrainingConfig';
import ModuleLessons from './pages/admin/ModuleLessons';
import LessonConfig from './pages/admin/LessonConfig';
import UserDashboard from './pages/dashboard/UserDashboard';
import ExplorePage from './pages/dashboard/ExplorePage';
import TrainingView from './pages/dashboard/TrainingView';
import TrainingsPage from './pages/dashboard/TrainingsPage';
import LessonView from './pages/dashboard/LessonView';
import ProductCatalog from './pages/admin/ProductCatalog';
import ProductOrder from './pages/dashboard/ProductOrder';
import Checkout from './pages/dashboard/Checkout';

const App = () => {
    // const clientPath = import.meta.env.VITE_SITE_CLIENTE_URL || 'p';
    // const consultantPath = import.meta.env.VITE_SITE_CONSULTANT_URL || 'c';

    return (
        <Provider store={store}>
            <Router>
                <AuthProvider>
                    <Toaster position="top-right" />
                    <Routes>
                        {/* Rotas públicas */}
                        <Route path="/login" element={<Login />} />
                        <Route path="/register" element={<Register />} />
                        {/* Rotas de Landing Page - Públicas */}
                        <Route path={`/p/:digitalName`} element={<LandingPage />} />
                        <Route path={`/c/:digitalName`} element={<LandingPage />} />
                        
                        {/* Rota raiz - verifica autenticação e role do usuário */}
                        <Route path="/" element={<RootRedirect />} />
                        
                        {/* Rotas de Admin */}
                        <Route path="/admin" element={<AdminRoute><AdminLayout /></AdminRoute>}>
                            <Route index element={<AdminDashboard />} />
                            <Route path="dashboard" element={<AdminDashboard />} />
                            
                            {/* Gerenciamento */}
                            <Route path="users" element={<AdminUsers />} />
                            <Route path="trainings" element={<AdminTrainings />} />
                            <Route path="trainings/create" element={<CreateTraining />} />
                            <Route path="trainings/config/:id" element={<TrainingConfig />} />
                            <Route path="trainings/:training_id/modules/:module_id/lessons" element={<ModuleLessons />} />
                            <Route path="trainings/:training_id/modules/:module_id/lessons/:lesson_id" element={<LessonConfig />} />
                            <Route path="instructors" element={<div>Gerenciamento de Instrutores</div>} />
                            <Route path="categories" element={<div>Gerenciamento de Categorias</div>} />
                            
                            {/* Produtos */}
                            <Route path="products" element={<ProductCatalog />} />
                            <Route path="sales" element={<div>Relatório de Vendas</div>} />
                            <Route path="reports" element={<div>Relatórios</div>} />
                            <Route path="coupons" element={<div>Gerenciamento de Cupons</div>} />
                            
                            {/* Landing Pages */}
                            <Route path="landpages" element={<div>Todas as Landing Pages</div>} />
                            <Route path="landpages/templates" element={<div>Templates de Landing Pages</div>} />
                            <Route path="landpages/leads" element={<div>Gerenciamento de Leads</div>} />
                            
                            {/* IA */}
                            <Route path="ai/agents" element={<div>Agentes de IA</div>} />
                            <Route path="ai/settings" element={<div>Configurações de IA</div>} />
                            
                            {/* Outros */}
                            <Route path="support" element={<div>Suporte</div>} />
                            <Route path="roles" element={<div>Gerenciamento de Permissões</div>} />
                            <Route path="settings" element={<AdminSettings />} />
                            <Route path="profile" element={<div>Perfil do Administrador</div>} />
                        </Route>

                        {/* Rotas do Dashboard do Usuário */}
                        <Route path="/dashboard" element={<PrivateRoute><DashboardLayout /></PrivateRoute>}>
                            <Route index element={<UserDashboard />} />
                            <Route path="landpage" element={<LandingPages />} />
                            <Route path="landpage/new" element={<NewLandingPage />} />
                            <Route path="landpage/:id/config" element={<LandingPageConfig />} />
                            <Route path="leads" element={<Leads />} />
                            <Route path="explore" element={<ExplorePage />} />
                            <Route path="training/:id" element={<TrainingView />} />
                            <Route path="training/:id/module/:moduleId/lesson/:lessonId" element={<LessonView />} />
                            <Route path="trainings" element={<TrainingsPage />} />
                            <Route path="products/:productId/order" element={<ProductOrder />} />
                            <Route path="checkout/:orderId" element={<Checkout />} />
                        </Route>

                        {/* Rota para caminhos não encontrados */}
                        <Route path="*" element={
                            <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white">
                                <h1 className="text-4xl font-bold mb-4">Página não encontrada</h1>
                                <p className="text-gray-400">
                                    A página que você está procurando não existe ou não está disponível.
                                </p>
                            </div>
                        } />
                    </Routes>
                </AuthProvider>
            </Router>
        </Provider>
    );
};

export default App;
