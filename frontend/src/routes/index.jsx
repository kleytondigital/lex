import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ClientTemplate from '../pages/landpage/ClientTemplate';
import ConsultantTemplate from '../pages/landpage/ConsultantTemplate';
import Dashboard from '../pages/dashboard';
import Login from '../pages/auth/Login';
import Register from '../pages/auth/Register';
import ForgotPassword from '../pages/auth/ForgotPassword';
import ResetPassword from '../pages/auth/ResetPassword';
import PrivateRoute from './PrivateRoute';
import LandingPages from '../pages/dashboard/landpage/LandingPages';
import LandingPageConfig from '../pages/dashboard/landpage/LandingPageConfig';
import InProgressPage from '../pages/dashboard/InProgressPage';
import TrainingsPage from '../pages/dashboard/TrainingsPage';
import ExplorePage from '../pages/dashboard/ExplorePage';
import TrainingView from '../pages/dashboard/TrainingView';

const AppRoutes = () => {
    // Extrair os paths das variáveis de ambiente
    const clientPath = import.meta.env.VITE_SITE_CLIENTE_URL?.split('/').pop() || 'p';
    const consultantPath = import.meta.env.VITE_SITE_CONSULTANT_URL?.split('/').pop() || 'c';

    return (
        <Routes>
            {/* Rotas Públicas */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />

            {/* Rotas de Landing Pages */}
            <Route path={`/${clientPath}/:digitalName`} element={<ClientTemplate />} />
            <Route path={`/${consultantPath}/:digitalName`} element={<ConsultantTemplate />} />

            {/* Rotas do Dashboard (Protegidas) */}
            <Route path="/dashboard" element={<PrivateRoute><Dashboard /></PrivateRoute>}>
                <Route path="landpage" element={<LandingPages />} />
                <Route path="landpage/:id/config" element={<LandingPageConfig />} />
                <Route path="explore" element={<ExplorePage />} />
                <Route path="in-progress" element={<InProgressPage />} />
                <Route path="trainings" element={<TrainingsPage />} />
                <Route path="training/:id" element={<TrainingView />} />
            </Route>

            {/* Rota padrão */}
            <Route path="/" element={<Navigate to="/login" replace />} />
        </Routes>
    );
};

export default AppRoutes; 