import { Outlet } from 'react-router-dom';
import AdminSidebar from './AdminSidebar';

const AdminLayout = () => {
    return (
        <div className="flex h-screen bg-[#141414]">
            <AdminSidebar />
            <div className="flex-1 pl-64 overflow-auto">
                <main className="p-6">
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default AdminLayout; 