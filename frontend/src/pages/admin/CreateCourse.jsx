import AdminLayout from '../../components/AdminLayout';
import CourseForm from '../../components/admin/CourseForm';

const CreateCourse = () => {
    return (
        <AdminLayout>
            <div className="py-6">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
                    <h1 className="text-2xl font-semibold text-gray-300">Criar Novo Curso</h1>
                </div>
                <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8 mt-8">
                    <CourseForm />
                </div>
            </div>
        </AdminLayout>
    );
};

export default CreateCourse; 