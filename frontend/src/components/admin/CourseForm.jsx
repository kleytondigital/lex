import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { PlusIcon, XMarkIcon, PhotoIcon, PlusCircleIcon, MinusCircleIcon, ArrowUpOnSquareIcon as ArrowUpTrayIcon } from '@heroicons/react/24/solid';
import FormInput from '../FormInput';
import api from '../../services/api';

const CourseForm = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [courseData, setCourseData] = useState({
        title: '',
        description: '',
        instructor: '',
        thumbnail: '',
        price: 0,
        type: 'free', // 'free' ou 'premium'
        category: '',
        duration: '',
        level: 'beginner', // 'beginner', 'intermediate', 'advanced'
        requirements: [''],
        learningGoals: [''],
        modules: [{
            title: '',
            lessons: [{
                title: '',
                duration: '',
                videoUrl: '',
                description: ''
            }]
        }]
    });

    const handleInputChange = (e) => {
        const { id, name, value } = e.target;
        setCourseData(prev => ({
            ...prev,
            [id]: value,
            [name]: value
        }));
    };

    const handleArrayInput = (field, index, value) => {
        setCourseData(prev => ({
            ...prev,
            [field]: prev[field].map((item, i) => i === index ? value : item)
        }));
    };

    const addArrayItem = (field) => {
        setCourseData(prev => ({
            ...prev,
            [field]: [...prev[field], '']
        }));
    };

    const removeArrayItem = (field, index) => {
        setCourseData(prev => ({
            ...prev,
            [field]: prev[field].filter((_, i) => i !== index)
        }));
    };

    const addModule = () => {
        setCourseData(prev => ({
            ...prev,
            modules: [...prev.modules, {
                title: '',
                lessons: [{
                    title: '',
                    duration: '',
                    videoUrl: '',
                    description: ''
                }]
            }]
        }));
    };

    const handleModuleChange = (moduleIndex, field, value) => {
        setCourseData(prev => ({
            ...prev,
            modules: prev.modules.map((module, i) => 
                i === moduleIndex ? { ...module, [field]: value } : module
            )
        }));
    };

    const handleLessonChange = (moduleIndex, lessonIndex, field, value) => {
        setCourseData(prev => ({
            ...prev,
            modules: prev.modules.map((module, i) => 
                i === moduleIndex ? {
                    ...module,
                    lessons: module.lessons.map((lesson, j) =>
                        j === lessonIndex ? { ...lesson, [field]: value } : lesson
                    )
                } : module
            )
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            // Formatando os dados antes de enviar
            const formattedData = {
                ...courseData,
                price: courseData.type === 'free' ? 0 : Number(courseData.price),
                modules: courseData.modules.map(module => ({
                    ...module,
                    lessons: module.lessons.map(lesson => ({
                        ...lesson,
                        duration: lesson.duration.trim()
                    }))
                }))
            };

            await api.post('/admin/courses', formattedData);
            navigate('/admin/courses');
        } catch (err) {
            setError(err.response?.data?.error || 'Erro ao criar curso');
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-8">
            <div className="bg-[#1a1a1a] shadow-lg rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-300 mb-6">Informações Básicas</h3>
                
                <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                    <FormInput
                        id="title"
                        label="Título do Curso"
                        value={courseData.title}
                        onChange={handleInputChange}
                        required
                    />

                    <FormInput
                        id="instructor"
                        label="Instrutor"
                        value={courseData.instructor}
                        onChange={handleInputChange}
                        required
                    />

                    <div className="col-span-2">
                        <label className="block text-sm font-medium text-gray-400">
                            Descrição
                        </label>
                        <textarea
                            name="description"
                            rows={4}
                            value={courseData.description}
                            onChange={handleInputChange}
                            className="mt-1 block w-full rounded-md bg-[#252525] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                            required
                        />
                    </div>

                    <FormInput
                        id="thumbnail"
                        label="URL da Thumbnail"
                        value={courseData.thumbnail}
                        onChange={handleInputChange}
                        required
                    />

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Tipo do Curso
                        </label>
                        <select
                            name="type"
                            value={courseData.type}
                            onChange={handleInputChange}
                            className="mt-1 block w-full rounded-md bg-[#252525] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                            required
                        >
                            <option value="free">Gratuito</option>
                            <option value="premium">Premium</option>
                        </select>
                    </div>

                    {courseData.type === 'premium' && (
                        <FormInput
                            id="price"
                            label="Preço"
                            type="number"
                            min="0"
                            step="0.01"
                            value={courseData.price}
                            onChange={handleInputChange}
                            required
                        />
                    )}

                    <FormInput
                        id="category"
                        label="Categoria"
                        value={courseData.category}
                        onChange={handleInputChange}
                        required
                    />

                    <div>
                        <label className="block text-sm font-medium text-gray-400">
                            Nível
                        </label>
                        <select
                            name="level"
                            value={courseData.level}
                            onChange={handleInputChange}
                            className="mt-1 block w-full rounded-md bg-[#252525] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                            required
                        >
                            <option value="beginner">Iniciante</option>
                            <option value="intermediate">Intermediário</option>
                            <option value="advanced">Avançado</option>
                        </select>
                    </div>
                </div>
            </div>

            {/* Requisitos */}
            <div className="bg-[#1a1a1a] shadow-lg rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-300 mb-6">Requisitos</h3>
                
                {courseData.requirements.map((req, index) => (
                    <div key={index} className="flex gap-2 mb-3">
                        <input
                            type="text"
                            value={req}
                            onChange={(e) => handleArrayInput('requirements', index, e.target.value)}
                            className="flex-1 rounded-md bg-[#252525] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                            placeholder="Requisito do curso"
                        />
                        <button
                            type="button"
                            onClick={() => removeArrayItem('requirements', index)}
                            className="p-2 text-gray-400 hover:text-red-500"
                        >
                            <XMarkIcon className="h-5 w-5" />
                        </button>
                    </div>
                ))}
                
                <button
                    type="button"
                    onClick={() => addArrayItem('requirements')}
                    className="mt-2 flex items-center text-sm text-orange-500 hover:text-orange-600"
                >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Adicionar Requisito
                </button>
            </div>

            {/* Objetivos de Aprendizagem */}
            <div className="bg-[#1a1a1a] shadow-lg rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-300 mb-6">Objetivos de Aprendizagem</h3>
                
                {courseData.learningGoals.map((goal, index) => (
                    <div key={index} className="flex gap-2 mb-3">
                        <input
                            type="text"
                            value={goal}
                            onChange={(e) => handleArrayInput('learningGoals', index, e.target.value)}
                            className="flex-1 rounded-md bg-[#252525] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                            placeholder="Objetivo de aprendizagem"
                        />
                        <button
                            type="button"
                            onClick={() => removeArrayItem('learningGoals', index)}
                            className="p-2 text-gray-400 hover:text-red-500"
                        >
                            <XMarkIcon className="h-5 w-5" />
                        </button>
                    </div>
                ))}
                
                <button
                    type="button"
                    onClick={() => addArrayItem('learningGoals')}
                    className="mt-2 flex items-center text-sm text-orange-500 hover:text-orange-600"
                >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Adicionar Objetivo
                </button>
            </div>

            {/* Módulos e Aulas */}
            <div className="bg-[#1a1a1a] shadow-lg rounded-lg p-6">
                <h3 className="text-lg font-medium text-gray-300 mb-6">Módulos e Aulas</h3>
                
                {courseData.modules.map((module, moduleIndex) => (
                    <div key={moduleIndex} className="mb-8 p-4 border border-gray-700 rounded-lg">
                        <FormInput
                            label={`Módulo ${moduleIndex + 1}`}
                            value={module.title}
                            onChange={(e) => handleModuleChange(moduleIndex, 'title', e.target.value)}
                            required
                        />

                        <div className="mt-4 space-y-4">
                            {module.lessons.map((lesson, lessonIndex) => (
                                <div key={lessonIndex} className="p-4 bg-[#252525] rounded-lg">
                                    <h4 className="text-sm font-medium text-gray-400 mb-4">
                                        Aula {lessonIndex + 1}
                                    </h4>
                                    
                                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                        <FormInput
                                            label="Título da Aula"
                                            value={lesson.title}
                                            onChange={(e) => handleLessonChange(moduleIndex, lessonIndex, 'title', e.target.value)}
                                            required
                                        />

                                        <FormInput
                                            label="Duração"
                                            value={lesson.duration}
                                            onChange={(e) => handleLessonChange(moduleIndex, lessonIndex, 'duration', e.target.value)}
                                            placeholder="Ex: 45:00"
                                            required
                                        />

                                        <FormInput
                                            label="URL do Vídeo"
                                            value={lesson.videoUrl}
                                            onChange={(e) => handleLessonChange(moduleIndex, lessonIndex, 'videoUrl', e.target.value)}
                                            required
                                        />

                                        <div className="col-span-2">
                                            <label className="block text-sm font-medium text-gray-400">
                                                Descrição da Aula
                                            </label>
                                            <textarea
                                                value={lesson.description}
                                                onChange={(e) => handleLessonChange(moduleIndex, lessonIndex, 'description', e.target.value)}
                                                rows={3}
                                                className="mt-1 block w-full rounded-md bg-[#303030] border-gray-700 text-gray-300 shadow-sm focus:border-orange-500 focus:ring-orange-500"
                                            />
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                ))}

                <button
                    type="button"
                    onClick={addModule}
                    className="mt-4 flex items-center text-sm text-orange-500 hover:text-orange-600"
                >
                    <PlusIcon className="h-4 w-4 mr-1" />
                    Adicionar Módulo
                </button>
            </div>

            {error && (
                <div className="rounded-md bg-red-50 p-4">
                    <div className="flex">
                        <div className="ml-3">
                            <h3 className="text-sm font-medium text-red-800">{error}</h3>
                        </div>
                    </div>
                </div>
            )}

            <div className="flex justify-end">
                <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-orange-600 hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 disabled:opacity-50"
                >
                    {loading ? 'Salvando...' : 'Salvar Curso'}
                </button>
            </div>
        </form>
    );
};

export default CourseForm;
