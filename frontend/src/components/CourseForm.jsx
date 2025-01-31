import { useState, useEffect } from 'react';
import { Dialog } from '@headlessui/react';
import { ArrowUpOnSquareIcon as ArrowUpTrayIcon, XMarkIcon } from '@heroicons/react/24/solid';
import api from '../services/api';

const CourseForm = ({ isOpen, onClose, course = null }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    instructor: '',
    category: '',
    duration: '',
    price: '',
    thumbnail: null,
    previewUrl: '',
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (course) {
      setFormData({
        ...course,
        price: course.price.toString(),
        previewUrl: course.thumbnail,
      });
    }
  }, [course]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const data = new FormData();
    Object.keys(formData).forEach(key => {
      if (key !== 'previewUrl') {
        data.append(key, formData[key]);
      }
    });

    try {
      if (course) {
        await api.put(`/admin/courses/${course.id}`, data);
      } else {
        await api.post('/admin/courses', data);
      }
      onClose(true);
    } catch (error) {
      console.error('Erro ao salvar curso:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setFormData({
        ...formData,
        thumbnail: file,
        previewUrl: URL.createObjectURL(file),
      });
    }
  };

  return (
    <Dialog
      open={isOpen}
      onClose={() => !loading && onClose()}
      className="fixed inset-0 z-50 overflow-y-auto"
    >
      <div className="flex items-center justify-center min-h-screen">
        <Dialog.Overlay className="fixed inset-0 bg-black opacity-30" />

        <div className="relative bg-white rounded-lg max-w-2xl w-full mx-4">
          <div className="flex justify-between items-center px-6 py-4 border-b">
            <Dialog.Title className="text-lg font-semibold">
              {course ? 'Editar Curso' : 'Novo Curso'}
            </Dialog.Title>
            <button
              onClick={() => !loading && onClose()}
              className="text-gray-400 hover:text-gray-500"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-6">
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Thumbnail
                </label>
                <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  {formData.previewUrl ? (
                    <div className="relative">
                      <img
                        src={formData.previewUrl}
                        alt="Preview"
                        className="h-40 w-auto"
                      />
                      <button
                        type="button"
                        onClick={() => setFormData({
                          ...formData,
                          thumbnail: null,
                          previewUrl: '',
                        })}
                        className="absolute top-0 right-0 -mt-2 -mr-2 bg-red-500 text-white rounded-full p-1"
                      >
                        <XMarkIcon className="h-4 w-4" />
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-1 text-center">
                      <ArrowUpTrayIcon className="mx-auto h-12 w-12 text-gray-400" />
                      <div className="flex text-sm text-gray-600">
                        <label className="relative cursor-pointer bg-white rounded-md font-medium text-blue-600 hover:text-blue-500">
                          <span>Upload uma imagem</span>
                          <input
                            type="file"
                            accept="image/*"
                            className="sr-only"
                            onChange={handleImageChange}
                          />
                        </label>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Nome do Curso
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Descrição
                  </label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    rows={4}
                    className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Instrutor
                    </label>
                    <input
                      type="text"
                      value={formData.instructor}
                      onChange={(e) => setFormData({ ...formData, instructor: e.target.value })}
                      className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Categoria
                    </label>
                    <select
                      value={formData.category}
                      onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                      className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      required
                    >
                      <option value="">Selecione...</option>
                      <option value="programming">Programação</option>
                      <option value="design">Design</option>
                      <option value="business">Negócios</option>
                      <option value="marketing">Marketing</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Duração
                    </label>
                    <input
                      type="text"
                      value={formData.duration}
                      onChange={(e) => setFormData({ ...formData, duration: e.target.value })}
                      placeholder="Ex: 10h 30min"
                      className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Preço
                    </label>
                    <div className="mt-1 relative rounded-md shadow-sm">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <span className="text-gray-500 sm:text-sm">R$</span>
                      </div>
                      <input
                        type="number"
                        value={formData.price}
                        onChange={(e) => setFormData({ ...formData, price: e.target.value })}
                        className="block w-full pl-10 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                        required
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end space-x-3">
              <button
                type="button"
                onClick={() => !loading && onClose()}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50"
                disabled={loading}
              >
                Cancelar
              </button>
              <button
                type="submit"
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
                disabled={loading}
              >
                {loading ? 'Salvando...' : 'Salvar'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Dialog>
  );
};

export default CourseForm;
