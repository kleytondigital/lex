import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { UserIcon, LockClosedIcon } from '@heroicons/react/24/solid';
import { useAuth } from '../hooks/useAuth';
import FormInput from '../components/FormInput';
import { toast } from 'react-hot-toast';

const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
        const credentials = {
            email: formData.email,
            password: formData.password
        };
        
        const result = await login(credentials);
        
        if (result.success) {
            const user = JSON.parse(localStorage.getItem('@LEX:user'));
            if (user.role === 'admin') {
                navigate('/admin');
            } else {
                navigate('/dashboard');
            }
        } else {
            toast.error(result.error);
        }
    } catch (error) {
        console.error('Erro no login:', error);
        toast.error('Erro ao fazer login');
    } finally {
        setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <img
          className="mx-auto h-18 w-auto"
          src="/src/assets/logo.png"
          alt="LEX"
        />
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          Entre na sua conta
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Ou{' '}
          <Link to="/register" className="font-medium text-blue-600 hover:text-blue-500">
            crie sua conta gratuitamente
          </Link>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          <form className="space-y-6" onSubmit={handleSubmit}>
            <FormInput
              id="email"
              label="Email"
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              icon={UserIcon}
              required
            />

            <FormInput
              id="password"
              label="Senha"
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              icon={LockClosedIcon}
              required
            />

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
                  Lembrar-me
                </label>
              </div>

              <div className="text-sm">
                <Link to="/forgot-password" className="font-medium text-blue-600 hover:text-blue-500">
                  Esqueceu sua senha?
                </Link>
              </div>
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

            <div>
              <button
                type="submit"
                disabled={loading}
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {loading ? 'Entrando...' : 'Entrar'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
