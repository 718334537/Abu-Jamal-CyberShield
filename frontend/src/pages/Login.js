import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, LogIn, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';
const API = `${BACKEND_URL}/api`;

export default function Login({ onLogin }) {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({});

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.email) {
      newErrors.email = 'البريد الإلكتروني مطلوب';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'البريد الإلكتروني غير صالح';
    }
    
    if (!formData.password) {
      newErrors.password = 'كلمة المرور مطلوبة';
    } else if (formData.password.length < 6) {
      newErrors.password = 'كلمة المرور يجب أن تكون 6 أحرف على الأقل';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    
    try {
      const response = await axios.post(`${API}/auth/login`, {
        email: formData.email,
        password: formData.password
      });
      
      const { access_token, user } = response.data;
      
      // Store token and user data
      localStorage.setItem('token', access_token);
      localStorage.setItem('user', JSON.stringify(user));
      
      toast.success('تم تسجيل الدخول بنجاح!', {
        description: `مرحباً ${user.full_name}`,
        duration: 3000,
      });
      
      // Call onLogin callback
      onLogin(access_token, user);
      
      // Navigate to dashboard
      navigate('/');
      
    } catch (error) {
      console.error('Login error:', error);
      
      let errorMessage = 'فشل تسجيل الدخول';
      
      if (error.response) {
        if (error.response.status === 401) {
          errorMessage = 'البريد الإلكتروني أو كلمة المرور غير صحيحة';
        } else if (error.response.status === 403) {
          errorMessage = 'الحساب غير مفعل. يرجى التواصل مع المسؤول';
        } else if (error.response.data?.detail) {
          errorMessage = error.response.data.detail;
        }
      } else if (error.request) {
        errorMessage = 'تعذر الاتصال بالخادم. يرجى التحقق من اتصال الإنترنت';
      }
      
      toast.error(errorMessage, {
        duration: 5000,
        icon: <AlertCircle className="h-5 w-5" />
      });
      
      setErrors({
        submit: errorMessage
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = (role) => {
    const demoCredentials = {
      admin: { email: 'admin@test.com', password: 'admin123' },
      analyst: { email: 'analyst@test.com', password: 'analyst123' },
      intake: { email: 'intake@test.com', password: 'intake123' },
      reporter: { email: 'reporter@test.com', password: 'reporter123' },
      viewer: { email: 'viewer@test.com', password: 'viewer123' }
    };
    
    const credentials = demoCredentials[role];
    if (credentials) {
      setFormData(credentials);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center p-4" data-testid="login-page">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-600 to-blue-800 rounded-2xl mb-4">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2" data-testid="app-title">Abu Jamal CyberShield</h1>
          <p className="text-slate-400" data-testid="app-subtitle">نظام مكافحة الجرائم الإلكترونية</p>
        </div>

        <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700" data-testid="login-card">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-white text-center" data-testid="login-title">تسجيل الدخول</CardTitle>
            <CardDescription className="text-slate-400 text-center">
              أدخل بيانات الدخول للوصول إلى لوحة التحكم
            </CardDescription>
          </CardHeader>
          
          <form onSubmit={handleSubmit}>
            <CardContent className="space-y-4">
              {errors.submit && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3" data-testid="error-message">
                  <div className="flex items-center">
                    <AlertCircle className="h-5 w-5 text-red-500 ml-2" />
                    <p className="text-sm text-red-400">{errors.submit}</p>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="email" className="text-slate-200">البريد الإلكتروني</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="example@domain.com"
                  value={formData.email}
                  onChange={handleChange}
                  className={`bg-slate-700/50 border-slate-600 text-white ${
                    errors.email ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  required
                  disabled={loading}
                  data-testid="email-input"
                />
                {errors.email && (
                  <p className="text-sm text-red-500" data-testid="email-error">{errors.email}</p>
                )}
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="password" className="text-slate-200">كلمة المرور</Label>
                  <button
                    type="button"
                    className="text-sm text-blue-400 hover:text-blue-300"
                    onClick={() => toast.info('يجب التواصل مع المسؤول لإعادة تعيين كلمة المرور')}
                    data-testid="forgot-password-button"
                  >
                    نسيت كلمة المرور؟
                  </button>
                </div>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={handleChange}
                  className={`bg-slate-700/50 border-slate-600 text-white ${
                    errors.password ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  required
                  disabled={loading}
                  data-testid="password-input"
                />
                {errors.password && (
                  <p className="text-sm text-red-500" data-testid="password-error">{errors.password}</p>
                )}
              </div>

              {/* Demo Users Quick Access */}
              <div className="space-y-2">
                <Label className="text-slate-400 text-sm">تسجيل الدخول السريع (تجريبي)</Label>
                <div className="grid grid-cols-2 gap-2">
                  {['admin', 'analyst', 'intake', 'viewer'].map((role) => (
                    <Button
                      key={role}
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => handleDemoLogin(role)}
                      className="bg-slate-700/30 text-slate-300 border-slate-600 hover:bg-slate-600 hover:text-white"
                      disabled={loading}
                      data-testid={`demo-${role}-button`}
                    >
                      {role === 'admin' && 'مسؤول'}
                      {role === 'analyst' && 'محلل'}
                      {role === 'intake' && 'مسجل البلاغات'}
                      {role === 'viewer' && 'مشاهد'}
                    </Button>
                  ))}
                </div>
              </div>
            </CardContent>

            <CardFooter className="flex-col space-y-4">
              <Button
                type="submit"
                className="w-full btn-primary"
                disabled={loading}
                data-testid="login-button"
              >
                {loading ? (
                  <>
                    <div className="loading-spinner-small mr-2"></div>
                    جاري التحقق...
                  </>
                ) : (
                  <>
                    <LogIn className="ml-2 h-5 w-5" />
                    تسجيل الدخول
                  </>
                )}
              </Button>

              <div className="text-center">
                <p className="text-sm text-slate-400">
                  للاستفسارات والتسجيل الجديد، يرجى التواصل مع{' '}
                  <button
                    type="button"
                    className="text-blue-400 hover:text-blue-300 underline"
                    onClick={() => toast.info('البريد الإلكتروني للمسؤول: admin@abujamal-cybershield.com')}
                    data-testid="contact-admin-button"
                  >
                    المسؤول
                  </button>
                </p>
              </div>
            </CardFooter>
          </form>
        </Card>

        {/* Footer */}
        <div className="mt-8 text-center">
          <p className="text-sm text-slate-500" data-testid="copyright">
            &copy; {new Date().getFullYear()} Abu Jamal CyberShield. جميع الحقوق محفوظة.
          </p>
          <p className="text-xs text-slate-600 mt-1" data-testid="version">
            الإصدار 2.0.0 | نظام متخصص لمكافحة الجرائم الإلكترونية
          </p>
        </div>
      </div>
    </div>
  );
}