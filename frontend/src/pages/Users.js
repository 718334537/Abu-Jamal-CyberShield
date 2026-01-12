import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Label } from '@/components/ui/label';
import {
  Users,
  UserPlus,
  Search,
  Filter,
  MoreVertical,
  Edit,
  Trash2,
  Shield,
  UserCheck,
  UserX,
  Mail,
  Phone,
  Calendar,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const getAuthHeaders = () => ({
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
});

// Role labels in Arabic
const roleLabels = {
  admin: 'مسؤول',
  analyst: 'محلل',
  intake: 'مسجل البلاغات',
  reporter: 'معد التقارير',
  viewer: 'مشاهد',
};

// Role colors
const roleColors = {
  admin: 'bg-red-500/20 text-red-400 border-red-500/30',
  analyst: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  intake: 'bg-green-500/20 text-green-400 border-green-500/30',
  reporter: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  viewer: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
};

export default function Users() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [users, setUsers] = useState([]);
  const [totalPages, setTotalPages] = useState(1);
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedUser, setSelectedUser] = useState(null);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);

  // Form state for edit
  const [editForm, setEditForm] = useState({
    full_name: '',
    role: '',
    department: '',
    phone: '',
    is_active: true,
  });

  useEffect(() => {
    fetchUsers();
  }, [currentPage, roleFilter, statusFilter]);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      
      let url = `${API}/users?page=${currentPage}&limit=20`;
      if (roleFilter !== 'all') url += `&role=${roleFilter}`;
      if (statusFilter !== 'all') url += `&active=${statusFilter === 'active'}`;
      
      const response = await axios.get(url, getAuthHeaders());
      
      setUsers(response.data.users || []);
      setTotalPages(response.data.pages || 1);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      toast.error('فشل تحميل بيانات المستخدمين');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    // Implement search functionality
    toast.info('ميزة البحث المتقدم قريباً');
  };

  const handleEditUser = (user) => {
    setSelectedUser(user);
    setEditForm({
      full_name: user.full_name || '',
      role: user.role || '',
      department: user.department || '',
      phone: user.phone || '',
      is_active: user.is_active ?? true,
    });
    setIsEditDialogOpen(true);
  };

  const handleUpdateUser = async () => {
    try {
      const response = await axios.patch(
        `${API}/users/${selectedUser.id}`,
        editForm,
        getAuthHeaders()
      );
      
      toast.success('تم تحديث بيانات المستخدم بنجاح');
      fetchUsers();
      setIsEditDialogOpen(false);
    } catch (error) {
      console.error('Failed to update user:', error);
      toast.error('فشل تحديث بيانات المستخدم');
    }
  };

  const handleDeleteUser = async () => {
    try {
      await axios.delete(`${API}/users/${selectedUser.id}`, getAuthHeaders());
      
      toast.success('تم حذف المستخدم بنجاح');
      fetchUsers();
      setIsDeleteDialogOpen(false);
    } catch (error) {
      console.error('Failed to delete user:', error);
      
      let errorMessage = 'فشل حذف المستخدم';
      if (error.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      }
      
      toast.error(errorMessage);
    }
  };

  const handleToggleStatus = async (user) => {
    try {
      await axios.patch(
        `${API}/users/${user.id}`,
        { is_active: !user.is_active },
        getAuthHeaders()
      );
      
      toast.success(
        user.is_active
          ? 'تم تعطيل حساب المستخدم'
          : 'تم تفعيل حساب المستخدم'
      );
      fetchUsers();
    } catch (error) {
      console.error('Failed to toggle user status:', error);
      toast.error('فشل تغيير حالة المستخدم');
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'غير متاح';
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('ar-SA', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    }).format(date);
  };

  const formatLastLogin = (dateString) => {
    if (!dateString) return 'لم يسجل دخول';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 60) {
      return `منذ ${diffMins} دقيقة`;
    } else if (diffHours < 24) {
      return `منذ ${diffHours} ساعة`;
    } else if (diffDays < 7) {
      return `منذ ${diffDays} يوم`;
    } else {
      return formatDate(dateString);
    }
  };

  if (loading && users.length === 0) {
    return (
      <div className="space-y-6" data-testid="users-loading">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-white">المستخدمون</h1>
            <p className="text-slate-400">جار تحميل بيانات المستخدمين...</p>
          </div>
        </div>
        
        <Card className="case-card">
          <CardContent className="p-6">
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map(i => (
                <div key={i} className="h-16 bg-slate-700/30 rounded-lg animate-pulse"></div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="users-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white" data-testid="users-title">
            إدارة المستخدمين
          </h1>
          <p className="text-slate-400" data-testid="users-count">
            إجمالي {users.length} مستخدم
          </p>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Button
            onClick={fetchUsers}
            variant="outline"
            className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
            data-testid="refresh-users-button"
          >
            <RefreshCw className="ml-2 h-4 w-4" />
            تحديث
          </Button>
          
          <Dialog>
            <DialogTrigger asChild>
              <Button className="btn-primary" data-testid="add-user-button">
                <UserPlus className="ml-2 h-5 w-5" />
                إضافة مستخدم
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-slate-800 border-slate-700 text-white">
              <DialogHeader>
                <DialogTitle>إضافة مستخدم جديد</DialogTitle>
                <DialogDescription className="text-slate-400">
                  سيتم إرسال بيانات الدخول إلى بريد المستخدم الإلكتروني
                </DialogDescription>
              </DialogHeader>
              
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="new-email">البريد الإلكتروني</Label>
                  <Input
                    id="new-email"
                    placeholder="user@example.com"
                    className="bg-slate-700/50 border-slate-600"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="new-name">الاسم الكامل</Label>
                  <Input
                    id="new-name"
                    placeholder="الاسم الكامل"
                    className="bg-slate-700/50 border-slate-600"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="new-role">الدور</Label>
                  <Select>
                    <SelectTrigger className="bg-slate-700/50 border-slate-600">
                      <SelectValue placeholder="اختر الدور" />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-800 border-slate-700">
                      {Object.entries(roleLabels).map(([value, label]) => (
                        <SelectItem key={value} value={value} className="text-white">
                          {label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <DialogFooter>
                <Button
                  variant="outline"
                  className="bg-slate-700 text-white border-slate-600 hover:bg-slate-600"
                >
                  إلغاء
                </Button>
                <Button
                  className="btn-primary"
                  onClick={() => toast.info('ميزة إضافة مستخدم قريباً')}
                >
                  إنشاء مستخدم
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Filters and Search */}
      <Card className="case-card" data-testid="filters-card">
        <CardContent className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="space-y-2">
              <Label htmlFor="search" className="text-slate-200">بحث</Label>
              <form onSubmit={handleSearch} className="flex gap-2">
                <Input
                  id="search"
                  placeholder="بحث بالاسم أو البريد..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="bg-slate-700/50 border-slate-600 text-white"
                  data-testid="search-input"
                />
                <Button
                  type="submit"
                  variant="outline"
                  className="bg-slate-700 text-white border-slate-600 hover:bg-slate-600"
                  data-testid="search-button"
                >
                  <Search className="h-4 w-4" />
                </Button>
              </form>
            </div>

            {/* Role Filter */}
            <div className="space-y-2">
              <Label htmlFor="role-filter" className="text-slate-200">الدور</Label>
              <Select value={roleFilter} onValueChange={setRoleFilter}>
                <SelectTrigger className="bg-slate-700/50 border-slate-600 text-white" data-testid="role-filter">
                  <SelectValue placeholder="جميع الأدوار" />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-700">
                  <SelectItem value="all" className="text-white">جميع الأدوار</SelectItem>
                  {Object.entries(roleLabels).map(([value, label]) => (
                    <SelectItem key={value} value={value} className="text-white">
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Status Filter */}
            <div className="space-y-2">
              <Label htmlFor="status-filter" className="text-slate-200">الحالة</Label>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="bg-slate-700/50 border-slate-600 text-white" data-testid="status-filter">
                  <SelectValue placeholder="جميع الحالات" />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-700">
                  <SelectItem value="all" className="text-white">جميع الحالات</SelectItem>
                  <SelectItem value="active" className="text-white">نشط</SelectItem>
                  <SelectItem value="inactive" className="text-white">غير نشط</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card className="case-card" data-testid="users-table-card">
        <CardHeader>
          <CardTitle className="text-white">قائمة المستخدمين</CardTitle>
          <CardDescription className="text-slate-400">
            يمكنك إدارة وتعديل بيانات المستخدمين من هنا
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-slate-700">
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700 hover:bg-slate-800/50">
                  <TableHead className="text-slate-300">المستخدم</TableHead>
                  <TableHead className="text-slate-300">الدور</TableHead>
                  <TableHead className="text-slate-300">القسم</TableHead>
                  <TableHead className="text-slate-300">الحالة</TableHead>
                  <TableHead className="text-slate-300">آخر دخول</TableHead>
                  <TableHead className="text-slate-300">التسجيل</TableHead>
                  <TableHead className="text-slate-300 text-left">الإجراءات</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-slate-400">
                      <Users className="h-12 w-12 mx-auto mb-3 text-slate-600" />
                      <p>لا توجد بيانات للمستخدمين</p>
                    </TableCell>
                  </TableRow>
                ) : (
                  users.map((user) => (
                    <TableRow
                      key={user.id}
                      className="border-slate-700 hover:bg-slate-800/50"
                      data-testid={`user-row-${user.id}`}
                    >
                      <TableCell>
                        <div className="flex items-center space-x-3 space-x-reverse">
                          <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-blue-800 rounded-full flex items-center justify-center">
                            <span className="text-white font-semibold">
                              {user.full_name?.charAt(0) || 'U'}
                            </span>
                          </div>
                          <div>
                            <p className="text-white font-semibold">{user.full_name}</p>
                            <div className="flex items-center text-sm text-slate-400 mt-1">
                              <Mail className="h-3 w-3 ml-1" />
                              <span data-testid="user-email">{user.email}</span>
                            </div>
                            {user.phone && (
                              <div className="flex items-center text-sm text-slate-400 mt-1">
                                <Phone className="h-3 w-3 ml-1" />
                                <span>{user.phone}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={roleColors[user.role]} data-testid="user-role">
                          {roleLabels[user.role] || user.role}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-slate-300" data-testid="user-department">
                          {user.department || 'غير محدد'}
                        </span>
                      </TableCell>
                      <TableCell>
                        {user.is_active ? (
                          <Badge className="bg-green-500/20 text-green-400 border-green-500/30" data-testid="user-status-active">
                            <UserCheck className="h-3 w-3 ml-1" />
                            نشط
                          </Badge>
                        ) : (
                          <Badge className="bg-red-500/20 text-red-400 border-red-500/30" data-testid="user-status-inactive">
                            <UserX className="h-3 w-3 ml-1" />
                            غير نشط
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center text-slate-400">
                          <Calendar className="h-3 w-3 ml-1" />
                          <span data-testid="user-last-login">
                            {formatLastLogin(user.last_login)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-slate-400" data-testid="user-created-at">
                          {formatDate(user.created_at)}
                        </div>
                      </TableCell>
                      <TableCell className="text-left">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-8 w-8 p-0">
                              <span className="sr-only">فتح القائمة</span>
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="bg-slate-800 border-slate-700">
                            <DropdownMenuLabel>الإجراءات</DropdownMenuLabel>
                            <DropdownMenuSeparator className="bg-slate-700" />
                            <DropdownMenuItem
                              onClick={() => handleEditUser(user)}
                              className="text-slate-300 hover:text-white hover:bg-slate-700 cursor-pointer"
                              data-testid="edit-user-button"
                            >
                              <Edit className="ml-2 h-4 w-4" />
                              تعديل البيانات
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => handleToggleStatus(user)}
                              className="text-slate-300 hover:text-white hover:bg-slate-700 cursor-pointer"
                              data-testid="toggle-status-button"
                            >
                              {user.is_active ? (
                                <>
                                  <UserX className="ml-2 h-4 w-4" />
                                  تعطيل الحساب
                                </>
                              ) : (
                                <>
                                  <UserCheck className="ml-2 h-4 w-4" />
                                  تفعيل الحساب
                                </>
                              )}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator className="bg-slate-700" />
                            <DropdownMenuItem
                              onClick={() => {
                                setSelectedUser(user);
                                setIsDeleteDialogOpen(true);
                              }}
                              className="text-red-400 hover:text-red-300 hover:bg-red-600/10 cursor-pointer"
                              data-testid="delete-user-button"
                            >
                              <Trash2 className="ml-2 h-4 w-4" />
                              حذف المستخدم
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-6">
              <div className="text-sm text-slate-400">
                الصفحة {currentPage} من {totalPages}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
                  data-testid="prev-page-button"
                >
                  السابق
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="bg-slate-800 border-slate-700 text-white hover:bg-slate-700"
                  data-testid="next-page-button"
                >
                  التالي
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* User Statistics */}
      <Card className="case-card" data-testid="user-stats-card">
        <CardHeader>
          <CardTitle className="text-white">إحصائيات المستخدمين</CardTitle>
          <CardDescription className="text-slate-400">
            تحليل أداء ونشاط المستخدمين
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="text-center p-6 bg-gradient-to-br from-blue-900/30 to-blue-800/20 rounded-xl border border-blue-800/30">
              <Users className="h-8 w-8 text-blue-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">
                {users.filter(u => u.role === 'admin').length}
              </p>
              <p className="text-blue-300 font-semibold">مسؤولين</p>
              <p className="text-slate-400 text-sm mt-2">صلاحيات كاملة</p>
            </div>
            
            <div className="text-center p-6 bg-gradient-to-br from-green-900/30 to-green-800/20 rounded-xl border border-green-800/30">
              <Shield className="h-8 w-8 text-green-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">
                {users.filter(u => u.role === 'analyst').length}
              </p>
              <p className="text-green-300 font-semibold">محللين</p>
              <p className="text-slate-400 text-sm mt-2">متخصصين في التحليل</p>
            </div>
            
            <div className="text-center p-6 bg-gradient-to-br from-yellow-900/30 to-yellow-800/20 rounded-xl border border-yellow-800/30">
              <UserCheck className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">
                {users.filter(u => u.is_active).length}
              </p>
              <p className="text-yellow-300 font-semibold">مستخدمين نشطين</p>
              <p className="text-slate-400 text-sm mt-2">يستخدمون النظام حالياً</p>
            </div>
            
            <div className="text-center p-6 bg-gradient-to-br from-red-900/30 to-red-800/20 rounded-xl border border-red-800/30">
              <UserX className="h-8 w-8 text-red-400 mx-auto mb-2" />
              <p className="text-2xl font-bold text-white">
                {users.filter(u => !u.is_active).length}
              </p>
              <p className="text-red-300 font-semibold">مستخدمين غير نشطين</p>
              <p className="text-slate-400 text-sm mt-2">حسابات متوقفة</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Edit User Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="bg-slate-800 border-slate-700 text-white">
          <DialogHeader>
            <DialogTitle>تعديل بيانات المستخدم</DialogTitle>
            <DialogDescription className="text-slate-400">
              تعديل معلومات {selectedUser?.full_name}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">الاسم الكامل</Label>
              <Input
                id="edit-name"
                value={editForm.full_name}
                onChange={(e) => setEditForm({ ...editForm, full_name: e.target.value })}
                className="bg-slate-700/50 border-slate-600"
                data-testid="edit-name-input"
              />
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="edit-role">الدور</Label>
                <Select
                  value={editForm.role}
                  onValueChange={(value) => setEditForm({ ...editForm, role: value })}
                >
                  <SelectTrigger className="bg-slate-700/50 border-slate-600" data-testid="edit-role-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-700">
                    {Object.entries(roleLabels).map(([value, label]) => (
                      <SelectItem key={value} value={value} className="text-white">
                        {label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="edit-status">الحالة</Label>
                <Select
                  value={editForm.is_active ? 'active' : 'inactive'}
                  onValueChange={(value) => setEditForm({ ...editForm, is_active: value === 'active' })}
                >
                  <SelectTrigger className="bg-slate-700/50 border-slate-600" data-testid="edit-status-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-700">
                    <SelectItem value="active" className="text-white">نشط</SelectItem>
                    <SelectItem value="inactive" className="text-white">غير نشط</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="edit-department">القسم</Label>
              <Input
                id="edit-department"
                value={editForm.department}
                onChange={(e) => setEditForm({ ...editForm, department: e.target.value })}
                className="bg-slate-700/50 border-slate-600"
                data-testid="edit-department-input"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="edit-phone">رقم الهاتف</Label>
              <Input
                id="edit-phone"
                value={editForm.phone}
                onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })}
                className="bg-slate-700/50 border-slate-600"
                data-testid="edit-phone-input"
              />
            </div>
          </div>
          
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsEditDialogOpen(false)}
              className="bg-slate-700 text-white border-slate-600 hover:bg-slate-600"
            >
              إلغاء
            </Button>
            <Button
              onClick={handleUpdateUser}
              className="btn-primary"
              data-testid="update-user-button"
            >
              حفظ التغييرات
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete User Dialog */}
      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent className="bg-slate-800 border-slate-700 text-white">
          <DialogHeader>
            <DialogTitle>تأكيد الحذف</DialogTitle>
            <DialogDescription className="text-slate-400">
              هل أنت متأكد من رغبتك في حذف المستخدم {selectedUser?.full_name}؟
              <br />
              <span className="text-red-400">هذا الإجراء لا يمكن التراجع عنه.</span>
            </DialogDescription>
          </DialogHeader>
          
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
            <div className="flex items-center">
              <AlertCircle className="h-5 w-5 text-red-500 ml-2" />
              <p className="text-red-400 text-sm">
                تحذير: سيتم حذف المستخدم نهائياً من النظام.
              </p>
            </div>
          </div>
          
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsDeleteDialogOpen(false)}
              className="bg-slate-700 text-white border-slate-600 hover:bg-slate-600"
            >
              إلغاء
            </Button>
            <Button
              onClick={handleDeleteUser}
              className="bg-red-600 hover:bg-red-700 text-white"
              data-testid="confirm-delete-button"
            >
              <Trash2 className="ml-2 h-4 w-4" />
              حذف المستخدم
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}