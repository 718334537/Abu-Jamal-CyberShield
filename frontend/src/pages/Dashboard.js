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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import {
  BarChart3,
  FileText,
  Users,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingUp,
  Download,
  Eye,
  Filter,
  Calendar,
} from 'lucide-react';
import { toast } from 'sonner';

// Recharts for charts
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const getAuthHeaders = () => ({
  headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
});

// Color schemes
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const STATUS_COLORS = {
  new: '#3b82f6',
  under_analysis: '#8b5cf6',
  evidence_collected: '#10b981',
  report_submitted: '#f59e0b',
  closed: '#6b7280',
  escalated: '#ec4899',
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [activity, setActivity] = useState(null);
  const [timeRange, setTimeRange] = useState('week');

  useEffect(() => {
    fetchDashboardData();
  }, [timeRange]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const statsResponse = await axios.get(`${API}/dashboard/stats`, getAuthHeaders());
      setStats(statsResponse.data);
      
      const activityResponse = await axios.get(
        `${API}/dashboard/activity?limit=10`,
        getAuthHeaders()
      );
      setActivity(activityResponse.data);
    } catch (error) {
      toast.error('فشل تحميل بيانات لوحة التحكم');
      console.error('Dashboard fetch error:', error);
    } finally {
      setLoading(false);
    }
  };

  // ... (rest of the Dashboard component code will be added)
  // Due to length, I'll provide a complete but condensed version
