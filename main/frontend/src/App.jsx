import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useNavigate, useParams } from 'react-router-dom';
import { 
  Wifi, Users, Activity, AlertCircle, Search, Filter, 
  LogOut, Home, Folder, Radio, User, ChevronRight,
  Signal, Smartphone, RefreshCw, Edit2, Trash2, Move
} from 'lucide-react';

const API_URL = '/api';

// ============= COMPONENTES DE UTILIDADE =============

const Card = ({ children, className = '' }) => (
  <div className={`bg-white rounded-lg shadow-md p-6 ${className}`}>
    {children}
  </div>
);

const Button = ({ children, onClick, variant = 'primary', className = '', disabled = false }) => {
  const variants = {
    primary: 'bg-blue-600 hover:bg-blue-700 text-white',
    secondary: 'bg-gray-200 hover:bg-gray-300 text-gray-800',
    danger: 'bg-red-600 hover:bg-red-700 text-white',
    success: 'bg-green-600 hover:bg-green-700 text-white'
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${className}`}
    >
      {children}
    </button>
  );
};

const Badge = ({ children, variant = 'default' }) => {
  const variants = {
    success: 'bg-green-100 text-green-800',
    danger: 'bg-red-100 text-red-800',
    warning: 'bg-yellow-100 text-yellow-800',
    default: 'bg-gray-100 text-gray-800'
  };

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${variants[variant]}`}>
      {children}
    </span>
  );
};

// ============= AUTENTICAÇÃO =============

const LoginPage = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (response.ok) {
		localStorage.setItem('token', data.token);
		localStorage.setItem('user', JSON.stringify(data.user));
		onLogin(data.token, data.user);
      } else {
        setError(data.message || 'Erro ao fazer login');
      }
    } catch (err) {
      setError('Erro de conexão com o servidor');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
            <Wifi className="w-8 h-8 text-blue-600" />
          </div>
          <h1 className="text-2xl font-bold text-gray-800">Gerenciamento de APs</h1>
          <p className="text-gray-600 mt-2">Huawei S6730</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Usuário
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Digite seu usuário"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Senha
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Digite sua senha"
              required
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center gap-2">
              <AlertCircle className="w-5 h-5" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          <Button
            variant="primary"
            className="w-full"
            disabled={loading}
          >
            {loading ? 'Entrando...' : 'Entrar'}
          </Button>
        </form>

        <div className="mt-6 text-center text-sm text-gray-600">
          <p>Sistema de Gerenciamento Facilitado - SGF</p>
          <p className="font-mono mt-1">Para APs Huawei Via AC - <v1 className="0"></v1></p>
        </div>
      </Card>
    </div>
  );
};

// ============= LAYOUT PRINCIPAL =============

const Layout = ({ children, user, onLogout }) => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <Wifi className="w-8 h-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-800">Gerenciamento de APs</h1>
                <p className="text-xs text-gray-500">Huawei S6730</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm text-gray-600">
                <User className="w-4 h-4" />
                <span className="font-medium">{user?.name}</span>
              </div>
              <Button variant="secondary" onClick={onLogout} className="flex items-center gap-2">
                <LogOut className="w-4 h-4" />
                Sair
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex gap-6">
            <NavLink to="/" icon={Home}>Dashboard</NavLink>
            <NavLink to="/groups" icon={Folder}>Grupos</NavLink>
            <NavLink to="/aps" icon={Radio}>Access Points</NavLink>
            <NavLink to="/users" icon={Users}>Usuários</NavLink>
          </div>
        </div>
      </nav>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  );
};

const NavLink = ({ to, icon: Icon, children }) => {
  const navigate = useNavigate();
  const isActive = window.location.pathname === to;

  return (
    <button
      onClick={() => navigate(to)}
      className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
        isActive
          ? 'border-blue-600 text-blue-600 font-medium'
          : 'border-transparent text-gray-600 hover:text-gray-800 hover:border-gray-300'
      }`}
    >
      <Icon className="w-4 h-4" />
      {children}
    </button>
  );
};

// ============= DASHBOARD =============

const Dashboard = ({ token }) => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboard();
  }, []);

  const fetchDashboard = async () => {
    try {
      const response = await fetch(`${API_URL}/dashboard`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Erro ao carregar dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12">Carregando...</div>;
  }

  return (
    <div className="space-y-6">
		<div className="flex justify-between items-center">
		  <h2 className="text-2xl font-bold text-gray-800">Dashboard</h2>

		  <div className="flex gap-2">
			<Button
			  onClick={fetchDashboard}
			  variant="secondary"
			  className="flex items-center gap-2"
			>
			  <RefreshCw className="w-4 h-4" />
			  Atualizar
			</Button>

			<Button
			  variant="primary"
			  onClick={async () => {
				const confirmSave = window.confirm(
				  'Deseja salvar a configuração atual no switch?'
				);
				if (!confirmSave) return;

				try {
				  const response = await fetch(`${API_URL}/switch/save`, {
					method: 'POST',
					headers: {
					  'Authorization': `Bearer ${token}`
					}
				  });

				  const data = await response.json();

				  if (data.success) {
					alert('Configuração salva com sucesso no switch.');
				  } else {
					alert(data.error || 'Erro ao salvar configuração.');
				  }
				} catch (err) {
				  alert('Erro de comunicação com o backend.');
				}
			  }}
			>
			  Salvar Configuração
			</Button>
		  </div>
		</div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard
          title="Total de APs"
          value={stats?.total_aps || 0}
          icon={Radio}
          color="blue"
        />
        <StatCard
          title="Online"
          value={stats?.online || 0}
          icon={Activity}
          color="green"
        />
        <StatCard
          title="Offline"
          value={stats?.offline || 0}
          icon={AlertCircle}
          color="red"
        />
        <StatCard
          title="Idle"
          value={stats?.idle || 0}
          icon={Activity}
          color="yellow"
        />
      </div>

      {/* Alertas */}
      {stats?.default_aps > 0 && (
        <Card className="border-l-4 border-yellow-500">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-6 h-6 text-yellow-600 flex-shrink-0 mt-1" />
            <div className="flex-1">
              <h3 className="font-semibold text-gray-800 mb-1">
                APs Pendentes de Configuração
              </h3>
              <p className="text-gray-600 text-sm mb-3">
                Existem {stats.default_aps} APs no grupo "default" aguardando configuração.
              </p>
              <Button
                variant="primary"
                onClick={() => navigate('/aps?group=default')}
                className="text-sm"
              >
                Ver APs Pendentes
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Grupos */}
      <Card>
        <h3 className="text-lg font-semibold text-gray-800 mb-4">Grupos de APs</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {stats?.groups?.map((group) => (
            <div
              key={group.name}
              onClick={() => navigate(`/aps?group=${group.name}`)}
              className="p-4 border border-gray-200 rounded-lg hover:border-blue-500 hover:shadow-md transition-all cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Folder className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-800">{group.name}</p>
                    <p className="text-sm text-gray-500">{group.count} APs</p>
                  </div>
                </div>
                <ChevronRight className="w-5 h-5 text-gray-400" />
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

const StatCard = ({ title, value, icon: Icon, color }) => {
  const colors = {
    blue: 'bg-blue-100 text-blue-600',
    green: 'bg-green-100 text-green-600',
    red: 'bg-red-100 text-red-600',
    yellow: 'bg-yellow-100 text-yellow-600'
  };

  return (
    <Card>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-800">{value}</p>
        </div>
        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${colors[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </Card>
  );
};

// ============= GRUPOS =============

const GroupsPage = ({ token }) => {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchGroups();
  }, []);

  const fetchGroups = async () => {
    try {
      const response = await fetch(`${API_URL}/groups`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setGroups(data.data || []);
    } catch (err) {
      console.error('Erro ao carregar grupos:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12">Carregando...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-800">Grupos de APs</h2>
        <Button onClick={fetchGroups} variant="secondary" className="flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Atualizar
        </Button>
      </div>

		<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
		  {groups.map((group) => (
			<button
			  key={group.name}
			  type="button"
			  className="text-left w-full"
			  onClick={() => navigate(`/aps?group=${group.name}`)}
			>
			  <Card className="hover:shadow-lg transition-shadow cursor-pointer">
				<div className="flex items-center gap-4">
				  <div className="w-16 h-16 bg-blue-100 rounded-lg flex items-center justify-center">
					<Folder className="w-8 h-8 text-blue-600" />
				  </div>
				  <div className="flex-1">
					<h3 className="font-semibold text-gray-800 text-lg">{group.name}</h3>
					<p className="text-gray-600 text-sm mt-1">
					  {group.count} Access Points
					</p>
				  </div>
				  <ChevronRight className="w-6 h-6 text-gray-400" />
				</div>
			  </Card>
			</button>
		  ))}
		</div>
    </div>
  );
};

// ============= ACCESS POINTS =============

const APsPage = ({ token }) => {
  const [aps, setAps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [groupFilter, setGroupFilter] = useState('');
  const navigate = useNavigate();
  
  
  
  
  

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const group = params.get('group');
    if (group) setGroupFilter(group);
    fetchAPs(group);
  }, []);

  const fetchAPs = async (group = null) => {
    try {
      const url = group ? `${API_URL}/aps?group=${group}` : `${API_URL}/aps`;
      const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setAps(data.data || []);
    } catch (err) {
      console.error('Erro ao carregar APs:', err);
    } finally {
      setLoading(false);
    }
  };
  


  const filteredAPs = aps.filter(ap => {
    const matchesSearch = 
      ap.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ap.mac.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || ap.state.toLowerCase() === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const getStatusBadge = (status) => {
    const variants = {
      'online': 'success',
      'offline': 'danger',
      'idle': 'warning'
    };
    return <Badge variant={variants[status.toLowerCase()]}>{status}</Badge>;
  };

  if (loading) {
    return <div className="text-center py-12">Carregando...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-800">Access Points</h2>
          {groupFilter && (
            <p className="text-sm text-gray-600 mt-1">Grupo: {groupFilter}</p>
          )}
        </div>
        <Button onClick={() => fetchAPs(groupFilter)} variant="secondary" className="flex items-center gap-2">
          <RefreshCw className="w-4 h-4" />
          Atualizar
        </Button>
      </div>

      {/* Filtros */}
      <Card>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Buscar
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="MAC, Nome ou Serial..."
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">Todos</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="idle">Idle</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Lista de APs */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Nome</th>
                <th className="text-left py-3 px-4 font-semibold text-gray-700">MAC</th>
                
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Grupo</th>
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Status</th>
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Ações</th>
              </tr>
            </thead>
            <tbody>
              {filteredAPs.map((ap) => (
                <tr key={ap.mac} className="border-b border-gray-100 hover:bg-gray-50">
				<td className="py-3 px-4 font-medium text-gray-800">{ap.name}</td>
				<td className="py-3 px-4 text-gray-600 font-mono text-sm">{ap.mac}</td>
				<td className="py-3 px-4 text-gray-600">{ap.group}</td>
				<td className="py-3 px-4">{getStatusBadge(ap.state)}</td>
				<td className="py-3 px-4">
				  <Button
					variant="secondary"
					className="text-sm"
					onClick={() => navigate(`/aps/${ap.id}`)}
				  >
					Detalhes
				  </Button>
				</td>
			   </tr>
              ))}
            </tbody>
          </table>

          {filteredAPs.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              Nenhum AP encontrado
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};

// ============= DETALHES DO AP =============

const APDetailsPage = ({ token }) => {
  const { id } = useParams();
  const [ap, setAp] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  
  // Estados para edição
  const [editingName, setEditingName] = useState(false);
  const [newName, setNewName] = useState('');
  const [movingGroup, setMovingGroup] = useState(false);
  const [newGroup, setNewGroup] = useState('');
  const [availableGroups, setAvailableGroups] = useState([]);

  useEffect(() => {
    fetchAPDetails();
  }, [id]);

  const fetchAPDetails = async () => {
    try {
      const response = await fetch(`${API_URL}/aps/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setAp(data.data);
    } catch (err) {
      console.error('Erro ao carregar detalhes do AP:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12">Carregando...</div>;
  }

  if (!ap) {
    return <div className="text-center py-12">AP não encontrado</div>;
  }

	const fetchAvailableGroups = async () => {
	  try {
		const response = await fetch(`${API_URL}/groups`, {
		  headers: { 'Authorization': `Bearer ${token}` }
		});
		const data = await response.json();
		setAvailableGroups(data.data || []);
	  } catch (err) {
		console.error('Erro ao carregar grupos:', err);
	  }
	};

	const handleRename = async () => {
	  try {
		const response = await fetch(`${API_URL}/aps/${id}/rename`, {
		  method: 'POST',
		  headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${token}`
		  },
		  body: JSON.stringify({ name: newName })
		});
		
		const data = await response.json();
		
		if (data.success) {
		  setEditingName(false);
		  setNewName('');
		  fetchAPDetails();
		} else {
		  alert(data.error || 'Erro ao renomear AP');
		}
	  } catch (err) {
		alert('Erro de comunicação com o servidor');
	  }
	};

	const handleMove = async () => {
	  try {
		const response = await fetch(`${API_URL}/aps/${id}/move`, {
		  method: 'POST',
		  headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${token}`
		  },
		  body: JSON.stringify({ group: newGroup })
		});
		
		const data = await response.json();
		
		if (data.success) {
		  setMovingGroup(false);
		  setNewGroup('');
		  fetchAPDetails();
		} else {
		  alert(data.error || 'Erro ao mover AP');
		}
	  } catch (err) {
		alert('Erro de comunicação com o servidor');
	  }
	};

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="secondary" onClick={() => navigate('/aps')}>
          ← Voltar
        </Button>
        <h2 className="text-2xl font-bold text-gray-800">{ap.name}</h2>
      </div>

		{/* Informações Básicas */}
		<Card>
		  <div className="flex justify-between items-center mb-4">
			<h3 className="text-lg font-semibold text-gray-800">Informações Básicas</h3>
			<div className="flex gap-2">
			  {!editingName && !movingGroup && (
				<>
				  <Button
					variant="primary"
					className="text-sm"
					onClick={() => {
					  setEditingName(true);
					  setNewName(ap.name);
					}}
				  >
					Editar Nome
				  </Button>
				  <Button
					variant="secondary"
					className="text-sm"
					onClick={() => {
					  setMovingGroup(true);
					  setNewGroup(ap.group);
					  fetchAvailableGroups();
					}}
				  >
					Mover Grupo
				  </Button>
				</>
			  )}
			</div>
		  </div>
		  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
			<div>
			  <p className="text-sm text-gray-600 mb-1">Nome</p>
			  {editingName ? (
				<div className="flex gap-2 items-center">
				  <input
					type="text"
					value={newName}
					onChange={(e) => setNewName(e.target.value)}
					className="border border-gray-300 rounded px-2 py-1 flex-1"
				  />
				  <Button variant="success" className="text-sm" onClick={handleRename}>Salvar</Button>
				  <Button variant="secondary" className="text-sm" onClick={() => setEditingName(false)}>Cancelar</Button>
				</div>
			  ) : (
				<p className="font-medium text-gray-800">{ap.name}</p>
			  )}
			</div>
			<InfoItem label="MAC Address" value={ap.mac} />
			<InfoItem label="Serial" value={ap.serial} />
			<InfoItem label="Modelo" value={ap.type} />
			<div>
			  <p className="text-sm text-gray-600 mb-1">Grupo</p>
			  {movingGroup ? (
				<div className="flex gap-2 items-center">
				  <select
					value={newGroup}
					onChange={(e) => setNewGroup(e.target.value)}
					className="border border-gray-300 rounded px-2 py-1 flex-1"
				  >
					{availableGroups.map((g) => (
					  <option key={g.name} value={g.name}>{g.name}</option>
					))}
				  </select>
				  <Button variant="success" className="text-sm" onClick={handleMove}>Salvar</Button>
				  <Button variant="secondary" className="text-sm" onClick={() => setMovingGroup(false)}>Cancelar</Button>
				</div>
			  ) : (
				<p className="font-medium text-gray-800">{ap.group}</p>
			  )}
			</div>
			<InfoItem label="País" value={ap.country_code} />
			<InfoItem label="Status" value={<Badge variant="success">{ap.state}</Badge>} />
		  </div>
		</Card>

      {/* Rádios */}
      {ap.radios && (
        <Card>
          <h3 className="text-lg font-semibold text-gray-800 mb-4">Configuração de Rádios</h3>
          <div className="space-y-4">
            {ap.radios.map((radio, idx) => (
              <div key={idx} className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Signal className="w-5 h-5 text-blue-600" />
                  <span className="font-medium text-gray-800">{radio.band}</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Canal:</span>
                    <span className="ml-2 font-medium">{radio.channel}</span>
                  </div>
                  <div>
                    <span className="text-gray-600">Largura:</span>
                    <span className="ml-2 font-medium">{radio.bandwidth}</span>
                  </div>
	  			  <div>
					<span className="text-gray-600">Tipo:</span>
					<span className="ml-2 font-medium">{radio.type}</span>
				  </div>
				  <div>
					<span className="text-gray-600">EIRP:</span>
					<span className="ml-2 font-medium">{radio.eirp}</span>
				  </div>
                 </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* SSIDs */}
      {ap.ssids && ap.ssids.length > 0 && (
        <Card>
          <h3 className="text-lg font-semibold text-gray-800 mb-4">SSIDs Configurados</h3>
          <div className="space-y-2">
            {ap.ssids.map((ssid, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <Wifi className="w-5 h-5 text-blue-600" />
                  <span className="font-medium text-gray-800">{ssid.name}</span>
                </div>
                <Badge variant="default">{ssid.band}</Badge>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Clientes Conectados */}
      {ap.clients && ap.clients.length > 0 && (
        <Card>
          <h3 className="text-lg font-semibold text-gray-800 mb-4">
            Clientes Conectados ({ap.clients.length})
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">MAC</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">SSID</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Banda</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">RSSI</th>
                  <th className="text-left py-3 px-4 font-semibold text-gray-700">IP</th>
                </tr>
              </thead>
              <tbody>
                {ap.clients.map((client, idx) => (
                  <tr key={idx} className="border-b border-gray-100">
                    <td className="py-3 px-4 font-mono text-sm text-gray-600">{client.mac}</td>
                    <td className="py-3 px-4 text-gray-800">{client.ssid}</td>
                    <td className="py-3 px-4 text-gray-600">{client.band}</td>
                    <td className="py-3 px-4 text-gray-600">{client.rssi} dBm</td>
                    <td className="py-3 px-4 font-mono text-sm text-gray-600">{client.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
};



const InfoItem = ({ label, value }) => (
  <div>
    <p className="text-sm text-gray-600 mb-1">{label}</p>
    <p className="font-medium text-gray-800">{value}</p>
  </div>
);

// ============= USUÁRIOS =============

const UsersPage = ({ token }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_URL}/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      setUsers(data.data || []);
    } catch (err) {
      console.error('Erro ao carregar usuários:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12">Carregando...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-800">Usuários</h2>
        <Button variant="primary">Adicionar Usuário</Button>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Usuário</th>
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Função</th>
                <th className="text-left py-3 px-4 font-semibold text-gray-700">Ações</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.username} className="border-b border-gray-100">
                  <td className="py-3 px-4 font-medium text-gray-800">{user.username}</td>
                  <td className="py-3 px-4">
                    <Badge variant={user.role === 'admin' ? 'success' : 'default'}>
                      {user.role}
                    </Badge>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex gap-2">
                      <Button variant="secondary" className="text-sm">Editar</Button>
                      <Button variant="danger" className="text-sm">Excluir</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// ============= APP PRINCIPAL =============

function App() {
	const [token, setToken] = useState(localStorage.getItem('token'));
	const [user, setUser] = useState(
	  JSON.parse(localStorage.getItem('user') || 'null')
);

	const handleLogin = (newToken, newUser) => {
	  setToken(newToken);
	  setUser(newUser);
};

	const handleLogout = () => {
	  localStorage.removeItem('token');
	  localStorage.removeItem('user');
	  setToken(null);
	  setUser(null);
	};

  if (!token) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <Router>
		<Layout user={user} onLogout={handleLogout}>
        <Routes>
          <Route path="/" element={<Dashboard token={token} />} />
          <Route path="/groups" element={<GroupsPage token={token} />} />
          <Route path="/aps" element={<APsPage token={token} />} />
          <Route path="/aps/:id" element={<APDetailsPage token={token} />} />
          <Route path="/users" element={<UsersPage token={token} />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;