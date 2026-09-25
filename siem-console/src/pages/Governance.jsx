import React, { useEffect, useMemo, useRef, useState } from 'react';

const emptyUserForm = {
    email: '',
    display_name: '',
    password: '',
    role: 'SOC_ANALYST',
    manager_email: '',
    is_active: true,
};

const Governance = ({ apiBase, currentUser, notify, confirmAction }) => {
    const [activeSection, setActiveSection] = useState('overview');
    const [loading, setLoading] = useState(true);
    const [savingSettings, setSavingSettings] = useState(false);
    const [savingRole, setSavingRole] = useState('');
    const [savingRoleMeta, setSavingRoleMeta] = useState('');
    const [users, setUsers] = useState([]);
    const [creatingUser, setCreatingUser] = useState(false);
    const [resetPasswords, setResetPasswords] = useState({});
    const [userForm, setUserForm] = useState(emptyUserForm);
    const [showCreatePassword, setShowCreatePassword] = useState(false);
    const [settings, setSettings] = useState({});
    const [roles, setRoles] = useState([]);
    const [catalog, setCatalog] = useState({});
    const [auditQuery, setAuditQuery] = useState('');
    const [selectedAuditUser, setSelectedAuditUser] = useState('');
    const [userAuditEntries, setUserAuditEntries] = useState([]);
    const [userAuditLoading, setUserAuditLoading] = useState(false);
    const [message, setMessage] = useState('');
    const [roleForm, setRoleForm] = useState({ role: '', display_name: '', description: '' });
    const [showRoleModal, setShowRoleModal] = useState(false);
    const [policies, setPolicies] = useState([]);
    const [exceptions, setExceptions] = useState([]);
    const hashNavigatingRef = useRef(false);
    const activeSectionRef = useRef(activeSection);

    const canManage = String(currentUser?.role || '').toUpperCase() === 'SUPER_ADMIN';

    const governanceSections = useMemo(() => new Set([
        'overview', 'users', 'roles', 'policies', 'exceptions', 'settings', 'user_audit'
    ]), []);

    const governanceHref = (section, actorEmail = '') => {
        const sec = String(section || 'overview').trim() || 'overview';
        const actor = String(actorEmail || '').trim();
        if (sec === 'user_audit' && actor) {
            return `#/governance/user_audit?actor=${encodeURIComponent(actor)}`;
        }
        return `#/governance/${sec}`;
    };

    const getSectionFromHash = () => {
        const hash = String(window.location.hash || '');
        if (!hash.startsWith('#/governance')) return '';
        const withoutBase = hash.replace('#/governance', '').replace(/^\//, '').trim();
        const section = withoutBase.split('?')[0] || '';
        return section || 'overview';
    };

    const getAuditActorFromHash = () => {
        try {
            const hash = String(window.location.hash || '');
            const qIndex = hash.indexOf('?');
            if (qIndex < 0) return '';
            const query = hash.slice(qIndex + 1);
            const params = new URLSearchParams(query);
            return String(params.get('actor') || '').trim();
        } catch (_) {
            return '';
        }
    };

    const notifyUi = (m, sev = 'info') => {
        if (typeof notify === 'function') notify(m, sev);
    };

    const askConfirm = async (options = {}) => {
        if (typeof confirmAction === 'function') return !!(await confirmAction(options));
        return window.confirm(options?.message || 'Are you sure?');
    };

    const getAuthHeaders = (extra = {}) => {
        const token = window.localStorage.getItem('siem-auth-token') || '';
        return token ? { Authorization: `Bearer ${token}`, ...extra } : { ...extra };
    };

    const sortedPermissionKeys = useMemo(() => Object.keys(catalog).sort(), [catalog]);
    const managerOptions = useMemo(() => users.map(u => u.email).filter(Boolean), [users]);
    const roleNames = useMemo(() => roles.map(r => r.role), [roles]);
    const assignableRoles = useMemo(() => roles.filter(r => r.is_active).map(r => r.role), [roles]);

    const userAuditFiltered = useMemo(() => {
        const q = auditQuery.trim().toLowerCase();
        if (!q) return userAuditEntries;
        return userAuditEntries.filter((entry) => {
            const hay = `${entry.action || ''} ${entry.target_type || ''} ${entry.target_id || ''} ${entry.details || ''}`.toLowerCase();
            return hay.includes(q);
        });
    }, [userAuditEntries, auditQuery]);
    const roleLookup = useMemo(() => {
        const out = {};
        roles.forEach((r) => {
            out[r.role] = r;
        });
        return out;
    }, [roles]);
    const passwordPolicy = useMemo(() => {
        const minLength = Number(settings.password_min_length ?? 12) || 12;
        return {
            minLength,
            requireUpper: settings.password_require_upper !== false,
            requireLower: settings.password_require_lower !== false,
            requireDigit: settings.password_require_digit !== false,
            requireSpecial: settings.password_require_special !== false,
            blockEmailLocalpart: settings.password_prevent_email_localpart !== false,
        };
    }, [settings]);

    const load = async () => {
        setLoading(true);
        setMessage('');
        try {
            const [settingsRes, rolesRes, usersRes, policiesRes, exceptionsRes] = await Promise.all([
                fetch(`${apiBase}/admin/iam/settings`, { headers: getAuthHeaders() }),
                fetch(`${apiBase}/admin/iam/roles`, { headers: getAuthHeaders() }),
                fetch(`${apiBase}/admin/users`, { headers: getAuthHeaders() }),
                fetch(`${apiBase}/policies`, { headers: getAuthHeaders() }),
                fetch(`${apiBase}/exceptions`, { headers: getAuthHeaders() }),
            ]);
            const settingsData = await settingsRes.json().catch(() => ({}));
            const rolesData = await rolesRes.json().catch(() => ({}));
            const usersData = await usersRes.json().catch(() => ({}));
            const policiesData = await policiesRes.json().catch(() => ({}));
            const exceptionsData = await exceptionsRes.json().catch(() => ({}));

            if (!settingsRes.ok) {
                setMessage(settingsData.error || 'Failed to load IAM settings');
            } else {
                setSettings(settingsData.settings || {});
            }

            if (!rolesRes.ok) {
                setMessage((prev) => prev || rolesData.error || 'Failed to load IAM roles');
            } else {
                setRoles(Array.isArray(rolesData.roles) ? rolesData.roles : []);
                setCatalog(rolesData.catalog || {});
            }

            if (!usersRes.ok) {
                setMessage((prev) => prev || usersData.error || 'Failed to load users');
            } else {
                setUsers(Array.isArray(usersData.users) ? usersData.users : []);
            }

            if (!policiesRes.ok) {
                // silently fail for policies
            } else {
                setPolicies(Array.isArray(policiesData.policies) ? policiesData.policies : []);
            }

            if (!exceptionsRes.ok) {
                // silently fail for exceptions
            } else {
                setExceptions(Array.isArray(exceptionsData.exceptions) ? exceptionsData.exceptions : []);
            }
        } catch (_) {
            setMessage('Failed to load governance data');
        }
        setLoading(false);
    };

    const formatAuditDetails = (entry) => {
        let detailsText = String(entry.details || '');
        try {
            const parsed = JSON.parse(detailsText || '{}');
            detailsText = Object.entries(parsed || {})
                .map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
                .join(' · ');
        } catch (_) {
            // keep raw details text
        }
        return detailsText || '—';
    };

    const formatAuditTimestamp = (rawTs) => {
        const raw = String(rawTs || '').trim();
        if (!raw) return '—';
        try {
            // SQLite default datetime('now') => UTC "YYYY-MM-DD HH:MM:SS"
            if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(raw)) {
                const asUtc = new Date(raw.replace(' ', 'T') + 'Z');
                if (!Number.isNaN(asUtc.getTime())) return asUtc.toLocaleString();
            }
            const parsed = new Date(raw);
            if (!Number.isNaN(parsed.getTime())) return parsed.toLocaleString();
        } catch (_) {}
        return raw;
    };

    const getReadableActionDescription = (entry) => {
        const action = String(entry.action || '').toLowerCase();
        const actor = String(entry.actor || 'Unknown');
        const target_id = String(entry.target_id || '—');
        let parsed = {};
        let details = '';
        let closingComment = '';
        try {
            parsed = JSON.parse(String(entry.details || '{}'));
            if (parsed.summary) {
                const baseText = parsed.summary;
                if (parsed.final_statement) {
                    closingComment = ` - "${parsed.final_statement}"`;
                } else if (parsed.initial_statement) {
                    closingComment = ` - "${parsed.initial_statement}"`;
                }
                return baseText + closingComment;
            }
            if (parsed.incident_count) {
                details = ` ${parsed.incident_count} incident(s)`;
            }
            if (parsed.classification) {
                details += ` [${parsed.classification}]`;
            }
            if (parsed.assignee) {
                details += ` to ${parsed.assignee}`;
            }
            if (parsed.final_statement) {
                closingComment = ` - "${parsed.final_statement}"`;
            }
        } catch (_) {}

        const parsedPath = String(parsed?.path || '').toLowerCase();
        const payload = (parsed && typeof parsed.payload === 'object' && parsed.payload) ? parsed.payload : {};
        const changedKeys = Array.isArray(parsed?.changed_fields)
            ? parsed.changed_fields
            : (typeof parsed?.changed_fields === 'string'
                ? parsed.changed_fields.split(',').map((x) => x.trim()).filter(Boolean)
                : Object.keys(payload || {}));
        const changeSummary = String(parsed?.change_summary || '').trim();

        if (action === 'policy_updated') {
            if (changeSummary) return `${actor} updated policy "${parsed?.policy_name || target_id}" (${changeSummary})`;
            if (changedKeys.length > 0) return `${actor} updated policy "${parsed?.policy_name || target_id}" (changed: ${changedKeys.join(', ')})`;
        }
        if (action === 'exception_updated') {
            if (changeSummary) return `${actor} updated exception "${parsed?.exception_name || target_id}" (${changeSummary})`;
            if (changedKeys.length > 0) return `${actor} updated exception "${parsed?.exception_name || target_id}" (changed: ${changedKeys.join(', ')})`;
        }
        if (action === 'app_user_updated') {
            if (changeSummary) return `${actor} updated user ${target_id} (${changeSummary})`;
            if (changedKeys.length > 0) return `${actor} updated user ${target_id} (changed: ${changedKeys.join(', ')})`;
        }
        if (action === 'custom_role_updated') {
            if (changeSummary) return `${actor} updated custom role ${target_id} (${changeSummary})`;
            if (changedKeys.length > 0) return `${actor} updated custom role ${target_id} (changed: ${changedKeys.join(', ')})`;
        }

        if (action === 'policy_updated' && Object.prototype.hasOwnProperty.call(payload, 'is_active')) {
            return `${actor} ${payload.is_active ? 'activated' : 'deactivated'} policy "${parsed?.policy_name || target_id}"`;
        }
        if (action === 'exception_updated' && Object.prototype.hasOwnProperty.call(payload, 'is_active')) {
            return `${actor} ${payload.is_active ? 'activated' : 'deactivated'} exception "${parsed?.exception_name || target_id}"`;
        }
        if (action === 'exception_updated' && Object.prototype.hasOwnProperty.call(payload, 'mode')) {
            return `${actor} changed exception "${parsed?.exception_name || target_id}" mode to ${String(payload.mode || '').toUpperCase()}`;
        }
        if (action === 'app_user_updated' && Object.prototype.hasOwnProperty.call(payload, 'is_active')) {
            return `${actor} ${payload.is_active ? 'activated' : 'deactivated'} user ${target_id}`;
        }
        if (action === 'app_user_updated' && Object.prototype.hasOwnProperty.call(payload, 'role')) {
            return `${actor} changed user ${target_id} role to ${String(payload.role || '').toUpperCase()}`;
        }
        if (action === 'custom_role_updated' && Object.prototype.hasOwnProperty.call(payload, 'is_active')) {
            return `${actor} ${payload.is_active ? 'activated' : 'deactivated'} custom role ${target_id}`;
        }
        if (action === 'iam_settings_updated' && changedKeys.length > 0) {
            return `${actor} updated IAM settings (${changedKeys.join(', ')})`;
        }

        if (action === 'app_user_created' && parsedPath.includes('/api/admin/users/') && parsedPath.includes('/reset-password')) {
            const parts = parsedPath.split('/').filter(Boolean);
            const uid = parts.length >= 4 ? parts[3] : target_id;
            return `${actor} reset password for user ${String(uid || '').toUpperCase()}`;
        }
        if (action === 'app_user_created' && parsedPath.includes('/api/admin/users/') && parsedPath.includes('/revoke-sessions')) {
            const parts = parsedPath.split('/').filter(Boolean);
            const uid = parts.length >= 4 ? parts[3] : target_id;
            return `${actor} revoked sessions for user ${String(uid || '').toUpperCase()}`;
        }

        const actionMap = {
            'password_changed': `${actor} changed their password`,
            'profile_updated': `${actor} updated their profile`,
            'policy_created': `${actor} created policy "${parsed?.policy_name || target_id}"`,
            'policy_updated': `${actor} updated policy "${parsed?.policy_name || target_id}"`,
            'policy_activated': `${actor} activated policy "${parsed?.policy_name || target_id}"`,
            'policy_deactivated': `${actor} deactivated policy "${parsed?.policy_name || target_id}"`,
            'policy_deleted': `${actor} deleted policy "${parsed?.policy_name || target_id}"`,
            'exception_created': `${actor} created exception "${parsed?.exception_name || target_id}"`,
            'exception_updated': `${actor} updated exception "${parsed?.exception_name || target_id}"`,
            'exception_activated': `${actor} activated exception "${parsed?.exception_name || target_id}"`,
            'exception_deactivated': `${actor} deactivated exception "${parsed?.exception_name || target_id}"`,
            'exception_deleted': `${actor} deleted exception "${parsed?.exception_name || target_id}"`,
            'incident_closed': `${actor} closed incident ${target_id}${closingComment}`,
            'incident_reopened': `${actor} reopened incident ${target_id}`,
            'incident_escalated': `${actor} escalated incident ${target_id}`,
            'incident_ticket_raised': `${actor} raised ticket for incident ${target_id}`,
            'incident_updated': `${actor} updated incident ${target_id}`,
            'incident_bulk_closed': `${actor} closed${details}${closingComment}`,
            'incident_bulk_assigned': `${actor} assigned${details}`,
            'incident_bulk_escalated': `${actor} escalated${details}`,
            'incident_bulk_reopened': `${actor} reopened${details}`,
            'incident_bulk_ticket_raised': `${actor} raised ticket for${details}`,
            'app_user_created': `${actor} created user ${target_id}`,
            'app_user_updated': `${actor} updated user ${target_id}`,
            'app_user_activated': `${actor} activated user ${target_id}`,
            'app_user_deactivated': `${actor} deactivated user ${target_id}`,
            'app_user_role_changed': `${actor} changed user ${target_id} role to ${String(payload?.role || '').toUpperCase() || '—'}`,
            'app_user_password_reset': `${actor} reset password for user ${target_id}`,
            'auth_session_revoked': `${actor} revoked sessions for user ${target_id}`,
            'iam_settings_updated': `${actor} updated IAM settings`,
            'iam_role_permissions_updated': `${actor} updated permissions for role ${target_id}`,
            'custom_role_created': `${actor} created custom role ${target_id}`,
            'custom_role_updated': `${actor} updated custom role ${target_id}`,
            'custom_role_activated': `${actor} activated custom role ${target_id}`,
            'custom_role_deactivated': `${actor} deactivated custom role ${target_id}`,
            'custom_role_deleted': `${actor} deleted custom role ${target_id}`,
        };
        if (actionMap[action]) return actionMap[action];
        if (changedKeys.length > 0) {
            return `${actor} ${action} ${target_id} (${changedKeys.join(', ')})`;
        }
        return `${actor} ${action} ${target_id}`;
    };

    const fetchUserAudit = async (actorEmail, { clear = false } = {}) => {
        const actor = String(actorEmail || '').trim();
        if (!actor) return;
        setUserAuditLoading(true);
        if (clear) setUserAuditEntries([]);
        try {
            const res = await fetch(`${apiBase}/audit?limit=300&action_only=true&actor=${encodeURIComponent(actor)}`, { headers: getAuthHeaders() });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to load user audit logs');
            } else {
                setUserAuditEntries(Array.isArray(data.entries) ? data.entries : []);
            }
        } catch (_) {
            setMessage('Failed to load user audit logs');
        }
        setUserAuditLoading(false);
    };

    const openUserAudit = async (actorEmail) => {
        const actor = String(actorEmail || '').trim();
        if (!actor) return;
        setSelectedAuditUser(actor);
        setAuditQuery('');
        setActiveSection('user_audit');
        const nextHash = governanceHref('user_audit', actor);
        if ((window.location.hash || '') !== nextHash) {
            window.history.pushState(null, '', `${window.location.pathname}${nextHash}`);
        }
        await fetchUserAudit(actor, { clear: true });
    };

    const closeUserAudit = () => {
        setSelectedAuditUser('');
        setUserAuditEntries([]);
        setAuditQuery('');
        setActiveSection('overview');
    };

    useEffect(() => {
        if (!selectedAuditUser || activeSection !== 'user_audit') return;
        if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
        const timer = setInterval(() => {
            if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
            fetchUserAudit(selectedAuditUser);
        }, 15000);
        return () => clearInterval(timer);
    }, [selectedAuditUser, activeSection]);

    useEffect(() => {
        activeSectionRef.current = activeSection;
    }, [activeSection]);

    useEffect(() => {
        const applyFromHash = () => {
            const fromHash = getSectionFromHash();
            if (!fromHash || !governanceSections.has(fromHash) || fromHash === activeSectionRef.current) return;
            hashNavigatingRef.current = true;
            setActiveSection(fromHash);
            if (fromHash === 'user_audit') {
                const actorFromHash = getAuditActorFromHash();
                if (actorFromHash) {
                    setSelectedAuditUser(actorFromHash);
                    setAuditQuery('');
                    fetchUserAudit(actorFromHash, { clear: true });
                }
            }
        };
        applyFromHash();

        const onHashChange = () => {
            applyFromHash();
        };
        window.addEventListener('hashchange', onHashChange);
        return () => window.removeEventListener('hashchange', onHashChange);
    }, [governanceSections]);

    useEffect(() => {
        const next = activeSection === 'user_audit' && selectedAuditUser
            ? governanceHref('user_audit', selectedAuditUser)
            : governanceHref(activeSection);
        const current = String(window.location.hash || '');
        if (current === next) return;
        if (hashNavigatingRef.current) {
            hashNavigatingRef.current = false;
            return;
        }
        window.history.pushState(null, '', `${window.location.pathname}${next}`);
    }, [activeSection, selectedAuditUser]);

    useEffect(() => {
        if (canManage) load();
    }, [apiBase, canManage]);

    const updateSetting = (key, value) => {
        setSettings((prev) => ({ ...prev, [key]: value }));
    };

    const validateNewUserPassword = (password, email) => {
        const pwd = String(password || '');
        const em = String(email || '').trim().toLowerCase();
        if (pwd.length < passwordPolicy.minLength) {
            return `Password must be at least ${passwordPolicy.minLength} characters`;
        }
        if (passwordPolicy.requireUpper && !/[A-Z]/.test(pwd)) return 'Password must include an uppercase letter';
        if (passwordPolicy.requireLower && !/[a-z]/.test(pwd)) return 'Password must include a lowercase letter';
        if (passwordPolicy.requireDigit && !/\d/.test(pwd)) return 'Password must include a number';
        if (passwordPolicy.requireSpecial && !/[^A-Za-z0-9]/.test(pwd)) return 'Password must include a special character';
        if (passwordPolicy.blockEmailLocalpart && em.includes('@')) {
            const local = em.split('@')[0];
            if (local && pwd.toLowerCase().includes(local)) {
                return 'Password must not contain the email username';
            }
        }
        return '';
    };

    const createUser = async (e) => {
        e.preventDefault();
        setCreatingUser(true);
        setMessage('');
        const passwordError = validateNewUserPassword(userForm.password, userForm.email);
        if (passwordError) {
            setMessage(passwordError);
            setCreatingUser(false);
            return;
        }
        try {
            const res = await fetch(`${apiBase}/admin/users`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(userForm),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to create user');
            } else {
                setUserForm(emptyUserForm);
                notifyUi('User created', 'success');
                setMessage('User created');
                load();
            }
        } catch (_) {
            setMessage('Failed to create user');
        }
        setCreatingUser(false);
    };

    const toggleUserActive = async (user) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ is_active: !user.is_active }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to update user status');
                return;
            }
            notifyUi(`User ${user.is_active ? 'deactivated' : 'activated'}`, 'success');
            load();
        } catch (_) {
            setMessage('Failed to update user status');
        }
    };

    const updateUserRole = async (user, role) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ role }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to update role');
                return;
            }
            notifyUi('Role updated', 'success');
            load();
        } catch (_) {
            setMessage('Failed to update role');
        }
    };

    const resetUserPassword = async (user) => {
        const next = String(resetPasswords[user.user_id] || '');
        const passwordError = validateNewUserPassword(next, user.email || '');
        if (passwordError) {
            setMessage(passwordError);
            return;
        }
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}/reset-password`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ new_password: next }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to reset password');
                return;
            }
            setResetPasswords((prev) => ({ ...prev, [user.user_id]: '' }));
            notifyUi('Password reset', 'success');
            setMessage(`Password reset for ${user.display_name}`);
        } catch (_) {
            setMessage('Failed to reset password');
        }
    };

    const revokeUserSessions = async (user) => {
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/users/${user.user_id}/revoke-sessions`, {
                method: 'POST',
                headers: getAuthHeaders(),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to revoke sessions');
                return;
            }
            notifyUi('Sessions revoked', 'success');
            setMessage(`Revoked ${data.count || 0} sessions for ${user.display_name}`);
        } catch (_) {
            setMessage('Failed to revoke sessions');
        }
    };

    const saveSettings = async (e) => {
        e.preventDefault();
        setSavingSettings(true);
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/iam/settings`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(settings),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to save IAM settings');
            } else {
                setSettings(data.settings || settings);
                notifyUi('IAM settings updated', 'success');
                setMessage('IAM settings updated');
            }
        } catch (_) {
            setMessage('Failed to save IAM settings');
        }
        setSavingSettings(false);
    };

    const toggleRolePermission = (roleName, permissionKey) => {
        setRoles((prev) => prev.map((roleRow) => {
            if (roleRow.role !== roleName) return roleRow;
            const nextOverrides = { ...(roleRow.overrides || {}) };
            nextOverrides[permissionKey] = !(permissionKey in nextOverrides
                ? !!nextOverrides[permissionKey]
                : !!(roleRow.effective_permissions || []).includes(permissionKey));
            const nextEffective = new Set(roleRow.effective_permissions || []);
            if (nextOverrides[permissionKey]) nextEffective.add(permissionKey);
            else nextEffective.delete(permissionKey);
            return {
                ...roleRow,
                overrides: nextOverrides,
                effective_permissions: Array.from(nextEffective),
            };
        }));
    };

    const saveRolePermissions = async (roleRow) => {
        setSavingRole(roleRow.role);
        setMessage('');
        try {
            const res = await fetch(`${apiBase}/admin/iam/roles/${encodeURIComponent(roleRow.role)}/permissions`, {
                method: 'PUT',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ permissions: roleRow.overrides || {} }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || `Failed to save ${roleRow.role} permissions`);
            } else {
                setRoles((prev) => prev.map((r) => {
                    if (r.role !== roleRow.role) return r;
                    return { ...r, effective_permissions: data.effective_permissions || r.effective_permissions };
                }));
                notifyUi(`${roleRow.role} permissions updated`, 'success');
                setMessage(`${roleRow.role} permissions updated`);
            }
        } catch (_) {
            setMessage(`Failed to save ${roleRow.role} permissions`);
        }
        setSavingRole('');
    };

    const createCustomRole = async (e) => {
        e.preventDefault();
        setMessage('');
        setSavingRoleMeta('create');
        try {
            const res = await fetch(`${apiBase}/admin/iam/roles`, {
                method: 'POST',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(roleForm),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to create custom role');
                setSavingRoleMeta('');
                return;
            }
            setRoleForm({ role: '', display_name: '', description: '' });
            setShowRoleModal(false);
            notifyUi('Custom role created', 'success');
            load();
        } catch (_) {
            setMessage('Failed to create custom role');
        }
        setSavingRoleMeta('');
    };

    const toggleRoleActive = async (roleRow) => {
        if (roleRow.is_system) return;
        setMessage('');
        setSavingRoleMeta(roleRow.role);
        try {
            const res = await fetch(`${apiBase}/admin/iam/roles/${encodeURIComponent(roleRow.role)}`, {
                method: 'PATCH',
                headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify({ is_active: !roleRow.is_active }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to update role status');
                return;
            }
            notifyUi(`Role ${roleRow.is_active ? 'deactivated' : 'activated'}`, 'success');
            load();
        } catch (_) {
            setMessage('Failed to update role status');
        }
        setSavingRoleMeta('');
    };

    const deleteCustomRole = async (roleRow) => {
        if (roleRow?.is_system) return;
        const ok = await askConfirm({
            title: 'Delete Custom Role',
            message: `Delete role "${roleRow.role}" permanently? This removes its permission profile.`,
            confirmText: 'Delete Role',
            cancelText: 'Cancel',
            tone: 'danger',
        });
        if (!ok) return;

        setMessage('');
        setSavingRoleMeta(`delete:${roleRow.role}`);
        try {
            const res = await fetch(`${apiBase}/admin/iam/roles/${encodeURIComponent(roleRow.role)}`, {
                method: 'DELETE',
                headers: getAuthHeaders(),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                setMessage(data.error || 'Failed to delete custom role');
                return;
            }
            notifyUi('Custom role deleted', 'success');
            load();
        } catch (_) {
            setMessage('Failed to delete custom role');
        }
        setSavingRoleMeta('');
    };

    const permissionEnabled = (roleName, permissionKey) => {
        const roleRow = roleLookup[roleName];
        if (!roleRow) return false;
        return !!(roleRow.effective_permissions || []).includes(permissionKey);
    };

    if (!canManage) {
        return (
            <div className="panel">
                <h2>IAM & Governance</h2>
                <div style={{ color: 'var(--text-muted)' }}>Only SUPER_ADMIN can manage IAM governance settings.</div>
            </div>
        );
    }

    return (
        <div style={{ display: 'grid', gap: '16px' }}>
            <div className="panel" style={{ marginBottom: 0, padding: '14px 16px' }}>
                <h2 style={{ marginBottom: '6px' }}>Admin Workspace</h2>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Unified IAM, users, governance settings, and permission operations.</div>
            </div>

            {message && <div className="panel" style={{ marginBottom: 0, color: 'var(--text-muted)' }}>{message}</div>}

            <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0, 1fr)', gap: '16px', alignItems: 'flex-start' }}>
                <aside className="panel" style={{ marginBottom: 0, position: 'sticky', top: '12px' }}>
                    <div style={{ display: 'grid', gap: '8px' }}>
                        <a className="btn" href={governanceHref('overview')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'overview' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'overview' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('overview')}>Overview</a>
                        <a className="btn" href={governanceHref('users')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'users' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'users' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('users')}>Users & Access</a>
                        <a className="btn" href={governanceHref('roles')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'roles' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'roles' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('roles')}>Roles & Permissions</a>
                        <a className="btn" href={governanceHref('policies')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'policies' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'policies' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('policies')}>Policies</a>
                        <a className="btn" href={governanceHref('exceptions')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'exceptions' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'exceptions' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('exceptions')}>Exceptions</a>
                        <a className="btn" href={governanceHref('settings')} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'settings' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'settings' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('settings')}>Governance Settings</a>
                        {selectedAuditUser && activeSection === 'user_audit' && (
                            <a className="btn" href={governanceHref('user_audit', selectedAuditUser)} style={{ textAlign: 'left', textDecoration: 'none', background: activeSection === 'user_audit' ? 'var(--accent)' : 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: activeSection === 'user_audit' ? 'white' : 'var(--text-strong)' }} onClick={() => setActiveSection('user_audit')}>
                                <div style={{ fontWeight: 700 }}>User Audit</div>
                                <div style={{ fontSize: '12px', opacity: 0.95, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '100%' }}>{selectedAuditUser}</div>
                            </a>
                        )}
                    </div>
                </aside>

                <div style={{ minWidth: 0 }}>
                    {activeSection === 'overview' && (
                        <div style={{ display: 'grid', gap: '16px' }}>
                            <div className="panel" style={{ marginBottom: 0 }}>
                                <h3 style={{ marginTop: 0 }}>Overview</h3>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
                                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px' }}>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Total Users</div>
                                        <div style={{ color: 'var(--text-strong)', fontSize: '22px', fontWeight: 700 }}>{users.length}</div>
                                    </div>
                                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px' }}>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Active Users</div>
                                        <div style={{ color: 'var(--text-strong)', fontSize: '22px', fontWeight: 700 }}>{users.filter(u => u.is_active).length}</div>
                                    </div>
                                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px' }}>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Roles</div>
                                        <div style={{ color: 'var(--text-strong)', fontSize: '22px', fontWeight: 700 }}>{roles.length}</div>
                                    </div>
                                    <div style={{ border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px' }}>
                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Permissions</div>
                                        <div style={{ color: 'var(--text-strong)', fontSize: '22px', fontWeight: 700 }}>{sortedPermissionKeys.length}</div>
                                    </div>
                                </div>
                                <div style={{ marginTop: '12px', color: 'var(--text-muted)', fontSize: '13px' }}>Use the left navigation to manage users, role access, and policy controls.</div>
                            </div>

                            <div className="panel" style={{ marginBottom: 0 }}>
                                <h3 style={{ marginTop: 0, marginBottom: '6px' }}>User Activity Directory</h3>
                                <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>Open action-only audit history for any user, including your own account.</div>
                                <div style={{ overflowX: 'auto' }}>
                                    <table style={{ width: '100%', minWidth: '800px', borderCollapse: 'collapse' }}>
                                        <thead>
                                            <tr>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>User</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Role</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Status</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Audit</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {users.length === 0 ? (
                                                <tr>
                                                    <td colSpan={4} style={{ padding: '12px', color: 'var(--text-muted)' }}>No users found.</td>
                                                </tr>
                                            ) : users.map((u) => (
                                                <tr key={`audit-${u.user_id}`}>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <div style={{ color: 'var(--text-strong)', fontWeight: 600 }}>{u.display_name || '—'}</div>
                                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{u.email || '—'}</div>
                                                    </td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>{u.role || '—'}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>{u.is_active ? 'Active' : 'Inactive'}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <a className="btn" href={governanceHref('user_audit', u.email)} style={{ textDecoration: 'none', background: 'var(--accent)', color: 'var(--text-inverse)', border: '1px solid var(--accent)' }} onClick={(e) => { if (e.button !== 0) return; e.preventDefault(); openUserAudit(u.email); }}>View Audit</a>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>


                        </div>
                    )}

                    {activeSection === 'users' && (
                        <div style={{ display: 'grid', gap: '16px' }}>
                            <div className="panel" style={{ marginBottom: 0 }}>
                                <h3 style={{ marginTop: 0 }}>Create User</h3>
                                <form onSubmit={createUser} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px', alignItems: 'end' }}>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Email</label>
                                        <input className="form-control" required value={userForm.email} onChange={(e) => setUserForm({ ...userForm, email: e.target.value })} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Display Name</label>
                                        <input className="form-control" required value={userForm.display_name} onChange={(e) => setUserForm({ ...userForm, display_name: e.target.value })} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Temporary Password</label>
                                        <div style={{ display: 'flex', gap: '8px' }}>
                                            <input className="form-control" type={showCreatePassword ? 'text' : 'password'} required minLength={passwordPolicy.minLength} value={userForm.password} onChange={(e) => setUserForm({ ...userForm, password: e.target.value })} />
                                            <button type="button" className="btn" style={{ background: 'var(--panel-bg-alt)', border: '1px solid var(--border-color)', color: 'var(--text-strong)' }} onClick={() => setShowCreatePassword(v => !v)}>{showCreatePassword ? 'Hide' : 'Show'}</button>
                                        </div>
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Role</label>
                                        <select className="form-control" value={userForm.role} onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}>
                                            {assignableRoles.map((role) => (
                                                <option key={role} value={role}>{role}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Manager Email</label>
                                        <input list="governance-manager-options" className="form-control" value={userForm.manager_email} onChange={(e) => setUserForm({ ...userForm, manager_email: e.target.value })} />
                                        <datalist id="governance-manager-options">
                                            {managerOptions.map((email) => (<option key={email} value={email} />))}
                                        </datalist>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'end' }}>
                                        <button className="btn" type="submit" disabled={creatingUser}>{creatingUser ? 'Creating...' : 'Create User'}</button>
                                    </div>
                                </form>
                            </div>

                            <div className="panel" style={{ marginBottom: 0 }}>
                                <h3 style={{ marginTop: 0 }}>User Directory ({users.length})</h3>
                                {loading ? (
                                    <div style={{ color: 'var(--text-muted)' }}>Loading users...</div>
                                ) : users.length === 0 ? (
                                    <div style={{ color: 'var(--text-muted)' }}>No users found.</div>
                                ) : (
                                    <div style={{ overflowX: 'auto' }}>
                                        <table style={{ width: '100%', minWidth: '1180px', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
                                            <thead>
                                                <tr>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>User</th>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>Role</th>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>Manager</th>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>Status</th>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>Temp Password</th>
                                                    <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '12px' }}>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {users.map((u) => (
                                                    <tr key={u.user_id} style={{ background: 'var(--panel-bg-alt)' }}>
                                                        <td style={{ padding: '10px', border: '1px solid var(--border-color)', borderRight: 'none', borderRadius: '10px 0 0 10px' }}>
                                                            <div style={{ fontWeight: 700, color: 'var(--text-strong)' }}>{u.display_name}</div>
                                                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{u.email}</div>
                                                        </td>
                                                        <td style={{ padding: '10px', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)' }}>
                                                            <select className="form-control" value={u.role} onChange={(e) => updateUserRole(u, e.target.value)}>
                                                                {assignableRoles.map((role) => (
                                                                    <option key={role} value={role}>{role}</option>
                                                                ))}
                                                            </select>
                                                        </td>
                                                        <td style={{ padding: '10px', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)', fontSize: '13px' }}>{u.manager_email || '—'}</td>
                                                        <td style={{ padding: '10px', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)' }}>
                                                            <button className="btn" style={{ background: u.is_active ? '#b45309' : 'var(--accent)' }} onClick={() => toggleUserActive(u)}>{u.is_active ? 'Deactivate' : 'Activate'}</button>
                                                        </td>
                                                        <td style={{ padding: '10px', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)' }}>
                                                            <input className="form-control" type="password" placeholder="Temporary password" value={resetPasswords[u.user_id] || ''} onChange={(e) => setResetPasswords((prev) => ({ ...prev, [u.user_id]: e.target.value }))} />
                                                        </td>
                                                        <td style={{ padding: '10px', border: '1px solid var(--border-color)', borderLeft: 'none', borderRadius: '0 10px 10px 0' }}>
                                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                                <button className="btn" onClick={() => resetUserPassword(u)}>Reset Password</button>
                                                                <button className="btn" style={{ background: '#b45309' }} onClick={() => revokeUserSessions(u)}>Revoke Sessions</button>
                                                                <a className="btn" href={governanceHref('user_audit', u.email)} style={{ textDecoration: 'none', background: 'var(--accent)', color: 'var(--text-inverse)', border: '1px solid var(--accent)' }} onClick={(e) => { if (e.button !== 0) return; e.preventDefault(); openUserAudit(u.email); }}>Audit</a>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeSection === 'roles' && (
                        <div className="panel" style={{ marginBottom: 0 }}>
                            <h3 style={{ marginTop: 0, marginBottom: '4px' }}>Role Permission Matrix</h3>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>Create, activate/deactivate, delete custom roles, and tune permissions in one grid.</div>
                            {loading ? (
                                <div style={{ color: 'var(--text-muted)' }}>Loading roles...</div>
                            ) : (
                                <>
                                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '12px' }}>
                                        <button className="btn" type="button" onClick={() => setShowRoleModal(true)}>Create Custom Role</button>
                                    </div>

                                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' }}>
                                        {roleNames.map((roleName) => (
                                            <button key={roleName} className="btn" disabled={savingRole === roleName} onClick={() => saveRolePermissions(roleLookup[roleName])}>
                                                {savingRole === roleName ? `Saving ${roleName}...` : `Save ${roleName}`}
                                            </button>
                                        ))}
                                    </div>
                                    <div style={{ overflowX: 'auto' }}>
                                        <table style={{ width: '100%', minWidth: '1000px', borderCollapse: 'collapse' }}>
                                            <thead>
                                                <tr>
                                                    <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', width: '45%' }}>Permission</th>
                                                    {roleNames.map((roleName) => (
                                                        <th key={roleName} style={{ textAlign: 'center', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', background: 'var(--panel-bg-alt)' }}>
                                                            <div>{roleName}</div>
                                                            <div style={{ marginTop: '6px', display: 'flex', justifyContent: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                                                <span style={{ fontSize: '10px', color: 'var(--text-muted)', border: '1px solid var(--border-color)', padding: '1px 6px', borderRadius: '999px' }}>{roleLookup[roleName]?.is_system ? 'SYSTEM' : 'CUSTOM'}</span>
                                                                {!roleLookup[roleName]?.is_system && (
                                                                    <button
                                                                        className="btn"
                                                                        type="button"
                                                                        style={{ fontSize: '10px', padding: '2px 6px', background: roleLookup[roleName]?.is_active ? '#b45309' : 'var(--accent)' }}
                                                                        onClick={() => toggleRoleActive(roleLookup[roleName])}
                                                                        disabled={savingRoleMeta === roleName}
                                                                    >
                                                                        {savingRoleMeta === roleName ? '...' : (roleLookup[roleName]?.is_active ? 'Disable' : 'Enable')}
                                                                    </button>
                                                                )}
                                                                {!roleLookup[roleName]?.is_system && (
                                                                    <button
                                                                        className="btn"
                                                                        type="button"
                                                                        style={{ fontSize: '10px', padding: '2px 6px', background: '#dc2626' }}
                                                                        onClick={() => deleteCustomRole(roleLookup[roleName])}
                                                                        disabled={savingRoleMeta === `delete:${roleName}`}
                                                                    >
                                                                        {savingRoleMeta === `delete:${roleName}` ? 'Deleting...' : 'Delete'}
                                                                    </button>
                                                                )}
                                                            </div>
                                                        </th>
                                                    ))}
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {sortedPermissionKeys.map((permKey) => (
                                                    <tr key={permKey}>
                                                        <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                            <div style={{ color: 'var(--text-strong)', fontSize: '13px', fontWeight: 600 }}>{permKey}</div>
                                                            <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{catalog[permKey]}</div>
                                                        </td>
                                                        {roleNames.map((roleName) => (
                                                            <td key={`${permKey}-${roleName}`} style={{ textAlign: 'center', padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                                <input
                                                                    type="checkbox"
                                                                    checked={permissionEnabled(roleName, permKey)}
                                                                    onChange={() => toggleRolePermission(roleName, permKey)}
                                                                />
                                                            </td>
                                                        ))}
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {activeSection === 'policies' && (
                        <div className="panel" style={{ marginBottom: 0 }}>
                            <h3 style={{ marginTop: 0, marginBottom: '4px' }}>Policies ({policies.length})</h3>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>Track policy ownership with last editor metadata.</div>
                            {loading ? (
                                <div style={{ color: 'var(--text-muted)' }}>Loading policies...</div>
                            ) : policies.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)' }}>No policies found.</div>
                            ) : (
                                <div style={{ overflowX: 'auto' }}>
                                    <table style={{ width: '100%', minWidth: '980px', borderCollapse: 'collapse' }}>
                                        <thead>
                                            <tr>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Policy</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Type</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Severity</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Status</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Last Updated By</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Last Updated At</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {policies.map((p) => (
                                                <tr key={p.policy_id}>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <div style={{ color: 'var(--text-strong)', fontWeight: 600 }}>{p.name || p.policy_id}</div>
                                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{p.policy_id}</div>
                                                    </td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{String(p.rule_type || 'regex').toUpperCase()}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{String(p.severity || 'MEDIUM').toUpperCase()}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <span style={{ fontSize: '11px', border: '1px solid var(--border-color)', borderRadius: '999px', padding: '2px 8px', color: (p.is_active === 0 || p.is_active === false) ? '#b45309' : 'var(--accent)' }}>
                                                            {(p.is_active === 0 || p.is_active === false) ? 'INACTIVE' : 'ACTIVE'}
                                                        </span>
                                                    </td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{p.updated_by || 'system'}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', whiteSpace: 'nowrap' }}>{p.updated_at || p.created_at || '—'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}

                    {activeSection === 'exceptions' && (
                        <div className="panel" style={{ marginBottom: 0 }}>
                            <h3 style={{ marginTop: 0, marginBottom: '4px' }}>Exceptions ({exceptions.length})</h3>
                            <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>Track exception ownership with last editor metadata.</div>
                            {loading ? (
                                <div style={{ color: 'var(--text-muted)' }}>Loading exceptions...</div>
                            ) : exceptions.length === 0 ? (
                                <div style={{ color: 'var(--text-muted)' }}>No exceptions found.</div>
                            ) : (
                                <div style={{ overflowX: 'auto' }}>
                                    <table style={{ width: '100%', minWidth: '1080px', borderCollapse: 'collapse' }}>
                                        <thead>
                                            <tr>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Exception</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Scope</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Mode</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Status</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Last Updated By</th>
                                                <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Last Updated At</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {exceptions.map((ex) => (
                                                <tr key={ex.exception_id}>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <div style={{ color: 'var(--text-strong)', fontWeight: 600 }}>{ex.name || ex.exception_id}</div>
                                                        <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{ex.exception_id}</div>
                                                    </td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{String(ex.scope_type || 'global').toUpperCase()}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{String(ex.mode || 'allow').toUpperCase()}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)' }}>
                                                        <span style={{ fontSize: '11px', border: '1px solid var(--border-color)', borderRadius: '999px', padding: '2px 8px', color: (ex.is_active === 0 || ex.is_active === false) ? '#b45309' : 'var(--accent)' }}>
                                                            {(ex.is_active === 0 || ex.is_active === false) ? 'INACTIVE' : 'ACTIVE'}
                                                        </span>
                                                    </td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)' }}>{ex.updated_by || 'system'}</td>
                                                    <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', whiteSpace: 'nowrap' }}>{ex.updated_at || ex.created_at || '—'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}

                    {activeSection === 'settings' && (
                        <div className="panel" style={{ marginBottom: 0 }}>
                            <h3 style={{ marginTop: 0 }}>Governance Settings</h3>
                            {loading ? (
                                <div style={{ color: 'var(--text-muted)' }}>Loading settings...</div>
                            ) : (
                                <form onSubmit={saveSettings} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Password Min Length</label>
                                        <input className="form-control" type="number" min="8" value={settings.password_min_length ?? 12} onChange={(e) => updateSetting('password_min_length', Number(e.target.value || 12))} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Max Concurrent Sessions Per User</label>
                                        <input className="form-control" type="number" min="1" value={settings.max_concurrent_sessions ?? 3} onChange={(e) => updateSetting('max_concurrent_sessions', Number(e.target.value || 3))} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Session Idle Timeout (minutes)</label>
                                        <input className="form-control" type="number" min="1" value={settings.session_idle_timeout_minutes ?? 120} onChange={(e) => updateSetting('session_idle_timeout_minutes', Number(e.target.value || 120))} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Login Lockout Attempts</label>
                                        <input className="form-control" type="number" min="3" value={settings.auth_max_failed_attempts ?? 5} onChange={(e) => updateSetting('auth_max_failed_attempts', Number(e.target.value || 5))} />
                                    </div>
                                    <div className="form-group" style={{ marginBottom: 0 }}>
                                        <label>Login Lockout Duration (minutes)</label>
                                        <input className="form-control" type="number" min="1" value={settings.auth_lockout_minutes ?? 15} onChange={(e) => updateSetting('auth_lockout_minutes', Number(e.target.value || 15))} />
                                    </div>

                                    <div className="form-group" style={{ marginBottom: 0, gridColumn: '1 / -1', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '8px' }}>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.password_require_upper} onChange={(e) => updateSetting('password_require_upper', e.target.checked)} /> Require uppercase</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.password_require_lower} onChange={(e) => updateSetting('password_require_lower', e.target.checked)} /> Require lowercase</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.password_require_digit} onChange={(e) => updateSetting('password_require_digit', e.target.checked)} /> Require number</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.password_require_special} onChange={(e) => updateSetting('password_require_special', e.target.checked)} /> Require special character</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.password_prevent_email_localpart} onChange={(e) => updateSetting('password_prevent_email_localpart', e.target.checked)} /> Block email username in password</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.enforce_last_super_admin_protection} onChange={(e) => updateSetting('enforce_last_super_admin_protection', e.target.checked)} /> Protect last active super admin</label>
                                        <label style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><input type="checkbox" checked={!!settings.enforce_policy_delete_confirmation_ticket} onChange={(e) => updateSetting('enforce_policy_delete_confirmation_ticket', e.target.checked)} /> Require ticket ID on policy/exception delete</label>
                                    </div>

                                    <div style={{ gridColumn: '1 / -1' }}>
                                        <button className="btn" type="submit" disabled={savingSettings}>{savingSettings ? 'Saving...' : 'Save Governance Settings'}</button>
                                    </div>
                                </form>
                            )}
                        </div>
                    )}

                    {activeSection === 'user_audit' && (
                        <div className="panel" style={{ marginBottom: 0 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '10px' }}>
                                <div>
                                    <h3 style={{ marginTop: 0, marginBottom: '4px' }}>User Audit: {selectedAuditUser || '—'}</h3>
                                    <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Action-level events showing what this user did in the portal.</div>
                                </div>
                                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                                    <input className="form-control" placeholder="Search action/target" value={auditQuery} onChange={(e) => setAuditQuery(e.target.value)} style={{ minWidth: '240px' }} />
                                    <button className="btn" type="button" onClick={() => fetchUserAudit(selectedAuditUser)} disabled={!selectedAuditUser || userAuditLoading}>{userAuditLoading ? 'Refreshing...' : 'Refresh'}</button>
                                    <button className="btn" type="button" style={{ background: 'var(--panel-bg-alt)', color: 'var(--text-strong)', border: '1px solid var(--border-color)' }} onClick={closeUserAudit}>Back to Overview</button>
                                </div>
                            </div>
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', minWidth: '720px', borderCollapse: 'collapse' }}>
                                    <thead>
                                        <tr>
                                            <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', width: '120px' }}>Time</th>
                                            <th style={{ textAlign: 'left', padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px' }}>Activity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {userAuditLoading ? (
                                            <tr>
                                                <td colSpan={2} style={{ padding: '14px', color: 'var(--text-muted)' }}>Loading user audit history...</td>
                                            </tr>
                                        ) : userAuditFiltered.length === 0 ? (
                                            <tr>
                                                <td colSpan={2} style={{ padding: '14px', color: 'var(--text-muted)' }}>No action audits found for this user.</td>
                                            </tr>
                                        ) : userAuditFiltered.map((entry) => (
                                            <tr key={`user-audit-${entry.id}`}>
                                                <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '12px', whiteSpace: 'nowrap' }}>{formatAuditTimestamp(entry.timestamp)}</td>
                                                <td style={{ padding: '10px', borderBottom: '1px solid var(--border-color)', color: 'var(--text-strong)', fontSize: '13px' }}>{getReadableActionDescription(entry)}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {showRoleModal && (
                <div className="modal-backdrop" onClick={() => setShowRoleModal(false)}>
                    <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px', width: '100%' }}>
                        <h3 className="modal-title">Create Custom Role</h3>
                        <form onSubmit={createCustomRole} style={{ display: 'grid', gap: '10px' }}>
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label>Role Key</label>
                                <input className="form-control" placeholder="e.g. INCIDENT_REVIEWER" value={roleForm.role} onChange={(e) => setRoleForm((prev) => ({ ...prev, role: e.target.value.toUpperCase() }))} />
                            </div>
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label>Display Name</label>
                                <input className="form-control" placeholder="Incident Reviewer" value={roleForm.display_name} onChange={(e) => setRoleForm((prev) => ({ ...prev, display_name: e.target.value }))} />
                            </div>
                            <div className="form-group" style={{ marginBottom: 0 }}>
                                <label>Description</label>
                                <input className="form-control" placeholder="Optional description" value={roleForm.description} onChange={(e) => setRoleForm((prev) => ({ ...prev, description: e.target.value }))} />
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="btn modal-btn-cancel" onClick={() => setShowRoleModal(false)}>Cancel</button>
                                <button className="btn" type="submit" disabled={savingRoleMeta === 'create'}>
                                    {savingRoleMeta === 'create' ? 'Creating...' : 'Create Role'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Governance;
