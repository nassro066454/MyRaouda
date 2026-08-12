import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createServer as createViteServer } from 'vite';
import { getDb, queryAll, queryOne, executeSql, logAudit, saveDb, resetDatabase, createNotification, syncSystemNotifications, syncWithPostgres } from './src/server/db';

const JWT_SECRET = process.env.JWT_SECRET || 'rawda_secret_key_kindergarten_2026';
const PORT = 3000;

export interface AuthRequest extends Request {
  user?: {
    id: number;
    email: string;
    name: string;
    role: string;
  };
}

// Auth middleware
function authenticateToken(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'لم يتم توفير رمز التوثيق' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'رمز التوثيق غير صالحة أو منتهي الصلاحية' });
    }
    req.user = decoded as any;
    next();
  });
}

// Role authorization middleware
function authorizeRoles(...roles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'ليس لديك الصلاحية الكافية للوصول إلى هذا الإجراء' });
    }
    next();
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Wait for DB initialization
  const db = await getDb();

  // Helper middleware to ensure DB is initialized and synced with cloud Postgres
  app.use(async (req, res, next) => {
    try {
      await syncWithPostgres();
    } catch (err) {
      console.error('Error syncing with Postgres:', err);
    }
    next();
  });

  // Helper middleware to check permission dynamically
  function hasPermission(role: string, permCode: string): boolean {
    if (role === 'admin') return true;
    const row = queryOne(db, 'SELECT 1 FROM role_permissions WHERE role = ? AND permission_code = ?', [role, permCode]);
    return !!row;
  }

  function authorizePermission(permCode: string) {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
      if (!req.user) return res.status(401).json({ error: 'غير مصرح' });
      if (hasPermission(req.user.role, permCode)) {
        return next();
      }
      return res.status(403).json({ error: 'غير مصرح لك بالوصول أو تنفيذ هذه العملية' });
    };
  }

  // -------------------------------------------------------------
  // AUTH ROUTES
  // -------------------------------------------------------------
  app.post('/api/auth/login', (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: 'يرجى إدخال البريد الإلكتروني وكلمة المرور' });
      }

      const user = queryOne(db, 'SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
      if (!user) {
        return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
      }

      // Check password using bcrypt
      const valid = bcrypt.compareSync(password, user.password_hash);
      if (!valid) {
        return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, name: user.name, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      logAudit(db, user.id, user.name, 'تسجيل دخول', 'المستخدمين', user.id, 'تم تسجيل الدخول بنجاح');

      res.json({
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'حدث خطأ في السيرفر أثناء تسجيل الدخول' });
    }
  });

  app.post('/api/auth/logout', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      if (req.user) {
        logAudit(db, req.user.id, req.user.name, 'تسجيل خروج', 'المستخدمين', req.user.id, 'تم تسجيل الخروج بنجاح من النظام');
      }
      res.json({ message: 'تم تسجيل الخروج بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء تسجيل الخروج' });
    }
  });

  app.get('/api/auth/me', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const user = queryOne(db, 'SELECT id, email, name, role, is_active FROM users WHERE id = ?', [req.user?.id]);
      if (!user) {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }
      const rolePerms = queryAll(db, 'SELECT permission_code FROM role_permissions WHERE role = ?', [user.role]);
      const permissions = rolePerms.map((rp: any) => rp.permission_code);
      res.json({ user: { ...user, permissions } });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات المستخدم' });
    }
  });

  // -------------------------------------------------------------
  // DASHBOARD STATS
  // -------------------------------------------------------------
  app.get('/api/dashboard/stats', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const totalChildren = queryOne(db, "SELECT COUNT(*) as count FROM children WHERE status != 'مؤرشف'")?.count || 0;
      const activeChildren = queryOne(db, "SELECT COUNT(*) as count FROM children WHERE status = 'نشط'")?.count || 0;

      const today = new Date().toISOString().split('T')[0];
      const todayAttendance = queryAll(db, 'SELECT status, COUNT(*) as count FROM attendance WHERE date = ? GROUP BY status', [today]);

      let presentCount = 0;
      let absentCount = 0;
      let lateCount = 0;
      let excusedCount = 0;

      todayAttendance.forEach((row: any) => {
        if (row.status === 'حاضر') presentCount = row.count;
        if (row.status === 'غائب') absentCount = row.count;
        if (row.status === 'متأخر') lateCount = row.count;
        if (row.status === 'غياب بعذر') excusedCount = row.count;
      });

      const totalActiveSubscriptions = queryOne(db, "SELECT COUNT(*) as count FROM subscriptions WHERE status != 'مغلق'")?.count || 0;
      
      const outstandingRes = queryOne(
        db,
        "SELECT COUNT(*) as count, COALESCE(SUM(final_amount - paid_amount), 0) as total_amount FROM subscriptions WHERE status IN ('متأخر', 'غير مدفوع', 'مدفوع جزئياً')"
      );

      const totalClasses = queryOne(db, "SELECT COUNT(*) as count FROM classes WHERE status = 'نشط'")?.count || 0;
      const capacityRes = queryOne(db, "SELECT COALESCE(SUM(capacity), 0) as total_cap, COALESCE(SUM(current_enrollment), 0) as total_enrolled FROM classes WHERE status = 'نشط'");
      const totalCaregivers = queryOne(db, "SELECT COUNT(*) as count FROM caregivers WHERE status = 'نشط'")?.count || 0;

      const totalRevenueRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM payments");
      const totalRevenue = totalRevenueRes?.total || 0;

      const childrenByClass = queryAll(
        db,
        `SELECT cl.name, COUNT(c.id) as count
         FROM classes cl
         LEFT JOIN children c ON cl.id = c.class_id AND c.status = 'نشط'
         WHERE cl.status = 'نشط'
         GROUP BY cl.id, cl.name`
      );

      const subscriptionStatusBreakdown = queryAll(
        db,
        `SELECT status as name, COUNT(*) as count FROM subscriptions GROUP BY status`
      );

      const paymentStatusBreakdown = queryAll(
        db,
        `SELECT status as name, COUNT(*) as count, COALESCE(SUM(final_amount - paid_amount), 0) as outstanding FROM subscriptions GROUP BY status`
      );

      // Overdue subscriptions list
      const overdueSubscriptions = queryAll(
        db,
        `SELECT s.*, c.full_name as child_name, p.full_name as parent_name, p.phone as parent_phone
         FROM subscriptions s
         JOIN children c ON s.child_id = c.id
         JOIN parents p ON c.parent_id = p.id
         WHERE s.status IN ('متأخر', 'غير مدفوع', 'مدفوع جزئياً')
         ORDER BY s.due_date ASC LIMIT 5`
      );

      // Class capacities
      const classCapacities = queryAll(
        db,
        `SELECT id, name, capacity, current_enrollment, (capacity - current_enrollment) as available_seats FROM classes WHERE status = 'نشط'`
      );

      // Audit logs
      const recentLogs = queryAll(db, `SELECT * FROM audit_logs ORDER BY id DESC LIMIT 6`);

      // Today's Meals
      const todayMeals = queryAll(
        db,
        `SELECT ms.*, u.name as created_by_name FROM meal_schedules ms LEFT JOIN users u ON ms.created_by_user_id = u.id WHERE ms.date = ? ORDER BY ms.id ASC`,
        [today]
      );

      // Treasury Summary
      const totalIncRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد'");
      const totalExpRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد'");
      const todayIncRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد' AND transaction_date = ?", [today]);
      const todayExpRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد' AND transaction_date = ?", [today]);

      const currentBalance = (totalIncRes?.total || 0) - (totalExpRes?.total || 0);

      // Children monthly growth
      const childrenMonthlyGrowthRaw = queryAll(
        db,
        `SELECT SUBSTR(COALESCE(enrollment_date, created_at), 1, 7) as month, COUNT(*) as count
         FROM children
         WHERE status != 'مؤرشف' AND (enrollment_date IS NOT NULL OR created_at IS NOT NULL)
         GROUP BY month
         ORDER BY month ASC
         LIMIT 12`
      );
      const childrenMonthlyGrowth = childrenMonthlyGrowthRaw.map((r: any) => ({
        month: r.month,
        count: r.count,
      }));

      // Age distribution
      const childrenDobList = queryAll(db, `SELECT dob FROM children WHERE status != 'مؤرشف' AND dob IS NOT NULL`);
      const ageGroups: { [key: string]: number } = {
        'أقل من 3 سنوات': 0,
        '3 - 4 سنوات': 0,
        '4 - 5 سنوات': 0,
        '5 - 6 سنوات': 0,
        'أكثر من 6 سنوات': 0,
      };

      const nowYear = new Date().getFullYear();
      const nowMonth = new Date().getMonth();

      childrenDobList.forEach((row: any) => {
        if (!row.dob) return;
        const dobDate = new Date(row.dob);
        if (isNaN(dobDate.getTime())) return;
        let age = nowYear - dobDate.getFullYear();
        const mDiff = nowMonth - dobDate.getMonth();
        if (mDiff < 0 || (mDiff === 0 && new Date().getDate() < dobDate.getDate())) {
          age--;
        }
        if (age < 3) {
          ageGroups['أقل من 3 سنوات']++;
        } else if (age >= 3 && age < 4) {
          ageGroups['3 - 4 سنوات']++;
        } else if (age >= 4 && age < 5) {
          ageGroups['4 - 5 سنوات']++;
        } else if (age >= 5 && age < 6) {
          ageGroups['5 - 6 سنوات']++;
        } else {
          ageGroups['أكثر من 6 سنوات']++;
        }
      });

      const ageDistribution = Object.keys(ageGroups).map((group) => ({
        ageGroup: group,
        count: ageGroups[group],
      }));

      res.json({
        totalChildren,
        activeChildren,
        totalRevenue,
        todayAttendance: {
          present: presentCount,
          absent: absentCount,
          late: lateCount,
          excused: excusedCount,
          totalRecorded: presentCount + absentCount + lateCount + excusedCount,
        },
        subscriptions: {
          activeCount: totalActiveSubscriptions,
          outstandingCount: outstandingRes?.count || 0,
          outstandingAmount: outstandingRes?.total_amount || 0,
        },
        classes: {
          totalClasses,
          totalCapacity: capacityRes?.total_cap || 0,
          totalEnrolled: capacityRes?.total_enrolled || 0,
          availableSeats: (capacityRes?.total_cap || 0) - (capacityRes?.total_enrolled || 0),
        },
        totalCaregivers,
        overdueSubscriptions,
        classCapacities,
        childrenByClass,
        subscriptionStatusBreakdown,
        paymentStatusBreakdown,
        childrenMonthlyGrowth,
        ageDistribution,
        recentLogs,
        todayMeals,
        treasurySummary: {
          currentBalance,
          todayIncome: todayIncRes?.total || 0,
          todayExpenses: todayExpRes?.total || 0,
          outstandingPayments: outstandingRes?.total_amount || 0,
        },
      });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ في جلب إحصائيات لوحة التحكم' });
    }
  });

  // -------------------------------------------------------------
  // SETTINGS API
  // -------------------------------------------------------------
  app.get('/api/settings', (req: Request, res: Response) => {
    try {
      const settings = queryOne(db, 'SELECT * FROM settings ORDER BY id ASC LIMIT 1');
      res.json({ settings });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب إعدادات الروضة' });
    }
  });

  app.put('/api/settings', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { kindergarten_name, logo_url, phone, address, academic_year, currency, backup_path, auto_backup_on_logout, backup_frequency, backup_time } = req.body;
      const currencyValue = currency || 'ر.س';
      const backupPathValue = backup_path || 'Downloads';
      const autoLogoutVal = auto_backup_on_logout !== undefined ? (auto_backup_on_logout ? 1 : 0) : 1;
      const backupFreqValue = backup_frequency || 'daily';
      const backupTimeValue = backup_time || '18:00';
      const now = new Date().toISOString();
      executeSql(
        db,
        `UPDATE settings SET kindergarten_name = ?, logo_url = ?, phone = ?, address = ?, academic_year = ?, currency = ?, backup_path = ?, auto_backup_on_logout = ?, backup_frequency = ?, backup_time = ?, updated_at = ? WHERE id = 1`,
        [kindergarten_name, logo_url, phone, address, academic_year, currencyValue, backupPathValue, autoLogoutVal, backupFreqValue, backupTimeValue, now]
      );
      logAudit(db, req.user!.id, req.user!.name, 'تعديل الإعدادات', 'الإعدادات', 1, `تم تحديث إعدادات النظام والنسخ الاحتياطي بنجاح`);
      res.json({ message: 'تم حفظ الإعدادات بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حفظ إعدادات الروضة' });
    }
  });

  app.post('/api/settings/reset-database', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { password, confirmPhrase } = req.body;
      if (!password) {
        return res.status(400).json({ error: 'يرجى إدخال كلمة مرور المدير لتأكيد تصفير قاعدة البيانات' });
      }

      if (confirmPhrase) {
        const cleanPhrase = String(confirmPhrase).trim().toUpperCase();
        if (cleanPhrase !== 'RESET' && cleanPhrase !== 'تصفير') {
          return res.status(400).json({ error: 'يرجى كتابة عبارة التأكيد "RESET" أو "تصفير" بشكل صحيح' });
        }
      }

      // Verify admin user password
      const adminUser = queryOne(db, 'SELECT * FROM users WHERE id = ? AND role = "admin"', [req.user?.id]);
      if (!adminUser) {
        return res.status(403).json({ error: 'حساب غير مصرح له بتنفيذ هذه العملية' });
      }

      const isValidPassword = bcrypt.compareSync(password, adminUser.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'كلمة مرور المدير غير صحيحة' });
      }

      // Reset DB to initial fresh state
      resetDatabase(db);

      // Log audit on freshly reset DB
      const freshAdmin = queryOne(db, 'SELECT * FROM users WHERE email = ?', [adminUser.email]) || queryOne(db, 'SELECT * FROM users WHERE role = "admin" LIMIT 1');
      if (freshAdmin) {
        logAudit(db, freshAdmin.id, freshAdmin.name, 'تصفير قاعدة البيانات', 'النظام', 1, `تم تصفير وإعادة ضبط المصنع لقاعدة البيانات بنجاح بواسطة المدير (${adminUser.name})`);
      }

      res.json({ message: 'تم تصفير قاعدة البيانات بنجاح وإعادة النظام لحالة ضبط المصنع' });
    } catch (err: any) {
      console.error('Reset DB Error:', err);
      res.status(500).json({ error: 'حدث خطأ أثناء تصفير قاعدة البيانات' });
    }
  });

  app.get('/api/settings/backup', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const backup = {
        version: '1.0',
        timestamp: new Date().toISOString(),
        kindergarten: queryOne(db, 'SELECT * FROM settings WHERE id = 1'),
        tables: {
          settings: queryAll(db, 'SELECT * FROM settings'),
          users: queryAll(db, 'SELECT * FROM users'),
          parents: queryAll(db, 'SELECT * FROM parents'),
          caregivers: queryAll(db, 'SELECT * FROM caregivers'),
          classes: queryAll(db, 'SELECT * FROM classes'),
          children: queryAll(db, 'SELECT * FROM children'),
          subscriptions: queryAll(db, 'SELECT * FROM subscriptions'),
          payments: queryAll(db, 'SELECT * FROM payments'),
          attendance: queryAll(db, 'SELECT * FROM attendance'),
          health_notes: queryAll(db, 'SELECT * FROM health_notes'),
          behavior_notes: queryAll(db, 'SELECT * FROM behavior_notes'),
          audit_logs: queryAll(db, 'SELECT * FROM audit_logs'),
          meal_schedules: queryAll(db, 'SELECT * FROM meal_schedules'),
          treasury_transactions: queryAll(db, 'SELECT * FROM treasury_transactions'),
          notifications: queryAll(db, 'SELECT * FROM notifications'),
          kindergarten_events: queryAll(db, 'SELECT * FROM kindergarten_events')
        }
      };

      logAudit(db, req.user!.id, req.user!.name, 'تصدير نسخة احتياطية', 'النظام', 1, 'تم تحميل نسخة احتياطية لقاعدة البيانات بنجاح');
      res.json(backup);
    } catch (err: any) {
      console.error('Backup Error:', err);
      res.status(500).json({ error: 'حدث خطأ أثناء إنشاء النسخة الاحتياطية' });
    }
  });

  app.post('/api/settings/restore', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const backupData = req.body;
      if (!backupData || !backupData.tables) {
        return res.status(400).json({ error: 'ملف النسخة الاحتياطية غير صالح أو تالف' });
      }

      const { tables } = backupData;

      db.run('BEGIN TRANSACTION');
      try {
        const tableNames = [
          'payments', 'subscriptions', 'health_notes', 'behavior_notes', 'attendance', 
          'children', 'classes', 'caregivers', 'parents', 'treasury_transactions', 
          'meal_schedules', 'notifications', 'kindergarten_events', 'audit_logs', 'users', 'settings'
        ];
        
        for (const t of tableNames) {
          try {
            db.run(`DELETE FROM ${t}`);
          } catch (e) {
            // ignore if table missing
          }
        }

        if (tables.settings && Array.isArray(tables.settings)) {
          for (const row of tables.settings) {
            executeSql(db, `INSERT INTO settings (id, kindergarten_name, logo_url, phone, address, academic_year, currency, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.kindergarten_name, row.logo_url, row.phone, row.address, row.academic_year, row.currency || 'ر.س', row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.users && Array.isArray(tables.users)) {
          for (const row of tables.users) {
            executeSql(db, `INSERT INTO users (id, email, password_hash, name, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.email, row.password_hash, row.name, row.role, row.is_active !== undefined ? row.is_active : 1, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.parents && Array.isArray(tables.parents)) {
          for (const row of tables.parents) {
            executeSql(db, `INSERT INTO parents (id, full_name, relationship, phone, secondary_phone, email, address, occupation, emergency_contact, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.full_name, row.relationship, row.phone, row.secondary_phone, row.email, row.address, row.occupation, row.emergency_contact, row.notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.caregivers && Array.isArray(tables.caregivers)) {
          for (const row of tables.caregivers) {
            executeSql(db, `INSERT INTO caregivers (id, name, phone, email, position, assigned_class_id, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.name, row.phone, row.email, row.position, row.assigned_class_id, row.status || 'نشط', row.notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.classes && Array.isArray(tables.classes)) {
          for (const row of tables.classes) {
            executeSql(db, `INSERT INTO classes (id, name, age_group, capacity, current_enrollment, assigned_caregiver_id, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.name, row.age_group, row.capacity || 20, row.current_enrollment || 0, row.assigned_caregiver_id, row.status || 'نشط', row.notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.children && Array.isArray(tables.children)) {
          for (const row of tables.children) {
            executeSql(db, `INSERT INTO children (id, child_number, full_name, first_name, last_name, dob, gender, photo_url, parent_id, class_id, enrollment_date, status, emergency_contact, health_notes, allergies, general_notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.child_number, row.full_name, row.first_name, row.last_name, row.dob, row.gender, row.photo_url, row.parent_id, row.class_id, row.enrollment_date, row.status || 'نشط', row.emergency_contact, row.health_notes, row.allergies, row.general_notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.subscriptions && Array.isArray(tables.subscriptions)) {
          for (const row of tables.subscriptions) {
            executeSql(db, `INSERT INTO subscriptions (id, child_id, period_type, start_date, end_date, amount, discount, final_amount, paid_amount, status, due_date, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.child_id, row.period_type, row.start_date, row.end_date, row.amount, row.discount || 0, row.final_amount, row.paid_amount || 0, row.status || 'غير مدفوع', row.due_date, row.notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.payments && Array.isArray(tables.payments)) {
          for (const row of tables.payments) {
            executeSql(db, `INSERT INTO payments (id, subscription_id, child_id, parent_id, amount, payment_date, payment_method, reference_number, notes, recorded_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.subscription_id, row.child_id, row.parent_id, row.amount, row.payment_date, row.payment_method || 'نقداً', row.reference_number, row.notes, row.recorded_by_user_id, row.created_at
            ]);
          }
        }

        if (tables.attendance && Array.isArray(tables.attendance)) {
          for (const row of tables.attendance) {
            executeSql(db, `INSERT INTO attendance (id, child_id, class_id, date, status, arrival_time, departure_time, notes, recorded_by_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.child_id, row.class_id, row.date, row.status, row.arrival_time, row.departure_time, row.notes, row.recorded_by_user_id, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.health_notes && Array.isArray(tables.health_notes)) {
          for (const row of tables.health_notes) {
            executeSql(db, `INSERT INTO health_notes (id, child_id, date, note_type, description, medication_info, additional_notes, recorded_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.child_id, row.date, row.note_type, row.description, row.medication_info, row.additional_notes, row.recorded_by_user_id, row.created_at
            ]);
          }
        }

        if (tables.behavior_notes && Array.isArray(tables.behavior_notes)) {
          for (const row of tables.behavior_notes) {
            executeSql(db, `INSERT INTO behavior_notes (id, child_id, date, observation_type, description, follow_up, recorded_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.child_id, row.date, row.observation_type, row.description, row.follow_up, row.recorded_by_user_id, row.created_at
            ]);
          }
        }

        if (tables.treasury_transactions && Array.isArray(tables.treasury_transactions)) {
          for (const row of tables.treasury_transactions) {
            executeSql(db, `INSERT INTO treasury_transactions (id, transaction_date, type, amount, category, description, payment_method, reference_number, payment_id, recorded_by_user_id, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.transaction_date, row.type, row.amount, row.category, row.description, row.payment_method, row.reference_number, row.payment_id, row.recorded_by_user_id, row.status, row.notes, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.meal_schedules && Array.isArray(tables.meal_schedules)) {
          for (const row of tables.meal_schedules) {
            executeSql(db, `INSERT INTO meal_schedules (id, date, meal_type, meal_name, description, ingredients, side_dish, dessert_fruit, drink, notes, status, created_by_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.date, row.meal_type, row.meal_name, row.description, row.ingredients, row.side_dish, row.dessert_fruit, row.drink, row.notes, row.status, row.created_by_user_id, row.created_at, row.updated_at
            ]);
          }
        }

        if (tables.notifications && Array.isArray(tables.notifications)) {
          for (const row of tables.notifications) {
            executeSql(db, `INSERT INTO notifications (id, user_id, target_role, title, message, type, is_read, related_entity, related_id, action_url, priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.user_id, row.target_role, row.title, row.message, row.type, row.is_read, row.related_entity, row.related_id, row.action_url, row.priority, row.created_at
            ]);
          }
        }

        if (tables.kindergarten_events && Array.isArray(tables.kindergarten_events)) {
          for (const row of tables.kindergarten_events) {
            executeSql(db, `INSERT INTO kindergarten_events (id, title, description, event_date, category, target_role, created_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
              row.id, row.title, row.description, row.event_date, row.category, row.target_role, row.created_by_user_id, row.created_at
            ]);
          }
        }

        db.run('COMMIT');
        saveDb();

        logAudit(db, req.user!.id, req.user!.name, 'استعادة نسخة احتياطية', 'النظام', 1, 'تم استعادة النسخة الاحتياطية بنجاح');
        res.json({ message: 'تم استعادة النسخة الاحتياطية بنجاح وتحديث بيانات النظام' });
      } catch (txErr) {
        db.run('ROLLBACK');
        throw txErr;
      }
    } catch (err: any) {
      console.error('Restore Error:', err);
      res.status(500).json({ error: 'حدث خطأ أثناء استعادة النسخة الاحتياطية: ' + (err.message || '') });
    }
  });

  // -------------------------------------------------------------
  // CHILDREN MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/children', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { search, class_id, status } = req.query;
      let sql = `
        SELECT c.*, cl.name as class_name, p.full_name as parent_name, p.phone as parent_phone
        FROM children c
        LEFT JOIN classes cl ON c.class_id = cl.id
        LEFT JOIN parents p ON c.parent_id = p.id
        WHERE 1=1
      `;
      const params: any[] = [];

      if (status) {
        sql += ` AND c.status = ?`;
        params.push(status);
      } else {
        sql += ` AND c.status != 'مؤرشف'`;
      }

      if (class_id) {
        sql += ` AND c.class_id = ?`;
        params.push(Number(class_id));
      }

      if (search) {
        sql += ` AND (c.full_name LIKE ? OR c.child_number LIKE ? OR p.full_name LIKE ? OR p.phone LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term, term);
      }

      sql += ` ORDER BY c.id DESC`;

      const children = queryAll(db, sql, params);
      res.json({ children });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب قائمة الأطفال' });
    }
  });

  app.get('/api/children/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const childId = Number(req.params.id);
      const child = queryOne(
        db,
        `SELECT c.*, cl.name as class_name, p.full_name as parent_name, p.phone as parent_phone, p.email as parent_email, p.address as parent_address, p.relationship as parent_relationship
         FROM children c
         LEFT JOIN classes cl ON c.class_id = cl.id
         LEFT JOIN parents p ON c.parent_id = p.id
         WHERE c.id = ?`,
        [childId]
      );

      if (!child) {
        return res.status(404).json({ error: 'الطفل غير موجود' });
      }

      const canSeeHealth = hasPermission(req.user!.role, 'health.manage');
      const canSeeBehavior = hasPermission(req.user!.role, 'behavior.manage');

      const subscriptions = queryAll(db, 'SELECT * FROM subscriptions WHERE child_id = ? ORDER BY id DESC', [childId]);
      const payments = queryAll(db, 'SELECT * FROM payments WHERE child_id = ? ORDER BY id DESC', [childId]);
      const attendance = queryAll(db, 'SELECT * FROM attendance WHERE child_id = ? ORDER BY date DESC LIMIT 30', [childId]);
      const healthNotes = canSeeHealth
        ? queryAll(db, 'SELECT hn.*, u.name as recorded_by_name FROM health_notes hn LEFT JOIN users u ON hn.recorded_by_user_id = u.id WHERE hn.child_id = ? ORDER BY hn.id DESC', [childId])
        : [];
      const behaviorNotes = canSeeBehavior
        ? queryAll(db, 'SELECT bn.*, u.name as recorded_by_name FROM behavior_notes bn LEFT JOIN users u ON bn.recorded_by_user_id = u.id WHERE bn.child_id = ? ORDER BY bn.id DESC', [childId])
        : [];

      res.json({
        child,
        subscriptions,
        payments,
        attendance,
        healthNotes,
        behaviorNotes,
        canSeeHealth,
        canSeeBehavior,
      });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب ملف الطفل' });
    }
  });

  app.post('/api/children', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const {
        full_name,
        first_name,
        last_name,
        dob,
        gender,
        photo_url,
        parent_id,
        class_id,
        enrollment_date,
        status = 'نشط',
        emergency_contact,
        health_notes,
        allergies,
        general_notes,
      } = req.body;

      if (!full_name || !dob || !gender || !parent_id) {
        return res.status(400).json({ error: 'يرجى إكمال جميع الحقول الأساسية المطلوبة' });
      }

      // Check class capacity if class assigned
      if (class_id) {
        const targetClass = queryOne(db, 'SELECT capacity, current_enrollment, name FROM classes WHERE id = ?', [class_id]);
        if (targetClass && targetClass.current_enrollment >= targetClass.capacity && !req.body.override_capacity) {
          return res.status(400).json({ error: `الفصل (${targetClass.name}) مكتمل السعة (${targetClass.capacity} طفل)` });
        }
      }

      const now = new Date().toISOString();
      const count = (queryOne(db, 'SELECT COUNT(*) as count FROM children')?.count || 0) + 1001;
      const child_number = req.body.child_number || `CH-${count}`;

      executeSql(
        db,
        `INSERT INTO children (child_number, full_name, first_name, last_name, dob, gender, photo_url, parent_id, class_id, enrollment_date, status, emergency_contact, health_notes, allergies, general_notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          child_number,
          full_name,
          first_name || full_name.split(' ')[0] || '',
          last_name || full_name.split(' ').slice(1).join(' ') || '',
          dob,
          gender,
          photo_url || '',
          parent_id,
          class_id || null,
          enrollment_date || new Date().toISOString().split('T')[0],
          status,
          emergency_contact || '',
          health_notes || '',
          allergies || '',
          general_notes || '',
          now,
          now,
        ]
      );

      const newChild = queryOne(db, 'SELECT id FROM children WHERE child_number = ?', [child_number]);

      // Update class current enrollment
      if (class_id && status === 'نشط') {
        executeSql(db, 'UPDATE classes SET current_enrollment = (SELECT COUNT(*) FROM children WHERE class_id = ? AND status = "نشط") WHERE id = ?', [class_id, class_id]);
      }

      logAudit(db, req.user!.id, req.user!.name, 'إضافة طفل', 'الأطفال', newChild?.id, `تمت إضافة الطفل ${full_name}`);

      res.json({ message: 'تم تسجيل الطفل بنجاح', child_id: newChild?.id });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء إضافة الطفل' });
    }
  });

  app.put('/api/children/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const childId = Number(req.params.id);
      const oldChild = queryOne(db, 'SELECT * FROM children WHERE id = ?', [childId]);
      if (!oldChild) {
        return res.status(404).json({ error: 'الطفل غير موجود' });
      }

      const {
        full_name,
        first_name,
        last_name,
        dob,
        gender,
        photo_url,
        parent_id,
        class_id,
        enrollment_date,
        status,
        emergency_contact,
        health_notes,
        allergies,
        general_notes,
      } = req.body;

      const now = new Date().toISOString();

      executeSql(
        db,
        `UPDATE children SET
         full_name = ?, first_name = ?, last_name = ?, dob = ?, gender = ?, photo_url = ?,
         parent_id = ?, class_id = ?, enrollment_date = ?, status = ?, emergency_contact = ?,
         health_notes = ?, allergies = ?, general_notes = ?, updated_at = ?
         WHERE id = ?`,
        [
          full_name,
          first_name,
          last_name,
          dob,
          gender,
          photo_url,
          parent_id,
          class_id || null,
          enrollment_date,
          status,
          emergency_contact,
          health_notes,
          allergies,
          general_notes,
          now,
          childId,
        ]
      );

      // Recalculate enrollment for old and new class
      if (oldChild.class_id) {
        executeSql(db, 'UPDATE classes SET current_enrollment = (SELECT COUNT(*) FROM children WHERE class_id = ? AND status = "نشط") WHERE id = ?', [oldChild.class_id, oldChild.class_id]);
      }
      if (class_id) {
        executeSql(db, 'UPDATE classes SET current_enrollment = (SELECT COUNT(*) FROM children WHERE class_id = ? AND status = "نشط") WHERE id = ?', [class_id, class_id]);
      }

      logAudit(db, req.user!.id, req.user!.name, 'تعديل طفل', 'الأطفال', childId, `تم تحديث بيانات الطفل ${full_name}`);

      res.json({ message: 'تم تحديث بيانات الطفل بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء تحديث بيانات الطفل' });
    }
  });

  app.delete('/api/children/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const childId = Number(req.params.id);
      const child = queryOne(db, 'SELECT * FROM children WHERE id = ?', [childId]);
      if (!child) return res.status(404).json({ error: 'الطفل غير موجود' });

      executeSql(db, "UPDATE children SET status = 'مؤرشف', updated_at = ? WHERE id = ?", [new Date().toISOString(), childId]);

      if (child.class_id) {
        executeSql(db, 'UPDATE classes SET current_enrollment = (SELECT COUNT(*) FROM children WHERE class_id = ? AND status = "نشط") WHERE id = ?', [child.class_id, child.class_id]);
      }

      logAudit(db, req.user!.id, req.user!.name, 'أرشفة طفل', 'الأطفال', childId, `تم أرشفة الطفل ${child.full_name}`);
      res.json({ message: 'تمت أرشفة الطفل بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء أرشفة الطفل' });
    }
  });

  // -------------------------------------------------------------
  // PARENTS MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/parents', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { search } = req.query;
      let sql = `SELECT p.*, (SELECT COUNT(*) FROM children c WHERE c.parent_id = p.id AND c.status != 'مؤرشف') as children_count FROM parents p WHERE 1=1`;
      const params: any[] = [];

      if (search) {
        sql += ` AND (p.full_name LIKE ? OR p.phone LIKE ? OR p.secondary_phone LIKE ? OR p.email LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term, term);
      }

      sql += ` ORDER BY p.id DESC`;
      const parents = queryAll(db, sql, params);
      res.json({ parents });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات أولياء الأمور' });
    }
  });

  app.get('/api/parents/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const parentId = Number(req.params.id);
      const parent = queryOne(db, 'SELECT * FROM parents WHERE id = ?', [parentId]);
      if (!parent) return res.status(404).json({ error: 'ولي الأمر غير موجود' });

      const children = queryAll(db, 'SELECT c.*, cl.name as class_name FROM children c LEFT JOIN classes cl ON c.class_id = cl.id WHERE c.parent_id = ?', [parentId]);
      res.json({ parent, children });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب ملف ولي الأمر' });
    }
  });

  app.post('/api/parents', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { full_name, relationship, phone, secondary_phone, email, address, occupation, emergency_contact, notes } = req.body;
      if (!full_name || !relationship || !phone) {
        return res.status(400).json({ error: 'يرجى إدخال اسم ولي الأمر وصلة القرابة ورقم الهاتف' });
      }

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO parents (full_name, relationship, phone, secondary_phone, email, address, occupation, emergency_contact, notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [full_name, relationship, phone, secondary_phone || '', email || '', address || '', occupation || '', emergency_contact || '', notes || '', now, now]
      );

      const parent = queryOne(db, 'SELECT id FROM parents ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة ولي أمر', 'أولياء الأمور', parent?.id, `تمت إضافة ولي الأمر ${full_name}`);

      res.json({ message: 'تم إضافة ولي الأمر بنجاح', parent_id: parent?.id });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء إضافة ولي الأمر' });
    }
  });

  app.put('/api/parents/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const parentId = Number(req.params.id);
      const { full_name, relationship, phone, secondary_phone, email, address, occupation, emergency_contact, notes } = req.body;

      const now = new Date().toISOString();
      executeSql(
        db,
        `UPDATE parents SET full_name = ?, relationship = ?, phone = ?, secondary_phone = ?, email = ?, address = ?, occupation = ?, emergency_contact = ?, notes = ?, updated_at = ? WHERE id = ?`,
        [full_name, relationship, phone, secondary_phone, email, address, occupation, emergency_contact, notes, now, parentId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل ولي أمر', 'أولياء الأمور', parentId, `تم تحديث بيانات ولي الأمر ${full_name}`);
      res.json({ message: 'تم تحديث بيانات ولي الأمر بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في تحديث بيانات ولي الأمر' });
    }
  });

  app.delete('/api/parents/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const parentId = Number(req.params.id);
      const parent = queryOne(db, 'SELECT * FROM parents WHERE id = ?', [parentId]);
      if (!parent) return res.status(404).json({ error: 'ولي الأمر غير موجود' });

      const childrenCount = queryOne(db, "SELECT COUNT(*) as count FROM children WHERE parent_id = ? AND status != 'مؤرشف'", [parentId])?.count || 0;
      if (childrenCount > 0) {
        return res.status(400).json({ error: `لا يمكن أرشفة ولي الأمر لوجود ${childrenCount} طفل مسجل باسمه` });
      }

      executeSql(db, 'DELETE FROM parents WHERE id = ?', [parentId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف ولي أمر', 'أولياء الأمور', parentId, `تم حذف ملف ولي الأمر ${parent.full_name}`);
      res.json({ message: 'تم حذف ولي الأمر بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء حذف ولي الأمر' });
    }
  });

  // -------------------------------------------------------------
  // CLASSES MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/classes', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const classes = queryAll(
        db,
        `SELECT cl.*, cg.name as caregiver_name, (cl.capacity - cl.current_enrollment) as available_seats
         FROM classes cl
         LEFT JOIN caregivers cg ON cl.assigned_caregiver_id = cg.id
         ORDER BY cl.id ASC`
      );
      res.json({ classes });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات الفصول' });
    }
  });

  app.get('/api/classes/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const classId = Number(req.params.id);
      const classInfo = queryOne(
        db,
        `SELECT cl.*, cg.name as caregiver_name FROM classes cl LEFT JOIN caregivers cg ON cl.assigned_caregiver_id = cg.id WHERE cl.id = ?`,
        [classId]
      );
      if (!classInfo) return res.status(404).json({ error: 'الفصل غير موجود' });

      const children = queryAll(db, `SELECT c.*, p.full_name as parent_name, p.phone as parent_phone FROM children c LEFT JOIN parents p ON c.parent_id = p.id WHERE c.class_id = ? AND c.status = 'نشط'`, [classId]);

      res.json({ classInfo, children });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات الفصل' });
    }
  });

  app.post('/api/classes', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { name, age_group, capacity, assigned_caregiver_id, notes } = req.body;
      if (!name || !age_group || !capacity) {
        return res.status(400).json({ error: 'يرجى تحديد اسم الفصل والفئة العمرية والطاقة الاستيعابية' });
      }

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO classes (name, age_group, capacity, current_enrollment, assigned_caregiver_id, status, notes, created_at, updated_at)
         VALUES (?, ?, ?, 0, ?, 'نشط', ?, ?, ?)`,
        [name, age_group, Number(capacity), assigned_caregiver_id || null, notes || '', now, now]
      );

      const newClass = queryOne(db, 'SELECT id FROM classes ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة فصل', 'الفصول', newClass?.id, `تم إنشاء فصل جديد: ${name}`);

      res.json({ message: 'تم إنشاء الفصل بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في إنشاء الفصل' });
    }
  });

  app.put('/api/classes/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const classId = Number(req.params.id);
      const { name, age_group, capacity, assigned_caregiver_id, status, notes } = req.body;

      const now = new Date().toISOString();
      executeSql(
        db,
        `UPDATE classes SET name = ?, age_group = ?, capacity = ?, assigned_caregiver_id = ?, status = ?, notes = ?, updated_at = ? WHERE id = ?`,
        [name, age_group, Number(capacity), assigned_caregiver_id || null, status, notes, now, classId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل فصل', 'الفصول', classId, `تم تحديث بيانات الفصل ${name}`);
      res.json({ message: 'تم تحديث الفصل بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في تحديث الفصل' });
    }
  });

  app.delete('/api/classes/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const classId = Number(req.params.id);
      const cls = queryOne(db, 'SELECT * FROM classes WHERE id = ?', [classId]);
      if (!cls) return res.status(404).json({ error: 'الفصل غير موجود' });

      const childrenCount = queryOne(db, "SELECT COUNT(*) as count FROM children WHERE class_id = ? AND status = 'نشط'", [classId])?.count || 0;
      if (childrenCount > 0) {
        return res.status(400).json({ error: `لا يمكن أرشفة الفصل لوجود ${childrenCount} طفل مسجلين فيه حالياً` });
      }

      executeSql(db, "UPDATE classes SET status = 'غير نشط', updated_at = ? WHERE id = ?", [new Date().toISOString(), classId]);
      logAudit(db, req.user!.id, req.user!.name, 'أرشفة فصل', 'الفصول', classId, `تم تغيير حالة الفصل ${cls.name} إلى غير نشط`);
      res.json({ message: 'تم تعطيل الفصل بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في أرشفة الفصل' });
    }
  });

  // -------------------------------------------------------------
  // CAREGIVERS / TEACHERS MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/caregivers', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const caregivers = queryAll(
        db,
        `SELECT cg.*, cl.name as assigned_class_name
         FROM caregivers cg
         LEFT JOIN classes cl ON cg.id = cl.assigned_caregiver_id
         ORDER BY cg.id ASC`
      );
      res.json({ caregivers });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات المعلمات' });
    }
  });

  app.post('/api/caregivers', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { name, phone, email, position, notes } = req.body;
      if (!name || !phone || !position) {
        return res.status(400).json({ error: 'يرجى إدخال اسم المعلمة ورقم الهاتف والمسمى الوظيفي' });
      }

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO caregivers (name, phone, email, position, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, 'نشط', ?, ?, ?)`,
        [name, phone, email || '', position, notes || '', now, now]
      );

      const cg = queryOne(db, 'SELECT id FROM caregivers ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة معلمة', 'المعلمات', cg?.id, `تمت إضافة المعلمة ${name}`);

      res.json({ message: 'تمت إضافة المعلمة بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء إضافة المعلمة' });
    }
  });

  app.put('/api/caregivers/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const cgId = Number(req.params.id);
      const { name, phone, email, position, status, notes } = req.body;

      const now = new Date().toISOString();
      executeSql(
        db,
        `UPDATE caregivers SET name = ?, phone = ?, email = ?, position = ?, status = ?, notes = ?, updated_at = ? WHERE id = ?`,
        [name, phone, email, position, status, notes, now, cgId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل معلمة', 'المعلمات', cgId, `تم تحديث بيانات المعلمة ${name}`);
      res.json({ message: 'تم تحديث بيانات المعلمة بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في تحديث بيانات المعلمة' });
    }
  });

  app.delete('/api/caregivers/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const cgId = Number(req.params.id);
      const cg = queryOne(db, 'SELECT * FROM caregivers WHERE id = ?', [cgId]);
      if (!cg) return res.status(404).json({ error: 'المعلمة غير موجودة' });

      executeSql(db, "UPDATE caregivers SET status = 'غير نشط', updated_at = ? WHERE id = ?", [new Date().toISOString(), cgId]);
      logAudit(db, req.user!.id, req.user!.name, 'أرشفة معلمة', 'المعلمات', cgId, `تمت أرشفة المعلمة ${cg.name}`);
      res.json({ message: 'تمت أرشفة المعلمة بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في أرشفة المعلمة' });
    }
  });

  // -------------------------------------------------------------
  // ATTENDANCE MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/attendance', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const date = (req.query.date as string) || new Date().toISOString().split('T')[0];
      const class_id = req.query.class_id ? Number(req.query.class_id) : null;

      let sql = `
        SELECT c.id as child_id, c.child_number, c.full_name, c.photo_url, c.class_id, cl.name as class_name,
               a.id as attendance_id, a.date, COALESCE(a.status, '') as status,
               a.arrival_time, a.departure_time, a.notes
        FROM children c
        JOIN classes cl ON c.class_id = cl.id
        LEFT JOIN attendance a ON c.id = a.child_id AND a.date = ?
        WHERE c.status = 'نشط'
      `;
      const params: any[] = [date];

      if (class_id) {
        sql += ` AND c.class_id = ?`;
        params.push(class_id);
      }

      sql += ` ORDER BY c.full_name ASC`;

      const list = queryAll(db, sql, params);
      res.json({ date, class_id, list });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات كشف الحضور' });
    }
  });

  app.post('/api/attendance', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { date, records } = req.body; // records: Array of { child_id, class_id, status, arrival_time, departure_time, notes }
      if (!date || !Array.isArray(records)) {
        return res.status(400).json({ error: 'بيانات غير مكتملة لتسجيل الحضور' });
      }

      const now = new Date().toISOString();

      records.forEach((rec: any) => {
        if (!rec.child_id || !rec.status) return;

        const existing = queryOne(db, 'SELECT id FROM attendance WHERE child_id = ? AND date = ?', [rec.child_id, date]);

        if (existing) {
          executeSql(
            db,
            `UPDATE attendance SET status = ?, arrival_time = ?, departure_time = ?, notes = ?, recorded_by_user_id = ?, updated_at = ? WHERE id = ?`,
            [rec.status, rec.arrival_time || '', rec.departure_time || '', rec.notes || '', req.user!.id, now, existing.id]
          );
        } else {
          executeSql(
            db,
            `INSERT INTO attendance (child_id, class_id, date, status, arrival_time, departure_time, notes, recorded_by_user_id, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [rec.child_id, rec.class_id, date, rec.status, rec.arrival_time || '', rec.departure_time || '', rec.notes || '', req.user!.id, now, now]
          );
        }
      });

      logAudit(db, req.user!.id, req.user!.name, 'تسجيل حضور', 'الحضور', null, `تم حفظ سجل الحضور والغياب بتاريخ ${date} لعدد ${records.length} طفل`);

      res.json({ message: 'تم حفظ كشف الحضور والغياب بنجاح' });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء حفظ كشف الحضور' });
    }
  });

  // -------------------------------------------------------------
  // SUBSCRIPTIONS & PAYMENTS MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/subscriptions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { status, child_id, search } = req.query;
      let sql = `
        SELECT s.*, c.full_name as child_name, c.child_number, cl.name as class_name, p.full_name as parent_name, p.phone as parent_phone
        FROM subscriptions s
        JOIN children c ON s.child_id = c.id
        LEFT JOIN classes cl ON c.class_id = cl.id
        JOIN parents p ON c.parent_id = p.id
        WHERE 1=1
      `;
      const params: any[] = [];

      if (status) {
        sql += ` AND s.status = ?`;
        params.push(status);
      }

      if (child_id) {
        sql += ` AND s.child_id = ?`;
        params.push(Number(child_id));
      }

      if (search) {
        sql += ` AND (c.full_name LIKE ? OR p.full_name LIKE ? OR p.phone LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term);
      }

      sql += ` ORDER BY s.id DESC`;

      const subscriptions = queryAll(db, sql, params);
      res.json({ subscriptions });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب بيانات الاشتراكات' });
    }
  });

  app.post('/api/subscriptions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { child_id, period_type, start_date, end_date, amount, discount = 0, due_date, notes } = req.body;
      if (!child_id || !period_type || !start_date || !end_date || !amount || !due_date) {
        return res.status(400).json({ error: 'يرجى إكمال جميع الحقول المطلوبة للاشتراك' });
      }

      const final_amount = Number(amount) - Number(discount);
      const now = new Date().toISOString();

      executeSql(
        db,
        `INSERT INTO subscriptions (child_id, period_type, start_date, end_date, amount, discount, final_amount, paid_amount, status, due_date, notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'غير مدفوع', ?, ?, ?, ?)`,
        [child_id, period_type, start_date, end_date, Number(amount), Number(discount), final_amount, due_date, notes || '', now, now]
      );

      const sub = queryOne(db, 'SELECT id FROM subscriptions ORDER BY id DESC LIMIT 1');
      const child = queryOne(db, 'SELECT full_name FROM children WHERE id = ?', [child_id]);

      logAudit(db, req.user!.id, req.user!.name, 'إضافة اشتراك', 'الاشتراكات', sub?.id, `تم إنشاء اشتراك جديد للطفل ${child?.full_name} بمبلغ ${final_amount} ريال`);

      res.json({ message: 'تم إضافة الاشتراك بنجاح', subscription_id: sub?.id });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء تسجيل الاشتراك' });
    }
  });

  app.get('/api/payments', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const payments = queryAll(
        db,
        `SELECT pm.*, c.full_name as child_name, p.full_name as parent_name, u.name as recorded_by_name
         FROM payments pm
         JOIN children c ON pm.child_id = c.id
         JOIN parents p ON pm.parent_id = p.id
         LEFT JOIN users u ON pm.recorded_by_user_id = u.id
         ORDER BY pm.id DESC`
      );
      res.json({ payments });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب سجل المدفوعات' });
    }
  });

  app.post('/api/payments', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { subscription_id, amount, payment_date, payment_method, reference_number, notes } = req.body;
      if (!subscription_id || !amount || !payment_method) {
        return res.status(400).json({ error: 'يرجى اختيار الاشتراك وإدخال المبلغ وطريقة الدفع' });
      }

      const sub = queryOne(db, 'SELECT * FROM subscriptions WHERE id = ?', [subscription_id]);
      if (!sub) return res.status(404).json({ error: 'الاشتراك غير موجود' });

      const child = queryOne(db, 'SELECT * FROM children WHERE id = ?', [sub.child_id]);
      if (!child) return res.status(404).json({ error: 'الطفل المتربط بالاشتراك غير موجود' });

      const payAmount = Number(amount);
      const newPaidTotal = sub.paid_amount + payAmount;
      let newStatus = 'مدفوع جزئياً';

      if (newPaidTotal >= sub.final_amount) {
        newStatus = 'مدفوع';
      } else if (newPaidTotal === 0) {
        newStatus = 'غير مدفوع';
      }

      const now = new Date().toISOString();

      // Record payment
      executeSql(
        db,
        `INSERT INTO payments (subscription_id, child_id, parent_id, amount, payment_date, payment_method, reference_number, notes, recorded_by_user_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [subscription_id, sub.child_id, child.parent_id, payAmount, payment_date || new Date().toISOString().split('T')[0], payment_method, reference_number || '', notes || '', req.user!.id, now]
      );

      // Update subscription status and paid amount
      executeSql(
        db,
        `UPDATE subscriptions SET paid_amount = ?, status = ?, updated_at = ? WHERE id = ?`,
        [newPaidTotal, newStatus, now, subscription_id]
      );

      const payRec = queryOne(db, 'SELECT id FROM payments ORDER BY id DESC LIMIT 1');
      if (payRec?.id) {
        const desc = `سداد اشتراك للطفل: ${child.full_name} (سند: ${reference_number || payRec.id})`;
        executeSql(
          db,
          `INSERT INTO treasury_transactions (transaction_date, type, amount, category, description, payment_method, reference_number, payment_id, recorded_by_user_id, status, notes, created_at, updated_at)
           VALUES (?, 'دخل', ?, 'رسوم اشتراكات الروضة', ?, ?, ?, ?, ?, 'مؤكد', ?, ?, ?)`,
          [payment_date || new Date().toISOString().split('T')[0], payAmount, desc, payment_method, reference_number || '', payRec.id, req.user!.id, notes || '', now, now]
        );
      }

      logAudit(db, req.user!.id, req.user!.name, 'تسجيل دفعة', 'المدفوعات', payRec?.id, `تم استلام دفعة بمبلغ ${payAmount} ريال للطفل ${child.full_name}`);

      res.json({ message: 'تم تسديد الدفعة بنجاح', status: newStatus, remaining: Math.max(0, sub.final_amount - newPaidTotal) });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء تسجيل عملية الدفع' });
    }
  });

  app.put('/api/payments/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const paymentId = Number(req.params.id);
      const { amount, payment_date, payment_method, reference_number, notes } = req.body;

      const oldPayment = queryOne(db, 'SELECT * FROM payments WHERE id = ?', [paymentId]);
      if (!oldPayment) {
        return res.status(404).json({ error: 'سند القبض غير موجود' });
      }

      const sub = queryOne(db, 'SELECT * FROM subscriptions WHERE id = ?', [oldPayment.subscription_id]);
      if (!sub) {
        return res.status(404).json({ error: 'الاشتراك المرتبط غير موجود' });
      }

      const newAmount = Number(amount);
      const diff = newAmount - oldPayment.amount;
      const newPaidTotal = sub.paid_amount + diff;
      let newStatus = 'مدفوع جزئياً';

      if (newPaidTotal >= sub.final_amount) {
        newStatus = 'مدفوع';
      } else if (newPaidTotal <= 0) {
        newStatus = 'غير مدفوع';
      }

      const now = new Date().toISOString();

      // Update payment
      executeSql(
        db,
        `UPDATE payments SET amount = ?, payment_date = ?, payment_method = ?, reference_number = ?, notes = ? WHERE id = ?`,
        [newAmount, payment_date || oldPayment.payment_date, payment_method || oldPayment.payment_method, reference_number || '', notes || '', paymentId]
      );

      // Update subscription
      executeSql(
        db,
        `UPDATE subscriptions SET paid_amount = ?, status = ?, updated_at = ? WHERE id = ?`,
        [newPaidTotal, newStatus, now, sub.id]
      );

      // Update treasury transaction if exists
      executeSql(
        db,
        `UPDATE treasury_transactions SET amount = ?, transaction_date = ?, payment_method = ?, reference_number = ?, notes = ?, updated_at = ? WHERE payment_id = ?`,
        [newAmount, payment_date || oldPayment.payment_date, payment_method || oldPayment.payment_method, reference_number || '', notes || '', now, paymentId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل دفعة', 'المدفوعات', paymentId, `تم تعديل سند القبض #${paymentId} بقيمة ${newAmount}`);

      res.json({ message: 'تم تعديل سند القبض بنجاح' });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء تعديل سند القبض' });
    }
  });

  // -------------------------------------------------------------
  // HEALTH & BEHAVIORAL NOTES
  // -------------------------------------------------------------
  app.get('/api/health-notes', authenticateToken, authorizePermission('health.manage'), (req: AuthRequest, res: Response) => {
    try {
      const child_id = req.query.child_id ? Number(req.query.child_id) : null;
      const note_type = req.query.note_type ? String(req.query.note_type) : null;
      const search = req.query.search ? String(req.query.search).trim() : null;

      let sql = `
        SELECT hn.*, c.full_name as child_name, c.child_number, u.name as recorded_by_name
        FROM health_notes hn
        JOIN children c ON hn.child_id = c.id
        LEFT JOIN users u ON hn.recorded_by_user_id = u.id
        WHERE 1=1
      `;
      const params: any[] = [];
      if (child_id) {
        sql += ` AND hn.child_id = ?`;
        params.push(child_id);
      }
      if (note_type) {
        sql += ` AND hn.note_type = ?`;
        params.push(note_type);
      }
      if (search) {
        sql += ` AND (c.full_name LIKE ? OR hn.description LIKE ? OR hn.medication_info LIKE ? OR hn.additional_notes LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term, term);
      }
      sql += ` ORDER BY hn.id DESC`;

      const notes = queryAll(db, sql, params);
      res.json({ notes });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب الملاحظات الصحية' });
    }
  });

  app.post('/api/health-notes', authenticateToken, authorizePermission('health.manage'), (req: AuthRequest, res: Response) => {
    try {
      const { child_id, date, note_type, description, medication_info, additional_notes } = req.body;
      if (!child_id || !note_type || !description) {
        return res.status(400).json({ error: 'يرجى تحديد الطفل ونوع الملاحظة والوصف' });
      }

      const child = queryOne(db, 'SELECT full_name FROM children WHERE id = ?', [child_id]);
      if (!child) return res.status(404).json({ error: 'الطفل المرتبط غير موجود' });

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO health_notes (child_id, date, note_type, description, medication_info, additional_notes, recorded_by_user_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [child_id, date || new Date().toISOString().split('T')[0], note_type, description, medication_info || '', additional_notes || '', req.user!.id, now]
      );

      const newRec = queryOne(db, 'SELECT id FROM health_notes ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة ملاحظة صحية', 'الملاحظات الصحية', newRec?.id, `تم تسجيل ملاحظة صحية للطفل ${child.full_name} (${note_type})`);
      res.json({ message: 'تم تسجيل الملاحظة الصحية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حفظ الملاحظة الصحية' });
    }
  });

  app.put('/api/health-notes/:id', authenticateToken, authorizePermission('health.manage'), (req: AuthRequest, res: Response) => {
    try {
      const noteId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM health_notes WHERE id = ?', [noteId]);
      if (!existing) return res.status(404).json({ error: 'الملاحظة الصحية غير موجودة' });

      const { note_type, description, medication_info, additional_notes, date } = req.body;
      if (!note_type || !description) {
        return res.status(400).json({ error: 'يرجى توفير نوع الملاحظة ووصف الحالة' });
      }

      executeSql(
        db,
        `UPDATE health_notes SET note_type = ?, description = ?, medication_info = ?, additional_notes = ?, date = ? WHERE id = ?`,
        [note_type, description, medication_info || '', additional_notes || '', date || existing.date, noteId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل ملاحظة صحية', 'الملاحظات الصحية', noteId, `تم تحديث الملاحظة الصحية رقم ${noteId}`);
      res.json({ message: 'تم تحديث الملاحظة الصحية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في تحديث الملاحظة الصحية' });
    }
  });

  app.delete('/api/health-notes/:id', authenticateToken, authorizePermission('health.manage'), (req: AuthRequest, res: Response) => {
    try {
      const noteId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM health_notes WHERE id = ?', [noteId]);
      if (!existing) return res.status(404).json({ error: 'الملاحظة الصحية غير موجودة' });

      executeSql(db, 'DELETE FROM health_notes WHERE id = ?', [noteId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف ملاحظة صحية', 'الملاحظات الصحية', noteId, `تم حذف الملاحظة الصحية رقم ${noteId}`);
      res.json({ message: 'تم حذف الملاحظة الصحية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حذف الملاحظة الصحية' });
    }
  });

  app.get('/api/behavior-notes', authenticateToken, authorizePermission('behavior.manage'), (req: AuthRequest, res: Response) => {
    try {
      const child_id = req.query.child_id ? Number(req.query.child_id) : null;
      const observation_type = req.query.observation_type ? String(req.query.observation_type) : null;
      const search = req.query.search ? String(req.query.search).trim() : null;

      let sql = `
        SELECT bn.*, c.full_name as child_name, c.child_number, u.name as recorded_by_name
        FROM behavior_notes bn
        JOIN children c ON bn.child_id = c.id
        LEFT JOIN users u ON bn.recorded_by_user_id = u.id
        WHERE 1=1
      `;
      const params: any[] = [];
      if (child_id) {
        sql += ` AND bn.child_id = ?`;
        params.push(child_id);
      }
      if (observation_type) {
        sql += ` AND bn.observation_type = ?`;
        params.push(observation_type);
      }
      if (search) {
        sql += ` AND (c.full_name LIKE ? OR bn.description LIKE ? OR bn.follow_up LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term);
      }
      sql += ` ORDER BY bn.id DESC`;

      const notes = queryAll(db, sql, params);
      res.json({ notes });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب الملاحظات السلوكية' });
    }
  });

  app.post('/api/behavior-notes', authenticateToken, authorizePermission('behavior.manage'), (req: AuthRequest, res: Response) => {
    try {
      const { child_id, date, observation_type, description, follow_up } = req.body;
      if (!child_id || !observation_type || !description) {
        return res.status(400).json({ error: 'يرجى تحديد الطفل ونوع التقييم والوصف' });
      }

      const child = queryOne(db, 'SELECT full_name FROM children WHERE id = ?', [child_id]);
      if (!child) return res.status(404).json({ error: 'الطفل المرتبط غير موجود' });

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO behavior_notes (child_id, date, observation_type, description, follow_up, recorded_by_user_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [child_id, date || new Date().toISOString().split('T')[0], observation_type, description, follow_up || '', req.user!.id, now]
      );

      const newRec = queryOne(db, 'SELECT id FROM behavior_notes ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة ملاحظة سلوكية', 'الملاحظات السلوكية', newRec?.id, `تم تسجيل ملاحظة سلوكية للطفل ${child.full_name} (${observation_type})`);
      res.json({ message: 'تم تسجيل الملاحظة السلوكية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حفظ الملاحظة السلوكية' });
    }
  });

  app.put('/api/behavior-notes/:id', authenticateToken, authorizePermission('behavior.manage'), (req: AuthRequest, res: Response) => {
    try {
      const noteId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM behavior_notes WHERE id = ?', [noteId]);
      if (!existing) return res.status(404).json({ error: 'الملاحظة السلوكية غير موجودة' });

      const { observation_type, description, follow_up, date } = req.body;
      if (!observation_type || !description) {
        return res.status(400).json({ error: 'يرجى توفير نوع التقييم ووصف السلوك' });
      }

      executeSql(
        db,
        `UPDATE behavior_notes SET observation_type = ?, description = ?, follow_up = ?, date = ? WHERE id = ?`,
        [observation_type, description, follow_up || '', date || existing.date, noteId]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل ملاحظة سلوكية', 'الملاحظات السلوكية', noteId, `تم تحديث الملاحظة السلوكية رقم ${noteId}`);
      res.json({ message: 'تم تحديث الملاحظة السلوكية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في تحديث الملاحظة السلوكية' });
    }
  });

  app.delete('/api/behavior-notes/:id', authenticateToken, authorizePermission('behavior.manage'), (req: AuthRequest, res: Response) => {
    try {
      const noteId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM behavior_notes WHERE id = ?', [noteId]);
      if (!existing) return res.status(404).json({ error: 'الملاحظة السلوكية غير موجودة' });

      executeSql(db, 'DELETE FROM behavior_notes WHERE id = ?', [noteId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف ملاحظة سلوكية', 'الملاحظات السلوكية', noteId, `تم حذف الملاحظة السلوكية رقم ${noteId}`);
      res.json({ message: 'تم حذف الملاحظة السلوكية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حذف الملاحظة السلوكية' });
    }
  });

  // -------------------------------------------------------------
  // MEAL SCHEDULE API
  // -------------------------------------------------------------
  app.get('/api/meals', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const date = req.query.date ? String(req.query.date) : null;
      const start_date = req.query.start_date ? String(req.query.start_date) : null;
      const end_date = req.query.end_date ? String(req.query.end_date) : null;
      const meal_type = req.query.meal_type ? String(req.query.meal_type) : null;
      const status = req.query.status ? String(req.query.status) : null;

      let sql = `
        SELECT ms.*, u.name as created_by_name
        FROM meal_schedules ms
        LEFT JOIN users u ON ms.created_by_user_id = u.id
        WHERE 1=1
      `;
      const params: any[] = [];

      if (date) {
        sql += ` AND ms.date = ?`;
        params.push(date);
      }
      if (start_date && end_date) {
        sql += ` AND ms.date BETWEEN ? AND ?`;
        params.push(start_date, end_date);
      }
      if (meal_type) {
        sql += ` AND ms.meal_type = ?`;
        params.push(meal_type);
      }
      if (status) {
        sql += ` AND ms.status = ?`;
        params.push(status);
      }

      sql += ` ORDER BY ms.date ASC, ms.id ASC`;

      const meals = queryAll(db, sql, params);
      res.json({ meals });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب جدول الوجبات' });
    }
  });

  app.get('/api/meals/weekly', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const refDateStr = req.query.date ? String(req.query.date) : new Date().toISOString().split('T')[0];
      const refDate = new Date(refDateStr);

      const dayOfWeek = refDate.getDay();
      const diffToSaturday = (dayOfWeek + 1) % 7;
      const saturday = new Date(refDate);
      saturday.setDate(refDate.getDate() - diffToSaturday);

      const daysOfWeek: { date: string; day_name: string }[] = [];
      const arabicDays = ['السبت', 'الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة'];

      for (let i = 0; i < 7; i++) {
        const d = new Date(saturday);
        d.setDate(saturday.getDate() + i);
        daysOfWeek.push({
          date: d.toISOString().split('T')[0],
          day_name: arabicDays[i],
        });
      }

      const startDate = daysOfWeek[0].date;
      const endDate = daysOfWeek[6].date;

      const meals = queryAll(
        db,
        `SELECT ms.*, u.name as created_by_name
         FROM meal_schedules ms
         LEFT JOIN users u ON ms.created_by_user_id = u.id
         WHERE ms.date BETWEEN ? AND ?
         ORDER BY ms.date ASC, ms.id ASC`,
        [startDate, endDate]
      );

      const allergyChildren = queryAll(
        db,
        `SELECT id, full_name, allergies, health_notes
         FROM children
         WHERE status = 'نشط' AND (allergies IS NOT NULL AND allergies != '' AND allergies != 'لا يوجد')`
      );

      res.json({
        startDate,
        endDate,
        days: daysOfWeek,
        meals,
        allergyChildren,
      });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب جدول الوجبات الأسبوعي' });
    }
  });

  app.get('/api/meals/allergies-summary', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const childrenWithAllergies = queryAll(
        db,
        `SELECT c.id, c.full_name, c.allergies, c.health_notes, cl.name as class_name
         FROM children c
         LEFT JOIN classes cl ON c.class_id = cl.id
         WHERE c.status = 'نشط' AND (c.allergies IS NOT NULL AND c.allergies != '' AND c.allergies != 'لا يوجد')`
      );

      const healthNoteAllergies = queryAll(
        db,
        `SELECT hn.*, c.full_name as child_name, cl.name as class_name
         FROM health_notes hn
         JOIN children c ON hn.child_id = c.id
         LEFT JOIN classes cl ON c.class_id = cl.id
         WHERE hn.note_type = 'حساسية'`
      );

      res.json({ childrenWithAllergies, healthNoteAllergies });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب تقرير الحساسية الغذائية' });
    }
  });

  app.post('/api/meals', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { date, meal_type, meal_name, description, ingredients, side_dish, dessert_fruit, drink, notes, status } = req.body;
      if (!date || !meal_type || !meal_name) {
        return res.status(400).json({ error: 'يرجى إدخال التاريخ ونوع الوجبة واسم الوجبة' });
      }

      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO meal_schedules (date, meal_type, meal_name, description, ingredients, side_dish, dessert_fruit, drink, notes, status, created_by_user_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          date,
          meal_type,
          meal_name,
          description || '',
          ingredients || '',
          side_dish || '',
          dessert_fruit || '',
          drink || '',
          notes || '',
          status || 'مخطط',
          req.user!.id,
          now,
          now,
        ]
      );

      const newMeal = queryOne(db, 'SELECT id FROM meal_schedules ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة وجبة', 'جدول الإطعام', newMeal?.id, `تم إضافة وجبة (${meal_name}) بتاريخ ${date}`);

      res.json({ message: 'تم إضافة الوجبة بنجاح', id: newMeal?.id });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء إضافة الوجبة' });
    }
  });

  app.put('/api/meals/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const mealId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM meal_schedules WHERE id = ?', [mealId]);
      if (!existing) return res.status(404).json({ error: 'الوجبة غير موجودة' });

      const { date, meal_type, meal_name, description, ingredients, side_dish, dessert_fruit, drink, notes, status } = req.body;
      if (!date || !meal_type || !meal_name) {
        return res.status(400).json({ error: 'يرجى إدخال التاريخ ونوع الوجبة واسم الوجبة' });
      }

      const now = new Date().toISOString();
      executeSql(
        db,
        `UPDATE meal_schedules
         SET date = ?, meal_type = ?, meal_name = ?, description = ?, ingredients = ?, side_dish = ?, dessert_fruit = ?, drink = ?, notes = ?, status = ?, updated_at = ?
         WHERE id = ?`,
        [
          date,
          meal_type,
          meal_name,
          description || '',
          ingredients || '',
          side_dish || '',
          dessert_fruit || '',
          drink || '',
          notes || '',
          status || existing.status,
          now,
          mealId,
        ]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل وجبة', 'جدول الإطعام', mealId, `تم تحديث بيانات الوجبة (${meal_name})`);
      res.json({ message: 'تم تحديث الوجبة بنجاح' });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء تحديث الوجبة' });
    }
  });

  app.delete('/api/meals/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const mealId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM meal_schedules WHERE id = ?', [mealId]);
      if (!existing) return res.status(404).json({ error: 'الوجبة غير موجودة' });

      executeSql(db, 'DELETE FROM meal_schedules WHERE id = ?', [mealId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف وجبة', 'جدول الإطعام', mealId, `تم حذف الوجبة (${existing.meal_name})`);
      res.json({ message: 'تم حذف الوجبة بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء حذف الوجبة' });
    }
  });

  // -------------------------------------------------------------
  // KINDERGARTEN EVENTS / CALENDAR API
  // -------------------------------------------------------------
  app.get('/api/events', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const events = queryAll(db, 'SELECT e.*, u.name as created_by_name FROM kindergarten_events e LEFT JOIN users u ON e.created_by_user_id = u.id ORDER BY e.event_date ASC');
      res.json(events);
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب الفعاليات والمناسبات' });
    }
  });

  app.post('/api/events', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { title, description, event_date, category, target_role } = req.body;
      if (!title || !event_date || !category) {
        return res.status(400).json({ error: 'يرجى إدخال عنوان الحدث والتاريخ والفئة' });
      }
      const now = new Date().toISOString();
      executeSql(
        db,
        `INSERT INTO kindergarten_events (title, description, event_date, category, target_role, created_by_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [title, description || '', event_date, category, target_role || 'all', req.user!.id, now]
      );
      const newEvent = queryOne(db, 'SELECT id FROM kindergarten_events ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, 'إضافة فعالية', 'التقويم', newEvent?.id, `تم إضافة الحدث: ${title} (${event_date})`);
      res.json({ message: 'تم إضافة الحدث بنجاح', id: newEvent?.id });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في إضافة الحدث' });
    }
  });

  app.delete('/api/events/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const eventId = Number(req.params.id);
      const event = queryOne(db, 'SELECT * FROM kindergarten_events WHERE id = ?', [eventId]);
      if (!event) {
        return res.status(404).json({ error: 'الحدث غير موجود' });
      }
      executeSql(db, 'DELETE FROM kindergarten_events WHERE id = ?', [eventId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف فعالية', 'التقويم', eventId, `تم حذف الحدث: ${event.title}`);
      res.json({ message: 'تم حذف الحدث بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في حذف الحدث' });
    }
  });

  // -------------------------------------------------------------
  // TREASURY / CASH MANAGEMENT API
  // -------------------------------------------------------------
  app.get('/api/treasury/stats', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const today = new Date().toISOString().split('T')[0];
      const currentMonthStr = today.substring(0, 7);

      const totalIncomeRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد'");
      const totalExpenseRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد'");

      const todayIncomeRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد' AND transaction_date = ?", [today]);
      const todayExpenseRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد' AND transaction_date = ?", [today]);

      const monthIncomeRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد' AND transaction_date LIKE ?", [`${currentMonthStr}%`]);
      const monthExpenseRes = queryOne(db, "SELECT COALESCE(SUM(amount), 0) as total FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد' AND transaction_date LIKE ?", [`${currentMonthStr}%`]);

      const outstandingRes = queryOne(
        db,
        "SELECT COALESCE(SUM(final_amount - paid_amount), 0) as total FROM subscriptions WHERE status IN ('متأخر', 'غير مدفوع', 'مدفوع جزئياً')"
      );

      const incomeByCategory = queryAll(
        db,
        `SELECT category, COALESCE(SUM(amount), 0) as amount FROM treasury_transactions WHERE type = 'دخل' AND status = 'مؤكد' GROUP BY category`
      );

      const expensesByCategory = queryAll(
        db,
        `SELECT category, COALESCE(SUM(amount), 0) as amount FROM treasury_transactions WHERE type = 'صرف' AND status = 'مؤكد' GROUP BY category`
      );

      const totalInc = totalIncomeRes?.total || 0;
      const totalExp = totalExpenseRes?.total || 0;
      const currentBalance = totalInc - totalExp;

      res.json({
        currentBalance,
        todayIncome: todayIncomeRes?.total || 0,
        todayExpenses: todayExpenseRes?.total || 0,
        monthIncome: monthIncomeRes?.total || 0,
        monthExpenses: monthExpenseRes?.total || 0,
        netBalance: currentBalance,
        outstandingPayments: outstandingRes?.total || 0,
        incomeByCategory,
        expensesByCategory,
      });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ في جلب إحصائيات الخزينة' });
    }
  });

  app.get('/api/treasury/transactions', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const search = req.query.search ? String(req.query.search).trim() : null;
      const type = req.query.type ? String(req.query.type) : null;
      const category = req.query.category ? String(req.query.category) : null;
      const payment_method = req.query.payment_method ? String(req.query.payment_method) : null;
      const date_from = req.query.date_from ? String(req.query.date_from) : null;
      const date_to = req.query.date_to ? String(req.query.date_to) : null;

      let sql = `
        SELECT tt.*, u.name as recorded_by_name
        FROM treasury_transactions tt
        LEFT JOIN users u ON tt.recorded_by_user_id = u.id
        WHERE 1=1
      `;
      const params: any[] = [];

      if (type && type !== 'الكل') {
        sql += ` AND tt.type = ?`;
        params.push(type);
      }
      if (category && category !== 'الكل') {
        sql += ` AND tt.category = ?`;
        params.push(category);
      }
      if (payment_method && payment_method !== 'الكل') {
        sql += ` AND tt.payment_method = ?`;
        params.push(payment_method);
      }
      if (date_from && date_to) {
        sql += ` AND tt.transaction_date BETWEEN ? AND ?`;
        params.push(date_from, date_to);
      } else if (date_from) {
        sql += ` AND tt.transaction_date >= ?`;
        params.push(date_from);
      } else if (date_to) {
        sql += ` AND tt.transaction_date <= ?`;
        params.push(date_to);
      }
      if (search) {
        sql += ` AND (tt.description LIKE ? OR tt.category LIKE ? OR tt.reference_number LIKE ? OR tt.notes LIKE ?)`;
        const term = `%${search}%`;
        params.push(term, term, term, term);
      }

      sql += ` ORDER BY tt.transaction_date DESC, tt.id DESC`;

      const transactions = queryAll(db, sql, params);
      res.json({ transactions });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ في جلب معاملات الخزينة' });
    }
  });

  app.post('/api/treasury/transactions', authenticateToken, authorizePermission('financial.manage'), (req: AuthRequest, res: Response) => {
    try {
      const { transaction_date, type, amount, category, description, payment_method, reference_number, notes } = req.body;
      if (!type || !amount || !category || !description) {
        return res.status(400).json({ error: 'يرجى إدخال النوع، المبلغ، التصنيف، ووصف المعاملة' });
      }

      const numAmount = Number(amount);
      if (isNaN(numAmount) || numAmount <= 0) {
        return res.status(400).json({ error: 'يرجى إدخال مبلغ صحيح أكبر من 0' });
      }

      const now = new Date().toISOString();
      const txDate = transaction_date || new Date().toISOString().split('T')[0];

      executeSql(
        db,
        `INSERT INTO treasury_transactions (transaction_date, type, amount, category, description, payment_method, reference_number, recorded_by_user_id, status, notes, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'مؤكد', ?, ?, ?)`,
        [
          txDate,
          type,
          numAmount,
          category,
          description,
          payment_method || 'نقداً',
          reference_number || '',
          req.user!.id,
          notes || '',
          now,
          now,
        ]
      );

      const newTx = queryOne(db, 'SELECT id FROM treasury_transactions ORDER BY id DESC LIMIT 1');
      logAudit(db, req.user!.id, req.user!.name, `تسجيل ${type}`, 'الخزينة', newTx?.id, `تم تسجيل عملية ${type} بمبلغ ${numAmount} - ${description}`);

      res.json({ message: 'تم تسجيل المعاملة بنجاح', id: newTx?.id });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء إضافة معاملة الخزينة' });
    }
  });

  app.put('/api/treasury/transactions/:id', authenticateToken, authorizePermission('financial.manage'), (req: AuthRequest, res: Response) => {
    try {
      const txId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM treasury_transactions WHERE id = ?', [txId]);
      if (!existing) return res.status(404).json({ error: 'معاملة الخزينة غير موجودة' });

      const { transaction_date, type, amount, category, description, payment_method, reference_number, notes, status } = req.body;
      if (!type || !amount || !category || !description) {
        return res.status(400).json({ error: 'يرجى إدخال البيانات الرئيسية للمعاملة' });
      }

      const numAmount = Number(amount);
      const now = new Date().toISOString();

      executeSql(
        db,
        `UPDATE treasury_transactions
         SET transaction_date = ?, type = ?, amount = ?, category = ?, description = ?, payment_method = ?, reference_number = ?, notes = ?, status = ?, updated_at = ?
         WHERE id = ?`,
        [
          transaction_date || existing.transaction_date,
          type,
          numAmount,
          category,
          description,
          payment_method || existing.payment_method,
          reference_number || '',
          notes || '',
          status || existing.status,
          now,
          txId,
        ]
      );

      logAudit(db, req.user!.id, req.user!.name, 'تعديل معاملة خزينة', 'الخزينة', txId, `تم تعديل معاملة الخزينة رقم ${txId}`);
      res.json({ message: 'تم تحديث المعاملة بنجاح' });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء تعديل المعاملة' });
    }
  });

  app.delete('/api/treasury/transactions/:id', authenticateToken, authorizePermission('financial.manage'), (req: AuthRequest, res: Response) => {
    try {
      const txId = Number(req.params.id);
      const existing = queryOne(db, 'SELECT * FROM treasury_transactions WHERE id = ?', [txId]);
      if (!existing) return res.status(404).json({ error: 'المعاملة غير موجودة' });

      executeSql(db, "UPDATE treasury_transactions SET status = 'ملغى', updated_at = ? WHERE id = ?", [new Date().toISOString(), txId]);

      logAudit(db, req.user!.id, req.user!.name, 'إلغاء معاملة خزينة', 'الخزينة', txId, `تم إلغاء/إبطال معاملة الخزينة رقم ${txId}`);
      res.json({ message: 'تم إلغاء المعاملة المالية بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في إلغاء المعاملة' });
    }
  });

  app.get('/api/treasury/reports', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const today = new Date().toISOString().split('T')[0];
      const monthStr = today.substring(0, 7);

      const dailyTransactions = queryAll(
        db,
        `SELECT tt.*, u.name as recorded_by_name
         FROM treasury_transactions tt
         LEFT JOIN users u ON tt.recorded_by_user_id = u.id
         WHERE tt.transaction_date = ? AND tt.status = 'مؤكد'
         ORDER BY tt.id ASC`,
        [today]
      );

      const monthlyTransactions = queryAll(
        db,
        `SELECT tt.*, u.name as recorded_by_name
         FROM treasury_transactions tt
         LEFT JOIN users u ON tt.recorded_by_user_id = u.id
         WHERE tt.transaction_date LIKE ? AND tt.status = 'مؤكد'
         ORDER BY tt.transaction_date ASC, tt.id ASC`,
        [`${monthStr}%`]
      );

      res.json({ dailyTransactions, monthlyTransactions });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب تقارير الخزينة' });
    }
  });

  // -------------------------------------------------------------
  // USERS & AUDIT LOGS
  // -------------------------------------------------------------
  app.get('/api/users', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const users = queryAll(db, 'SELECT id, email, name, role, is_active, created_at FROM users ORDER BY id ASC');
      res.json({ users });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب قائمة المستخدمين' });
    }
  });

  app.post('/api/users', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { email, password, name, role } = req.body;
      if (!email || !password || !name || !role) {
        return res.status(400).json({ error: 'يرجى إكمال جميع الحقول' });
      }

      const hash = bcrypt.hashSync(password, 10);
      const now = new Date().toISOString();

      executeSql(
        db,
        `INSERT INTO users (email, password_hash, name, role, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)`,
        [email, hash, name, role, now, now]
      );

      logAudit(db, req.user!.id, req.user!.name, 'إضافة مستخدم', 'المستخدمين', null, `تم إضافة حساب جديد (${name}) بصلاحية ${role}`);
      res.json({ message: 'تمت إضافة الحساب بنجاح' });
    } catch (err: any) {
      res.status(500).json({ error: 'خطأ في إضافة حساب مستخدم جديد (قد يكون البريد مسجلاً مسبقاً)' });
    }
  });

  app.put('/api/users/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const userId = Number(req.params.id);
      const { name, email, role, is_active, password } = req.body;

      const existingUser = queryOne(db, 'SELECT * FROM users WHERE id = ?', [userId]);
      if (!existingUser) {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }

      if (!name || !email || !role) {
        return res.status(400).json({ error: 'يرجى توفير الاسم والبريد الإلكتروني والدور' });
      }

      const emailCheck = queryOne(db, 'SELECT id FROM users WHERE email = ? AND id != ?', [email, userId]);
      if (emailCheck) {
        return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل لحساب آخر' });
      }

      const now = new Date().toISOString();
      const activeStatus = is_active !== undefined ? (is_active ? 1 : 0) : existingUser.is_active;

      if (password && typeof password === 'string' && password.trim().length > 0) {
        const hash = bcrypt.hashSync(password.trim(), 10);
        executeSql(
          db,
          `UPDATE users SET name = ?, email = ?, role = ?, is_active = ?, password_hash = ?, updated_at = ? WHERE id = ?`,
          [name, email, role, activeStatus, hash, now, userId]
        );
      } else {
        executeSql(
          db,
          `UPDATE users SET name = ?, email = ?, role = ?, is_active = ?, updated_at = ? WHERE id = ?`,
          [name, email, role, activeStatus, now, userId]
        );
      }

      logAudit(db, req.user!.id, req.user!.name, 'تعديل حساب مستخدم', 'المستخدمين', userId, `تم تعديل بيانات الحساب (${name})`);
      res.json({ message: 'تم تحديث حساب المستخدم بنجاح' });
    } catch (err: any) {
      console.error(err);
      res.status(500).json({ error: 'خطأ أثناء تحديث بيانات الحساب' });
    }
  });

  app.delete('/api/users/:id', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const userId = Number(req.params.id);
      if (req.user!.id === userId) {
        return res.status(400).json({ error: 'لا يمكن حذف الحساب النشط الذي تسجل منه حالياً' });
      }

      const existingUser = queryOne(db, 'SELECT * FROM users WHERE id = ?', [userId]);
      if (!existingUser) {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }

      executeSql(db, 'DELETE FROM users WHERE id = ?', [userId]);
      logAudit(db, req.user!.id, req.user!.name, 'حذف حساب مستخدم', 'المستخدمين', userId, `تم حذف حساب المستخدم (${existingUser.name})`);
      res.json({ message: 'تم حذف حساب المستخدم بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء حذف حساب المستخدم' });
    }
  });

  app.get('/api/audit-logs', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const logs = queryAll(db, 'SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100');
      res.json({ logs });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب سجل العمليات' });
    }
  });

  // -------------------------------------------------------------
  // ROLES & PERMISSIONS MANAGEMENT
  // -------------------------------------------------------------
  app.get('/api/roles', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const roles = queryAll(db, 'SELECT * FROM roles ORDER BY id ASC');
      const allRolePerms = queryAll(db, 'SELECT * FROM role_permissions');

      const rolesWithPerms = roles.map((r: any) => ({
        ...r,
        permissions: allRolePerms.filter((rp: any) => rp.role === r.name).map((rp: any) => rp.permission_code),
      }));

      res.json({ roles: rolesWithPerms });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب قائمة الأدوار' });
    }
  });

  app.get('/api/permissions', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const permissions = queryAll(db, 'SELECT * FROM permissions ORDER BY module ASC, id ASC');
      res.json({ permissions });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب قائمة الصلاحيات' });
    }
  });

  app.put('/api/roles/:role/permissions', authenticateToken, authorizeRoles('admin'), (req: AuthRequest, res: Response) => {
    try {
      const { role } = req.params;
      const { permissions } = req.body;

      if (!Array.isArray(permissions)) {
        return res.status(400).json({ error: 'قائمة الصلاحيات غير صحيحة' });
      }

      executeSql(db, 'DELETE FROM role_permissions WHERE role = ?', [role]);

      permissions.forEach((code: string) => {
        executeSql(db, 'INSERT INTO role_permissions (role, permission_code) VALUES (?, ?)', [role, code]);
      });

      logAudit(db, req.user!.id, req.user!.name, 'تعديل صلاحيات دور', 'الصلاحيات', null, `تم تحديث صلاحيات الدور (${role})`);
      res.json({ message: 'تم تحديث صلاحيات الدور بنجاح' });
    } catch (err) {
      res.status(500).json({ error: 'خطأ أثناء تحديث صلاحيات الدور' });
    }
  });

  // -------------------------------------------------------------
  // REPORTS API
  // -------------------------------------------------------------
  app.get('/api/reports/query', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const type = String(req.query.type || 'children');
      const { startDate, endDate, class_id, child_id, parent_id, status } = req.query;

      let records: any[] = [];
      let summary: any = {};

      if (type === 'children') {
        let sql = `
          SELECT c.*, cl.name as class_name, p.full_name as parent_name, p.phone as parent_phone
          FROM children c
          LEFT JOIN classes cl ON c.class_id = cl.id
          LEFT JOIN parents p ON c.parent_id = p.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (parent_id) { sql += ` AND c.parent_id = ?`; params.push(Number(parent_id)); }
        if (child_id) { sql += ` AND c.id = ?`; params.push(Number(child_id)); }
        if (status) { sql += ` AND c.status = ?`; params.push(String(status)); }
        sql += ` ORDER BY c.full_name ASC`;
        records = queryAll(db, sql, params);
        summary = {
          total: records.length,
          active: records.filter(r => r.status === 'نشط').length,
          inactive: records.filter(r => r.status !== 'نشط').length,
        };
      } else if (type === 'children_by_class') {
        const classes = queryAll(db, `SELECT cl.*, cg.name as caregiver_name FROM classes cl LEFT JOIN caregivers cg ON cl.assigned_caregiver_id = cg.id WHERE cl.status = 'نشط'`);
        records = classes.map((cl: any) => {
          let sql = `
            SELECT c.*, p.full_name as parent_name, p.phone as parent_phone
            FROM children c
            LEFT JOIN parents p ON c.parent_id = p.id
            WHERE c.class_id = ? AND c.status = 'نشط'
          `;
          const params: any[] = [cl.id];
          if (child_id) { sql += ` AND c.id = ?`; params.push(Number(child_id)); }
          if (parent_id) { sql += ` AND c.parent_id = ?`; params.push(Number(parent_id)); }
          const kids = queryAll(db, sql, params);
          return {
            ...cl,
            childrenList: kids,
            enrolledCount: kids.length,
          };
        });
        summary = {
          totalClasses: classes.length,
          totalChildren: records.reduce((acc, c) => acc + c.enrolledCount, 0),
        };
      } else if (type === 'daily_attendance' || type === 'monthly_attendance' || type === 'absence' || type === 'late_arrivals') {
        let sql = `
          SELECT a.*, c.full_name as child_name, cl.name as class_name, p.full_name as parent_name
          FROM attendance a
          JOIN children c ON a.child_id = c.id
          LEFT JOIN classes cl ON a.class_id = cl.id
          LEFT JOIN parents p ON c.parent_id = p.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (startDate) { sql += ` AND a.date >= ?`; params.push(String(startDate)); }
        if (endDate) { sql += ` AND a.date <= ?`; params.push(String(endDate)); }
        if (class_id) { sql += ` AND a.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND a.child_id = ?`; params.push(Number(child_id)); }
        if (parent_id) { sql += ` AND c.parent_id = ?`; params.push(Number(parent_id)); }

        if (type === 'absence') {
          sql += ` AND a.status IN ('غائب', 'غياب بعذر')`;
        } else if (type === 'late_arrivals') {
          sql += ` AND a.status = 'متأخر'`;
        } else if (status) {
          sql += ` AND a.status = ?`;
          params.push(String(status));
        }

        sql += ` ORDER BY a.date DESC, c.full_name ASC`;
        records = queryAll(db, sql, params);
        summary = {
          totalRecords: records.length,
          present: records.filter(r => r.status === 'حاضر').length,
          absent: records.filter(r => r.status === 'غائب').length,
          late: records.filter(r => r.status === 'متأخر').length,
          excused: records.filter(r => r.status === 'غياب بعذر').length,
        };
      } else if (type === 'subscriptions') {
        let sql = `
          SELECT s.*, s.period_type as plan_name, c.full_name as child_name, cl.name as class_name, p.full_name as parent_name
          FROM subscriptions s
          JOIN children c ON s.child_id = c.id
          LEFT JOIN classes cl ON c.class_id = cl.id
          JOIN parents p ON c.parent_id = p.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (startDate) { sql += ` AND s.start_date >= ?`; params.push(String(startDate)); }
        if (endDate) { sql += ` AND s.start_date <= ?`; params.push(String(endDate)); }
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND s.child_id = ?`; params.push(Number(child_id)); }
        if (parent_id) { sql += ` AND c.parent_id = ?`; params.push(Number(parent_id)); }
        if (status) { sql += ` AND s.status = ?`; params.push(String(status)); }

        sql += ` ORDER BY s.id DESC`;
        records = queryAll(db, sql, params);
        summary = {
          total: records.length,
          active: records.filter(r => r.status === 'نشط' || r.status === 'مدفوع').length,
          totalAmount: records.reduce((acc, r) => acc + (Number(r.final_amount) || 0), 0),
          totalPaid: records.reduce((acc, r) => acc + (Number(r.paid_amount) || 0), 0),
        };
      } else if (type === 'payments') {
        let sql = `
          SELECT pm.*, c.full_name as child_name, cl.name as class_name, p.full_name as parent_name
          FROM payments pm
          JOIN children c ON pm.child_id = c.id
          LEFT JOIN classes cl ON c.class_id = cl.id
          JOIN parents p ON pm.parent_id = p.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (startDate) { sql += ` AND pm.payment_date >= ?`; params.push(String(startDate)); }
        if (endDate) { sql += ` AND pm.payment_date <= ?`; params.push(String(endDate)); }
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND pm.child_id = ?`; params.push(Number(child_id)); }
        if (parent_id) { sql += ` AND pm.parent_id = ?`; params.push(Number(parent_id)); }

        sql += ` ORDER BY pm.payment_date DESC`;
        records = queryAll(db, sql, params);
        summary = {
          totalPayments: records.length,
          totalCollected: records.reduce((acc, r) => acc + (Number(r.amount) || 0), 0),
        };
      } else if (type === 'outstanding_payments') {
        let sql = `
          SELECT s.*, c.full_name as child_name, cl.name as class_name, p.full_name as parent_name, p.phone as parent_phone
          FROM subscriptions s
          JOIN children c ON s.child_id = c.id
          LEFT JOIN classes cl ON c.class_id = cl.id
          JOIN parents p ON c.parent_id = p.id
          WHERE (s.final_amount - s.paid_amount) > 0
        `;
        const params: any[] = [];
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND s.child_id = ?`; params.push(Number(child_id)); }
        if (parent_id) { sql += ` AND c.parent_id = ?`; params.push(Number(parent_id)); }
        if (status) { sql += ` AND s.status = ?`; params.push(String(status)); }

        sql += ` ORDER BY s.due_date ASC`;
        records = queryAll(db, sql, params);
        summary = {
          count: records.length,
          totalOutstanding: records.reduce((acc, r) => acc + (Number(r.final_amount) - Number(r.paid_amount)), 0),
        };
      } else if (type === 'class_capacity') {
        const classes = queryAll(db, `
          SELECT cl.*, cg.name as caregiver_name, (cl.capacity - cl.current_enrollment) as available_seats
          FROM classes cl
          LEFT JOIN caregivers cg ON cl.assigned_caregiver_id = cg.id
          ORDER BY cl.name ASC
        `);
        records = classes;
        summary = {
          totalClasses: classes.length,
          totalCapacity: classes.reduce((acc: number, c: any) => acc + Number(c.capacity), 0),
          totalEnrolled: classes.reduce((acc: number, c: any) => acc + Number(c.current_enrollment), 0),
          totalAvailable: classes.reduce((acc: number, c: any) => acc + Math.max(0, Number(c.capacity) - Number(c.current_enrollment)), 0),
        };
      } else if (type === 'health') {
        let sql = `
          SELECT hn.*, c.full_name as child_name, c.child_number, cl.name as class_name, u.name as recorded_by_name
          FROM health_notes hn
          JOIN children c ON hn.child_id = c.id
          LEFT JOIN classes cl ON c.class_id = cl.id
          LEFT JOIN users u ON hn.recorded_by_user_id = u.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (startDate) { sql += ` AND hn.date >= ?`; params.push(String(startDate)); }
        if (endDate) { sql += ` AND hn.date <= ?`; params.push(String(endDate)); }
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND hn.child_id = ?`; params.push(Number(child_id)); }

        sql += ` ORDER BY hn.id DESC`;
        records = queryAll(db, sql, params);
        summary = {
          total: records.length,
        };
      } else if (type === 'behavioral') {
        let sql = `
          SELECT bn.*, c.full_name as child_name, c.child_number, cl.name as class_name, u.name as recorded_by_name
          FROM behavior_notes bn
          JOIN children c ON bn.child_id = c.id
          LEFT JOIN classes cl ON c.class_id = cl.id
          LEFT JOIN users u ON bn.recorded_by_user_id = u.id
          WHERE 1=1
        `;
        const params: any[] = [];
        if (startDate) { sql += ` AND bn.date >= ?`; params.push(String(startDate)); }
        if (endDate) { sql += ` AND bn.date <= ?`; params.push(String(endDate)); }
        if (class_id) { sql += ` AND c.class_id = ?`; params.push(Number(class_id)); }
        if (child_id) { sql += ` AND bn.child_id = ?`; params.push(Number(child_id)); }

        sql += ` ORDER BY bn.id DESC`;
        records = queryAll(db, sql, params);
        summary = {
          total: records.length,
        };
      }

      res.json({ type, summary, records });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'خطأ في جلب بيانات التقرير' });
    }
  });

  app.get('/api/reports/attendance', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { startDate, endDate, class_id } = req.query;
      let sql = `
        SELECT a.*, c.full_name as child_name, cl.name as class_name
        FROM attendance a
        JOIN children c ON a.child_id = c.id
        JOIN classes cl ON a.class_id = cl.id
        WHERE 1=1
      `;
      const params: any[] = [];
      if (startDate) {
        sql += ` AND a.date >= ?`;
        params.push(String(startDate));
      }
      if (endDate) {
        sql += ` AND a.date <= ?`;
        params.push(String(endDate));
      }
      if (class_id) {
        sql += ` AND a.class_id = ?`;
        params.push(Number(class_id));
      }
      sql += ` ORDER BY a.date DESC, c.full_name ASC`;
      const records = queryAll(db, sql, params);

      const summary = {
        totalRecords: records.length,
        present: records.filter((r: any) => r.status === 'حاضر').length,
        absent: records.filter((r: any) => r.status === 'غائب').length,
        late: records.filter((r: any) => r.status === 'متأخر').length,
        excused: records.filter((r: any) => r.status === 'غياب بعذر').length,
      };

      res.json({ summary, records });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب تقرير الحضور والغياب' });
    }
  });

  app.get('/api/reports/financial', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { startDate, endDate } = req.query;
      let paySql = `
        SELECT pm.*, c.full_name as child_name, p.full_name as parent_name
        FROM payments pm
        JOIN children c ON pm.child_id = c.id
        JOIN parents p ON pm.parent_id = p.id
        WHERE 1=1
      `;
      const params: any[] = [];
      if (startDate) {
        paySql += ` AND pm.payment_date >= ?`;
        params.push(String(startDate));
      }
      if (endDate) {
        paySql += ` AND pm.payment_date <= ?`;
        params.push(String(endDate));
      }
      paySql += ` ORDER BY pm.payment_date DESC`;
      const payments = queryAll(db, paySql, params);

      const totalReceived = payments.reduce((acc: number, item: any) => acc + (Number(item.amount) || 0), 0);

      const overdueSubs = queryAll(db, `
        SELECT s.*, c.full_name as child_name, p.full_name as parent_name
        FROM subscriptions s
        JOIN children c ON s.child_id = c.id
        JOIN parents p ON c.parent_id = p.id
        WHERE s.status IN ('متأخر', 'غير مدفوع', 'مدفوع جزئياً')
      `);

      const totalOutstanding = overdueSubs.reduce((acc: number, item: any) => acc + (Number(item.final_amount) - Number(item.paid_amount)), 0);

      res.json({
        summary: {
          totalReceived,
          totalOutstanding,
          paymentsCount: payments.length,
          overdueCount: overdueSubs.length,
        },
        payments,
        overdueSubscriptions: overdueSubs,
      });
    } catch (err) {
      res.status(500).json({ error: 'خطأ في جلب التقرير المالي' });
    }
  });

  // -------------------------------------------------------------
  // NOTIFICATIONS API
  // -------------------------------------------------------------
  app.get('/api/notifications', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      syncSystemNotifications(db);

      const userId = req.user!.id;
      const userRole = req.user!.role;
      const { unreadOnly, limit } = req.query;

      let sql = `
        SELECT * FROM notifications
        WHERE (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))
      `;
      const params: any[] = [userId, userRole];

      if (unreadOnly === 'true') {
        sql += ` AND is_read = 0`;
      }

      sql += ` ORDER BY created_at DESC, id DESC`;

      if (limit) {
        sql += ` LIMIT ?`;
        params.push(Number(limit) || 50);
      } else {
        sql += ` LIMIT 100`;
      }

      const notifications = queryAll(db, sql, params);

      const unreadCountRes = queryAll(
        db,
        `SELECT COUNT(*) as count FROM notifications
         WHERE is_read = 0
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [userId, userRole]
      );
      const unreadCount = unreadCountRes[0]?.count || 0;

      res.json({ notifications, unreadCount });
    } catch (err) {
      res.status(500).json({ error: 'تعذر تحميل الإشعارات. حاول مرة أخرى.' });
    }
  });

  app.get('/api/notifications/unread-count', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const unreadCountRes = queryAll(
        db,
        `SELECT COUNT(*) as count FROM notifications
         WHERE is_read = 0
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [userId, userRole]
      );
      const unreadCount = unreadCountRes[0]?.count || 0;

      res.json({ unreadCount });
    } catch (err) {
      res.status(500).json({ error: 'تعذر جلب عدد الإشعارات غير المقروءة' });
    }
  });

  app.put('/api/notifications/mark-all-read', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const userRole = req.user!.role;

      executeSql(
        db,
        `UPDATE notifications SET is_read = 1
         WHERE is_read = 0
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [userId, userRole]
      );

      res.json({ success: true, message: 'تم تحديد جميع الإشعارات كمعروءة' });
    } catch (err) {
      res.status(500).json({ error: 'تعذر تحديث حالة الإشعارات' });
    }
  });

  app.put('/api/notifications/:id/read', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { id } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      executeSql(
        db,
        `UPDATE notifications SET is_read = 1
         WHERE id = ?
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [id, userId, userRole]
      );

      res.json({ success: true, id: Number(id) });
    } catch (err) {
      res.status(500).json({ error: 'تعذر تحديث إشعار' });
    }
  });

  app.delete('/api/notifications/clear-all', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const userId = req.user!.id;
      const userRole = req.user!.role;

      executeSql(
        db,
        `DELETE FROM notifications
         WHERE is_read = 1
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [userId, userRole]
      );

      res.json({ message: 'تم مسح جميع الإشعارات المقروءة' });
    } catch (err) {
      res.status(500).json({ error: 'تعذر مسح الإشعارات' });
    }
  });

  app.delete('/api/notifications/:id', authenticateToken, (req: AuthRequest, res: Response) => {
    try {
      const { id } = req.params;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      executeSql(
        db,
        `DELETE FROM notifications
         WHERE id = ?
         AND (user_id = ? OR (user_id IS NULL AND (target_role = ? OR target_role = 'all')))`,
        [id, userId, userRole]
      );

      res.json({ message: 'تم حذف الإشعار' });
    } catch (err) {
      res.status(500).json({ error: 'تعذر حذف الإشعار' });
    }
  });

  // -------------------------------------------------------------
  // VITE MIDDLEWARE / STATIC SERVING
  // -------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
