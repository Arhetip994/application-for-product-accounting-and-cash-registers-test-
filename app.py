import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Menu
from datetime import datetime, timedelta
import hashlib
import csv
from tkinter import filedialog
import time
import re

# ==================== БАЗА ДАННЫХ С МИГРАЦИЕЙ ====================
def init_db():
    """Инициализация базы данных с безопасной миграцией"""
    conn = sqlite3.connect('vape_shop.db')
    cursor = conn.cursor()
    
    # 1. Создаём таблицу users, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'cashier')) NOT NULL,
            is_super_admin BOOLEAN DEFAULT 0,
            is_creator BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Создаём таблицу products, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            requires_18plus BOOLEAN DEFAULT 0,
            deleted BOOLEAN DEFAULT 0,
            deleted_by INTEGER,
            deleted_at DATETIME,
            FOREIGN KEY (deleted_by) REFERENCES users(id)
        )
    ''')
    
    # 3. Создаём таблицу sales, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            payment_type TEXT CHECK(payment_type IN ('cash', 'card')) NOT NULL,
            cashier_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sale_duration REAL,
            is_deleted_record BOOLEAN DEFAULT 0,
            buyer_18verified BOOLEAN DEFAULT 0,
            marking_code_used TEXT,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (cashier_id) REFERENCES users(id)
        )
    ''')
    
    # 4. Создаём таблицу scan_logs, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cashier_id INTEGER NOT NULL,
            barcode TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            product_id INTEGER,
            scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            sale_duration REAL
        )
    ''')
    
    # 5. Создаём таблицу categories, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    ''')
    
    # 6. ФУНКЦИЯ БЕЗОПАСНОГО ДОБАВЛЕНИЯ СТОЛБЦА
    def safe_add_column(table, column_def):
        """Безопасно добавляет столбец, если его ещё нет"""
        try:
            # Получаем список столбцов в таблице
            cursor.execute(f"PRAGMA table_info({table})")
            existing_columns = [col[1] for col in cursor.fetchall()]
            
            # Извлекаем имя нового столбца из определения
            new_col_name = column_def.split()[0]
            
            if new_col_name not in existing_columns:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
                print(f"✅ Добавлен столбец '{new_col_name}' в таблицу '{table}'")
            else:
                print(f"ℹ️ Столбец '{new_col_name}' уже существует в таблице '{table}'")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"ℹ️ Столбец '{new_col_name}' уже существует (по ошибке)")
            else:
                print(f"⚠️ Ошибка при добавлении столбца в '{table}': {e}")
    
    # 7. Добавляем недостающие столбцы (безопасно)
    # Для таблицы users
    safe_add_column("users", "is_super_admin BOOLEAN DEFAULT 0")
    safe_add_column("users", "is_creator BOOLEAN DEFAULT 0")
    safe_add_column("users", "created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
    
    # Для таблицы products
    safe_add_column("products", "deleted BOOLEAN DEFAULT 0")
    safe_add_column("products", "deleted_by INTEGER")
    safe_add_column("products", "deleted_at DATETIME")
    safe_add_column("products", "requires_18plus BOOLEAN DEFAULT 0")
    safe_add_column("products", "marking_code TEXT")
    safe_add_column("products", "marking_status TEXT DEFAULT 'not_scanned'")
    safe_add_column("products", "category_id INTEGER")
    
    # Для таблицы sales
    safe_add_column("sales", "sale_duration REAL")
    safe_add_column("sales", "is_deleted_record BOOLEAN DEFAULT 0")
    safe_add_column("sales", "buyer_18verified BOOLEAN DEFAULT 0")
    safe_add_column("sales", "marking_code_used TEXT")
    
    # Для таблицы scan_logs
    safe_add_column("scan_logs", "sale_duration REAL")
    
    # 8. Добавляем базовые категории (если их нет)
    cursor.execute("SELECT COUNT(*) FROM categories")
    if cursor.fetchone()[0] == 0:
        default_categories = ["Жидкости", "Одноразовые устройства", "Поды и системы", 
                             "Испарители", "Аккумуляторы", "Аксессуары"]
        cursor.executemany("INSERT INTO categories (name) VALUES (?)", [(cat,) for cat in default_categories])
        print("✅ Добавлены базовые категории товаров")
    
    # 9. Создаём админа по умолчанию
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        pwd_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                      ("admin", pwd_hash, "admin"))
        print("✅ Создан пользователь 'admin'")
    
    # 10. Создаём вашу учётную запись (создателя) - ЗАЩИЩЕНА ОТ УДАЛЕНИЯ
    cursor.execute("SELECT * FROM users WHERE username = 'Archmage1337'")
    if not cursor.fetchone():
        pwd_hash = hashlib.sha256("Dinar33hatin".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, is_super_admin, is_creator) 
            VALUES (?, ?, ?, ?, ?)
        """, ("Archmage1337", pwd_hash, "admin", 1, 1))
        print("✅ Создана ваша учётная запись 'Archmage1337' (создатель)")
    
    conn.commit()
    print("✅ База данных успешно инициализирована")
    return conn
# ==================== СИСТЕМА МАРКИРОВКИ ====================
class MarkingSystem:
    @staticmethod
    def validate_marking_code(code):
        if not code or len(code) != 31:
            return False
        if not re.match(r'^[A-Z0-9]{31}$', code):
            return False
        return True

# ==================== ОСНОВНОЙ КЛАСС ПРИЛОЖЕНИЯ ====================
class VapeShopApp:
    def __init__(self, root):
        self.db_conn = init_db()
        self.marking_system = MarkingSystem()
        self.root = root
        self.root.title("Vape Shop — Тестирование кассиров")
        self.root.geometry("950x700")
        self.root.minsize(800, 600)
        self.current_user = None
        self.scan_start_time = None
        
        # Настройка стиля
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        style.configure("Treeview", font=("Arial", 9))
        style.configure("TButton", font=("Arial", 10))
        style.configure("TLabel", font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        style.configure("Stats.TLabel", font=("Arial", 10, "italic"))
        style.configure("Success.TLabel", foreground="green", font=("Arial", 13, "bold"))
        style.configure("Error.TLabel", foreground="red", font=("Arial", 13, "bold"))
        style.configure("Warning.TLabel", foreground="#e65100", font=("Arial", 11, "bold"))
        style.configure("Deleted.TLabel", foreground="#9e9e9e", font=("Arial", 10, "italic"))
        style.configure("SuperAdmin.TLabel", foreground="#d32f2f", font=("Arial", 12, "bold"))
        style.configure("Creator.TLabel", foreground="#6a1b9a", font=("Arial", 13, "bold"))
        style.configure("AgeCheck.TLabel", foreground="#c62828", font=("Arial", 12, "bold"))
        style.configure("Marking.TLabel", foreground="#5d4037", font=("Arial", 11, "bold"))
        
        self.login_screen()

    # === БАЗОВЫЕ МЕТОДЫ ИНТЕРФЕЙСА ===
    def clear_content(self):
        if hasattr(self, 'content_frame'):
            for widget in self.content_frame.winfo_children():
                widget.destroy()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def create_standard_layout(self, title):
        """Создаёт стандартный макет: хедер + контент + футер"""
        self.clear_window()
        # Хедер
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=10)
        
        if self.current_user['is_creator']:
            ttk.Label(header, text=f"👑 Создатель: {self.current_user['username']}", 
                     style="Creator.TLabel").pack(side=tk.LEFT)
        elif self.current_user['is_super_admin']:
            ttk.Label(header, text=f"🔴 Супер-админ: {self.current_user['username']}", 
                     style="SuperAdmin.TLabel").pack(side=tk.LEFT)
        else:
            ttk.Label(header, text=f"Пользователь: {self.current_user['username']} ({self.current_user['role']})",
                     font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        ttk.Label(header, text=title, style="Header.TLabel").pack(side=tk.LEFT, padx=20)
        ttk.Button(header, text="Выйти", command=self.login_screen, width=10).pack(side=tk.RIGHT)
        
        # Основная рабочая область
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        # Нижняя панель с кнопками
        self.footer_frame = ttk.Frame(self.root)
        self.footer_frame.pack(fill=tk.X, padx=20, pady=10, side=tk.BOTTOM)
        # Статистика между контентом и футером
        self.stats_frame = ttk.Frame(self.root)
        self.stats_frame.pack(fill=tk.X, padx=20, pady=5, side=tk.BOTTOM)
        self.stats_label = ttk.Label(self.stats_frame, text="", style="Stats.TLabel")
        self.stats_label.pack()

    # === ЭКРАН ВХОДА ===
    def login_screen(self):
        self.clear_window()
        ttk.Label(self.root, text="Система тестирования кассиров", 
                 font=("Arial", 20, "bold")).pack(pady=40)
        ttk.Label(self.root, text="Логин:", font=("Arial", 12)).pack()
        self.username_entry = ttk.Entry(self.root, width=35, font=("Arial", 14))
        self.username_entry.pack(pady=8)
        self.username_entry.focus()
        ttk.Label(self.root, text="Пароль:", font=("Arial", 12)).pack()
        self.password_entry = ttk.Entry(self.root, width=35, font=("Arial", 14), show="*")
        self.password_entry.pack(pady=8)
        self.password_entry.bind('<Return>', lambda e: self.login())
        ttk.Button(self.root, text="Войти", command=self.login, width=25).pack(pady=30)
        
        version = "Версия 4.3 • Без категорий • Защита учётных записей • Исправлен выбор товара"
        ttk.Label(self.root, text=version, font=("Arial", 8), foreground="#757575").pack(side=tk.BOTTOM, pady=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT id, role, is_super_admin, is_creator 
            FROM users 
            WHERE username = ? AND password_hash = ?
        """, (username, pwd_hash))
        result = cursor.fetchone()
        if result:
            self.current_user = {
                "id": result[0], 
                "username": username, 
                "role": result[1],
                "is_super_admin": bool(result[2]),
                "is_creator": bool(result[3])
            }
            self.main_menu()
        else:
            messagebox.showerror("Ошибка", "Неверный логин или пароль")

    # === ГЛАВНОЕ МЕНЮ ===
    def main_menu(self):
        self.clear_window()
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=20, pady=15)
        
        if self.current_user['is_creator']:
            ttk.Label(header, text=f"👑 Создатель: {self.current_user['username']}", 
                     style="Creator.TLabel").pack(side=tk.LEFT)
        elif self.current_user['is_super_admin']:
            ttk.Label(header, text=f"🔴 Супер-админ: {self.current_user['username']}", 
                     style="SuperAdmin.TLabel").pack(side=tk.LEFT)
        else:
            ttk.Label(header, text=f"Пользователь: {self.current_user['username']} ({self.current_user['role']})",
                     font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header, text="Выйти", command=self.login_screen, width=10).pack(side=tk.RIGHT)
        ttk.Label(self.root, text="Vape Shop — Тестирование кассиров",
                 font=("Arial", 20, "bold")).pack(pady=25)
        
        menu_frame = ttk.Frame(self.root)
        menu_frame.pack(pady=10)
        buttons = [
            ("Продажа товара", self.sale_screen, "🛒"),
            ("Статистика кассира", self.cashier_stats, "📊"),
            ("Каталог товаров", self.view_products, "📦"),
            ("Чеки", self.view_receipts, "🧾"),
            ("История продаж", self.view_sales_history, "📜"),
            ("Отчет за день", self.daily_report, "📈")
        ]
        
        # Права доступа
        if self.current_user['is_creator'] or self.current_user['is_super_admin']:
            buttons.insert(1, ("Управление пользователями", self.manage_users, "👥"))
            buttons.insert(2, ("Удалённые товары", self.view_deleted_products, "🗑️"))
            buttons.insert(3, ("Добавить товар", self.add_product_screen, "➕"))
        elif self.current_user['role'] == 'admin':
            buttons.insert(1, ("Управление пользователями", self.manage_users, "👥"))
            buttons.insert(2, ("Добавить товар", self.add_product_screen, "➕"))
        else:
            buttons.insert(1, ("Добавить товар", self.add_product_screen, "➕"))
        
        for i, (text, command, icon) in enumerate(buttons):
            row = i // 2
            col = i % 2
            btn = ttk.Button(menu_frame, text=f"{icon} {text}", command=command, width=35)
            btn.grid(row=row, column=col, padx=15, pady=12, sticky="ew")

    # === ПРОДАЖА ТОВАРА ===
    def sale_screen(self):
        self.create_standard_layout("Продажа товара")
        scan_frame = ttk.LabelFrame(self.content_frame, text="Сканирование штрих-кода", padding=15)
        scan_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(scan_frame, text="Отсканируйте штрих-код или введите вручную:", 
                 font=("Arial", 11)).pack(pady=(0, 5))
        self.barcode_entry = ttk.Entry(scan_frame, width=40, font=("Arial", 18))
        self.barcode_entry.pack(pady=5)
        self.barcode_entry.focus()
        self.barcode_entry.bind('<Return>', lambda e: self.search_product_by_barcode())
        self.product_info = ttk.Label(scan_frame, text="", font=("Arial", 13, "bold"))
        self.product_info.pack(pady=10)
        list_frame = ttk.LabelFrame(self.content_frame, text="Или выберите товар из списка", padding=15)
        list_frame.pack(fill=tk.X, pady=(0, 15))
        ttk.Button(list_frame, text="📦 Выбрать товар из каталога", 
                  command=self.select_product_from_list, width=40).pack(pady=5)
        self.selected_product_label = ttk.Label(list_frame, text="", 
                                               font=("Arial", 11, "italic"), foreground="#555")
        self.selected_product_label.pack(pady=(5, 0))
        qty_frame = ttk.Frame(self.content_frame)
        qty_frame.pack(pady=10, fill=tk.X)
        ttk.Label(qty_frame, text="Количество:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
        self.quantity_entry = ttk.Entry(qty_frame, width=8, font=("Arial", 14))
        self.quantity_entry.insert(0, "1")
        self.quantity_entry.pack(side=tk.LEFT, padx=10)
        ttk.Label(qty_frame, text="  Тип оплаты:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
        self.payment_var = tk.StringVar(value="cash")
        ttk.Radiobutton(qty_frame, text="Наличные", variable=self.payment_var, value="cash").pack(side=tk.LEFT, padx=8)
        ttk.Radiobutton(qty_frame, text="Карта", variable=self.payment_var, value="card").pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="✅ Продать", command=self.complete_sale, width=18).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="🔄 Сбросить", command=self.sale_screen, width=18).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="⬅ Назад", command=self.main_menu, width=18).pack(side=tk.LEFT, padx=8)

    def search_product_by_barcode(self):
        barcode = self.barcode_entry.get().strip()
        if not barcode:
            return
        self.scan_start_time = time.time()
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT id, name, price, stock, requires_18plus, marking_code, marking_status
            FROM products
            WHERE barcode = ? AND deleted = 0
        """, (barcode,))
        product = cursor.fetchone()
        cursor.execute("""
            INSERT INTO scan_logs (cashier_id, barcode, success, product_id) 
            VALUES (?, ?, ?, ?)
        """, (self.current_user['id'], barcode, product is not None, product[0] if product else None))
        self.db_conn.commit()
        if product:
            self.current_product = product
            info_text = f"✓ {product[1]} | Цена: {product[2]:.2f}₽ | Остаток: {product[3]} шт"
            if product[4]:  # requires_18plus
                info_text += " | 🔞 ТРЕБУЕТСЯ ПРОВЕРКА 18+"
                self.product_info.config(text=info_text, style="AgeCheck.TLabel")
            else:
                self.product_info.config(text=info_text, style="Success.TLabel")
            
            # Проверка маркировки для вейп-товаров
            if product[4]:  # requires_18plus
                if product[5] and product[6] == "verified":  # marking_code exists and verified
                    self.marking_status.config(text=f"✅ Код маркировки: ...{product[5][-6:]} | Статус: ПРОВЕРЕН", 
                                             foreground="green")
                elif product[5]:
                    self.marking_status.config(text=f"⚠️ Код маркировки: ...{product[5][-6:]} | ОЖИДАЕТ ПРОВЕРКИ", 
                                             foreground="#e65100")
                else:
                    self.marking_status.config(text="⚠️ Отсканируйте 2D-код маркировки", foreground="#e65100")
            else:
                self.marking_status.config(text="ℹ️ Товар не требует маркировки", foreground="#555")
            
            self.selected_product_label.config(text="")
            self.quantity_entry.focus()
            self.quantity_entry.select_range(0, tk.END)
        else:
            if messagebox.askyesno("Товар не найден", 
                                 f"Штрих-код '{barcode}' не найден в базе.\nХотите быстро добавить новый товар?"):
                self.quick_add_product(barcode)
            else:
                self.product_info.config(text=f"❌ Товар с штрих-кодом {barcode} не найден", 
                                       style="Error.TLabel")
                self.current_product = None
                self.scan_start_time = None

    def quick_add_product(self, barcode):
        dialog = tk.Toplevel(self.root)
        dialog.title("Быстрое добавление товара")
        dialog.geometry("450x300")
        dialog.transient(self.root)
        dialog.grab_set()
        fields = {
            "name": ("Название товара:", ""),
            "price": ("Цена (₽):", "0.00"),
            "stock": ("Остаток:", "1"),
            "requires_18plus": ("Вейп-товар (требует 18+):", False),
            "marking_code": ("Код маркировки (31 символ):", "")
        }
        entries = {}
        row = 0
        for key, (label_text, default) in fields.items():
            ttk.Label(dialog, text=label_text, font=("Arial", 11)).grid(row=row, column=0, sticky=tk.W, padx=20, pady=8)
            if key == "requires_18plus":
                var = tk.BooleanVar(value=default)
                chk = ttk.Checkbutton(dialog, variable=var)
                chk.grid(row=row, column=1, sticky=tk.W, padx=10, pady=8)
                entries[key] = var
            else:
                entry = ttk.Entry(dialog, width=30, font=("Arial", 11))
                entry.insert(0, default)
                entry.grid(row=row, column=1, padx=10, pady=8)
                entries[key] = entry
            row += 1
        def save():
            name = entries["name"].get().strip()
            try:
                price = float(entries["price"].get().strip())
                stock = int(entries["stock"].get().strip())
                requires_18plus = entries["requires_18plus"].get()
                marking_code = entries["marking_code"].get().strip()
            except ValueError:
                messagebox.showerror("Ошибка", "Некорректная цена, остаток или маркировка")
                return
            if not name or price <= 0 or stock < 0:
                messagebox.showerror("Ошибка", "Проверьте корректность данных")
                return
            # Проверка маркировки для вейп-товаров
            if requires_18plus and marking_code:
                if not self.marking_system.validate_marking_code(marking_code):
                    messagebox.showerror("Ошибка маркировки", 
                        "Неверный формат кода маркировки!\n"
                        "Для вейп-товаров требуется действительный код Честный ЗНАК (31 символ).")
                    return
            marking_status = 'verified' if marking_code else 'not_scanned'
            try:
                cursor = self.db_conn.cursor()
                cursor.execute("""
                    INSERT INTO products (barcode, name, price, stock, requires_18plus, marking_code, marking_status, deleted) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """, (barcode, name, price, stock, requires_18plus, marking_code, marking_status))
                self.db_conn.commit()
                messagebox.showinfo("Успех", f"Товар '{name}' добавлен!")
                dialog.destroy()
                cursor.execute("SELECT id, name, price, stock, requires_18plus, marking_code, marking_status FROM products WHERE barcode = ?", (barcode,))
                self.current_product = cursor.fetchone()
                info_text = f"✓ {self.current_product[1]} | Цена: {self.current_product[2]:.2f}₽ | Остаток: {self.current_product[3]} шт"
                if self.current_product[4]:
                    info_text += " | 🔞 ТРЕБУЕТСЯ ПРОВЕРКА 18+"
                    self.product_info.config(text=info_text, style="AgeCheck.TLabel")
                    if self.current_product[5] and self.current_product[6] == "verified":
                        self.marking_status.config(text=f"✅ Код маркировки: ...{self.current_product[5][-6:]} | Статус: ПРОВЕРЕН", 
                                                 foreground="green")
                    elif self.current_product[5]:
                        self.marking_status.config(text=f"⚠️ Код маркировки: ...{self.current_product[5][-6:]} | ОЖИДАЕТ ПРОВЕРКИ", 
                                                 foreground="#e65100")
                    else:
                        self.marking_status.config(text="⚠️ Отсканируйте 2D-код маркировки", foreground="#e65100")
                else:
                    self.product_info.config(text=info_text, style="Success.TLabel")
                    self.marking_status.config(text="ℹ️ Товар не требует маркировки", foreground="#555")
                self.quantity_entry.focus()
                self.quantity_entry.select_range(0, tk.END)
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка", f"Штрих-код '{barcode}' уже существует!")
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=row, column=0, columnspan=2, pady=20)
        ttk.Button(btn_frame, text="Добавить и продать", command=save, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy, width=15).pack(side=tk.LEFT, padx=10)
        dialog.wait_window()

    def select_product_from_list(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Выберите товар для продажи")
        dialog.geometry("750x500")
        dialog.transient(self.root)
        dialog.grab_set()
        top_frame = ttk.Frame(dialog)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(top_frame, text="Поиск:").pack(side=tk.LEFT, padx=(20, 5))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.focus()
        tree_frame = ttk.Frame(dialog)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree = ttk.Treeview(tree_frame, columns=("id", "name", "price", "stock", "age18"),
                          show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        tree.heading("id", text="ID")
        tree.heading("name", text="Название")
        tree.heading("price", text="Цена, ₽")
        tree.heading("stock", text="Остаток")
        tree.heading("age18", text="18+")
        tree.column("id", width=50, anchor="center")
        tree.column("name", width=400)
        tree.column("price", width=100, anchor="e")
        tree.column("stock", width=80, anchor="center")
        tree.column("age18", width=60, anchor="center")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        def load_products(search_term=""):
            for item in tree.get_children():
                tree.delete(item)
            cursor = self.db_conn.cursor()
            query = """
                SELECT id, name, price, stock, requires_18plus 
                FROM products
                WHERE stock > 0 AND deleted = 0
            """
            params = []
            if search_term:
                query += " AND (LOWER(name) LIKE ? OR LOWER(barcode) LIKE ?)"
                params.extend([f"%{search_term.lower()}%", f"%{search_term.lower()}%"])
            query += " ORDER BY name"
            cursor.execute(query, params)
            for row in cursor.fetchall():
                tags = ("age18",) if row[4] else ()
                tree.insert("", "end", values=row, tags=tags)
            tree.tag_configure("age18", background="#fff8e1", foreground="#5d4037")
        load_products()
        search_var.trace("w", lambda *args: load_products(search_var.get()))
        def on_double_click(event):
            selected = tree.selection()
            if selected:
                item = tree.item(selected[0])
                values = item['values']
                # === ИСПРАВЛЕНО: корректное обновление self.current_product ===
                self.current_product = (values[0], values[1], float(values[2]), int(values[3]), bool(values[4]))
                self.selected_product_label.config(text=f"Выбрано: {values[1]} | {float(values[2]):.2f}₽ | Остаток: {values[3]} шт")
                self.product_info.config(text="")
                if values[4]:  # requires_18plus
                    cursor = self.db_conn.cursor()
                    cursor.execute("SELECT marking_code, marking_status FROM products WHERE id = ?", (values[0],))
                    marking_info = cursor.fetchone()
                    if marking_info and marking_info[0] and marking_info[1] == "verified":
                        self.marking_status.config(text=f"✅ Код маркировки: ...{marking_info[0][-6:]} | Статус: ПРОВЕРЕН", 
                                                 foreground="green")
                    elif marking_info and marking_info[0]:
                        self.marking_status.config(text=f"⚠️ Код маркировки: ...{marking_info[0][-6:]} | ОЖИДАЕТ ПРОВЕРКИ", 
                                                 foreground="#e65100")
                        self.marking_entry.focus()
                    else:
                        self.marking_status.config(text="⚠️ Отсканируйте 2D-код маркировки", foreground="#e65100")
                        self.marking_entry.focus()
                else:
                    self.marking_status.config(text="ℹ️ Товар не требует маркировки", foreground="#555")
                self.quantity_entry.focus()
                self.quantity_entry.select_range(0, tk.END)
                dialog.destroy()
        tree.bind("<Double-1>", on_double_click)
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(btn_frame, text="Выбрать", command=lambda: on_double_click(None), width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy, width=15).pack(side=tk.RIGHT, padx=5)
        dialog.wait_window()

    def complete_sale(self):
        if not hasattr(self, 'current_product') or not self.current_product:
            messagebox.showerror("Ошибка", "Сначала выберите товар (отсканируйте штрих-код или выберите из списка)")
            return
        try:
            quantity = int(self.quantity_entry.get())
            if quantity <= 0:
                raise ValueError
        except:
            messagebox.showerror("Ошибка", "Введите корректное количество (целое число > 0)")
            return
        if self.current_product[3] < quantity:
            messagebox.showwarning("Внимание",
                f"Недостаточно товара на складе!\nОстаток: {self.current_product[3]} шт")
            return
        # Проверка 18+ для вейп-товаров
        requires_18plus = bool(self.current_product[4])
        buyer_18verified = False
        marking_code_used = None
        if requires_18plus:
            # Проверка: товар имеет действительный код маркировки?
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT marking_code, marking_status FROM products WHERE id = ?", (self.current_product[0],))
            marking_info = cursor.fetchone()
            if not marking_info or not marking_info[0] or marking_info[1] != 'verified':
                messagebox.showerror("Ошибка", 
                    "❌ Невозможно продать вейп-товар без действительного кода маркировки!\n"
                    "Сначала отсканируйте и проверьте 2D-код Честный ЗНАК.")
                return
            if not messagebox.askyesno("⚠️ ПРОВЕРКА ВОЗРАСТА 18+", 
                "Покупатель предъявил паспорт и подтвердил возраст 18+ лет?\n\n"
                "❗ Продажа вейп-продуктов несовершеннолетним запрещена (ст. 19.15 КоАП РФ)"):
                messagebox.showwarning("Отказ в продаже", 
                    "Продажа отменена. Покупатель не подтвердил возраст 18+ лет.")
                return
            buyer_18verified = True
            marking_code_used = marking_info[0]
        total = self.current_product[2] * quantity
        payment_type = self.payment_var.get()
        if not messagebox.askyesno("Подтверждение",
            f"Продать:\n{self.current_product[1]}\nКоличество: {quantity} шт\nСумма: {total:.2f}₽\nОплата: {'Наличные' if payment_type == 'cash' else 'Карта'}"):
            return
        sale_duration = None
        if self.scan_start_time:
            sale_duration = time.time() - self.scan_start_time
        cursor = self.db_conn.cursor()
        cursor.execute("""
            INSERT INTO sales (product_id, quantity, total, payment_type, cashier_id, sale_duration, buyer_18verified, marking_code_used) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (self.current_product[0], quantity, total, payment_type, self.current_user['id'], sale_duration, buyer_18verified, marking_code_used))
        cursor.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (quantity, self.current_product[0]))
        self.db_conn.commit()
        speed_text = f" | ⚡ {sale_duration:.1f} сек" if sale_duration else ""
        success_msg = f"✅ Продажа выполнена!\n{self.current_product[1]} x{quantity} = {total:.2f}₽{speed_text}"
        if requires_18plus:
            success_msg += f"\n\n🔞 Возраст подтверждён | 📦 Маркировка: ...{marking_code_used[-6:]}"
        messagebox.showinfo("Успех", success_msg)
        self.sale_screen()

    # === СТАТИСТИКА КАССИРА ===
    def cashier_stats(self):
        self.create_standard_layout(f"Статистика кассира: {self.current_user['username']}")
        
        cursor = self.db_conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Проверяем наличие столбца sale_duration
        cursor.execute("PRAGMA table_info(sales)")
        columns = [col[1] for col in cursor.fetchall()]
        has_sale_duration = 'sale_duration' in columns
        
        if has_sale_duration:
            cursor.execute("""
                SELECT 
                    COUNT(*),
                    SUM(s.total),
                    AVG(s.sale_duration),
                    COUNT(CASE WHEN sl.success = 1 THEN 1 END),
                    COUNT(CASE WHEN sl.success = 0 THEN 1 END)
                FROM sales s
                LEFT JOIN scan_logs sl ON sl.cashier_id = s.cashier_id 
                    AND DATE(sl.scan_time) = DATE(s.timestamp)
                WHERE s.cashier_id = ? AND DATE(s.timestamp) = ?
            """, (self.current_user['id'], today))
        else:
            # Если столбца нет, используем упрощённый запрос
            cursor.execute("""
                SELECT 
                    COUNT(*),
                    SUM(s.total),
                    NULL,
                    0,
                    0
                FROM sales s
                WHERE s.cashier_id = ? AND DATE(s.timestamp) = ?
            """, (self.current_user['id'], today))
        
        result = cursor.fetchone()
        total_sales = result[0] or 0
        total_sum = result[1] or 0
        avg_time = result[2] or 0
        successful_scans = result[3] or 0
        failed_scans = result[4] or 0
        
        total_scans = successful_scans + failed_scans
        accuracy = (successful_scans / total_scans * 100) if total_scans > 0 else 100
        
        # Часы пик
        cursor.execute("""
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as sales_count
            FROM sales
            WHERE cashier_id = ? AND DATE(timestamp) = ?
            GROUP BY hour
            ORDER BY sales_count DESC
            LIMIT 3
        """, (self.current_user['id'], today))
        peak_hours = cursor.fetchall()
        cursor.close()
        
        # === БЛОК 1: Ключевые метрики ===
        metrics_frame = ttk.LabelFrame(self.content_frame, text="Ключевые показатели за сегодня", padding=15)
        metrics_frame.pack(fill=tk.X, pady=(0, 15))
        metrics = [
            ("Всего продаж", f"{total_sales} шт", "📊"),
            ("Оборот", f"{total_sum:.2f} ₽", "💰"),
            ("Среднее время", f"{avg_time:.1f} сек" if avg_time > 0 else "—", "⏱️"),
            ("Точность сканирования", f"{accuracy:.1f}%", "🎯"),
            ("Ошибок сканирования", f"{failed_scans}", "❌")
        ]
        metrics_grid = ttk.Frame(metrics_frame)
        metrics_grid.pack(fill=tk.X)
        for i, (label, value, icon) in enumerate(metrics):
            frame = ttk.Frame(metrics_grid, padding=10)
            frame.grid(row=0, column=i, padx=5, sticky="nsew")
            ttk.Label(frame, text=icon, font=("Arial", 20, "bold"), foreground="#1976d2").pack()
            ttk.Label(frame, text=label, font=("Arial", 9)).pack()
            ttk.Label(frame, text=value, font=("Arial", 14, "bold")).pack()
        
        # === БЛОК 2: Часы пик ===
        if peak_hours:
            peak_frame = ttk.LabelFrame(self.content_frame, text="Часы пик (самые активные)", padding=15)
            peak_frame.pack(fill=tk.X, pady=(0, 15))
            for hour, count in peak_hours:
                hour_label = f"{hour}:00-{int(hour)+1}:00"
                progress = ttk.Progressbar(peak_frame, value=count/total_sales*100 if total_sales > 0 else 0, 
                                         maximum=100, length=300)
                ttk.Label(peak_frame, text=f"{hour_label}: {count} продаж").pack(anchor="w", pady=(5, 0))
                progress.pack(fill=tk.X, pady=(0, 10))
        
        # === БЛОК 3: Рекомендации ===
        recommendations = []
        if avg_time > 15 and total_sales > 0:
            recommendations.append("⚠️ Слишком медленно: среднее время продажи > 15 сек")
        if accuracy < 90:
            recommendations.append(f"⚠️ Низкая точность: {accuracy:.1f}% успешных сканирований")
        if total_sales == 0:
            recommendations.append("ℹ️ Сегодня ещё не было продаж")
        
        if recommendations:
            rec_frame = ttk.LabelFrame(self.content_frame, text="Рекомендации", padding=15)
            rec_frame.pack(fill=tk.X, pady=(0, 15))
            for rec in recommendations:
                ttk.Label(rec_frame, text=rec, style="Warning.TLabel").pack(anchor="w", pady=3)
        else:
            ttk.Label(self.content_frame, text="✅ Отличная работа! Все показатели в норме", 
                     font=("Arial", 12, "bold"), foreground="green").pack(pady=10)
        
        # === КНОПКИ В ФУТЕРЕ ===
        ttk.Button(self.footer_frame, text="🔄 Обновить", command=self.cashier_stats, width=18).pack(side=tk.LEFT, padx=8)
        if self.current_user['role'] == 'admin':
            ttk.Button(self.footer_frame, text="Подробная статистика", 
                      command=self.admin_detailed_stats, width=25).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="⬅ Назад", command=self.main_menu, width=18).pack(side=tk.LEFT, padx=8)

    def admin_detailed_stats(self):
        if self.current_user['role'] != 'admin':
            return
        self.create_standard_layout("Подробная статистика всех кассиров")
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT 
                u.id,
                u.username,
                COUNT(s.id) as sales_count,
                SUM(s.total) as total_sum,
                AVG(s.sale_duration),
                COUNT(CASE WHEN sl.success = 1 THEN 1 END) as success_scans,
                COUNT(CASE WHEN sl.success = 0 THEN 1 END) as failed_scans
            FROM users u
            LEFT JOIN sales s ON s.cashier_id = u.id AND DATE(s.timestamp) = DATE('now')
            LEFT JOIN scan_logs sl ON sl.cashier_id = u.id AND DATE(sl.scan_time) = DATE('now')
            WHERE u.role = 'cashier'
            GROUP BY u.id
            ORDER BY sales_count DESC
        """)
        cashier_stats = cursor.fetchall()
        cursor.close()
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        tree = ttk.Treeview(tree_frame, columns=("username", "sales", "sum", "avg_time", "accuracy", "rating"), 
                          show="headings", yscrollcommand=vsb.set)
        vsb.config(command=tree.yview)
        tree.heading("username", text="Кассир")
        tree.heading("sales", text="Продаж")
        tree.heading("sum", text="Оборот, ₽")
        tree.heading("avg_time", text="Сред. время")
        tree.heading("accuracy", text="Точность")
        tree.heading("rating", text="Рейтинг")
        tree.column("username", width=150)
        tree.column("sales", width=100, anchor="center")
        tree.column("sum", width=120, anchor="e")
        tree.column("avg_time", width=120, anchor="center")
        tree.column("accuracy", width=100, anchor="center")
        tree.column("rating", width=120, anchor="center")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for cashier_id, username, sales_count, total_sum, avg_time, success_scans, failed_scans in cashier_stats:
            sales_count = sales_count or 0
            total_sum = total_sum or 0
            avg_time = avg_time or 0
            total_scans = (success_scans or 0) + (failed_scans or 0)
            accuracy = (success_scans / total_scans * 100) if total_scans > 0 else 100
            time_score = max(0, 20 - avg_time) * 2 if avg_time > 0 else 0
            accuracy_score = accuracy * 0.5
            sales_score = min(sales_count * 2, 30)
            rating = min(100, int(time_score + accuracy_score + sales_score))
            tags = ()
            if rating >= 80:
                tags = ("excellent",)
            elif rating >= 60:
                tags = ("good",)
            elif rating >= 40:
                tags = ("average",)
            else:
                tags = ("poor",)
            tree.insert("", "end", values=(
                username,
                sales_count,
                f"{total_sum:.2f}",
                f"{avg_time:.1f} сек" if avg_time > 0 else "—",
                f"{accuracy:.1f}%",
                f"{rating}/100"
            ), tags=tags)
        tree.tag_configure("excellent", background="#e8f5e9", foreground="#2e7d32")
        tree.tag_configure("good", background="#f1f8e9", foreground="#558b2f")
        tree.tag_configure("average", background="#fffde7", foreground="#f57f17")
        tree.tag_configure("poor", background="#ffebee", foreground="#c62828")
        legend_frame = ttk.Frame(self.content_frame)
        legend_frame.pack(fill=tk.X, pady=10)
        ratings = [
            ("🏆 Отлично (80-100)", "#2e7d32"),
            ("👍 Хорошо (60-79)", "#558b2f"),
            ("😐 Удовл. (40-59)", "#f57f17"),
            ("👎 Нужно улучшить (<40)", "#c62828")
        ]
        for text, color in ratings:
            lbl = ttk.Label(legend_frame, text=text, font=("Arial", 9))
            lbl.pack(side=tk.LEFT, padx=15)
            lbl.configure(foreground=color)
        ttk.Button(self.footer_frame, text="Назад", command=self.cashier_stats, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.footer_frame, text="Экспорт в CSV", command=self.export_cashier_stats, width=20).pack(side=tk.LEFT, padx=10)

    def export_cashier_stats(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может экспортировать статистику")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv")],
            title="Сохранить статистику кассиров"
        )
        if not filename:
            return
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT 
                u.username,
                COUNT(s.id) as sales_count,
                SUM(s.total) as total_sum,
                AVG(s.sale_duration),
                COUNT(CASE WHEN sl.success = 1 THEN 1 END) as success_scans,
                COUNT(CASE WHEN sl.success = 0 THEN 1 END) as failed_scans
            FROM users u
            LEFT JOIN sales s ON s.cashier_id = u.id AND DATE(s.timestamp) = DATE('now')
            LEFT JOIN scan_logs sl ON sl.cashier_id = u.id AND DATE(sl.scan_time) = DATE('now')
            WHERE u.role = 'cashier'
            GROUP BY u.id
            ORDER BY sales_count DESC
        """)
        stats = cursor.fetchall()
        cursor.close()
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["Кассир", "Продаж за день", "Оборот, ₽", "Среднее время, сек", 
                           "Успешных сканирований", "Ошибок сканирования", "Точность, %"])
            for username, sales_count, total_sum, avg_time, success_scans, failed_scans in stats:
                sales_count = sales_count or 0
                total_sum = total_sum or 0
                avg_time = avg_time or 0
                success_scans = success_scans or 0
                failed_scans = failed_scans or 0
                total_scans = success_scans + failed_scans
                accuracy = (success_scans / total_scans * 100) if total_scans > 0 else 100
                writer.writerow([
                    username,
                    sales_count,
                    f"{total_sum:.2f}",
                    f"{avg_time:.2f}" if avg_time > 0 else "0",
                    success_scans,
                    failed_scans,
                    f"{accuracy:.1f}"
                ])
        messagebox.showinfo("Успех", f"Статистика кассиров сохранена в файл:\n{filename}")

    # === УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ===
    def manage_users(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может управлять пользователями")
            return
        
        self.create_standard_layout("Управление пользователями")
        
        # === Форма добавления пользователя ===
        add_frame = ttk.LabelFrame(self.content_frame, text="Добавить нового пользователя", padding=15)
        add_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(add_frame, text="Логин:", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=8)
        username_entry = ttk.Entry(add_frame, width=30, font=("Arial", 11))
        username_entry.grid(row=0, column=1, padx=10, pady=8)
        
        ttk.Label(add_frame, text="Пароль:", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=8)
        password_entry = ttk.Entry(add_frame, width=30, font=("Arial", 11), show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=8)
        
        ttk.Label(add_frame, text="Роль:", font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=8)
        role_var = tk.StringVar(value="cashier")
        ttk.Radiobutton(add_frame, text="Кассир", variable=role_var, value="cashier").grid(row=2, column=1, sticky=tk.W)
        ttk.Radiobutton(add_frame, text="Администратор", variable=role_var, value="admin").grid(row=2, column=1, sticky=tk.W, padx=(100, 0))
        
        # Только супер-админ и создатель могут создавать других супер-админов
        super_admin_var = tk.BooleanVar(value=False)
        if self.current_user['is_super_admin'] or self.current_user['is_creator']:
            ttk.Label(add_frame, text="Супер-админ:", font=("Arial", 11)).grid(row=3, column=0, sticky=tk.W, pady=8)
            ttk.Checkbutton(add_frame, variable=super_admin_var, text="Да, сделать супер-админом").grid(row=3, column=1, sticky=tk.W)
        
        # Только создатель может создавать других создателей (только себя!)
        creator_var = tk.BooleanVar(value=False)
        if self.current_user['is_creator']:
            ttk.Label(add_frame, text="Создатель:", font=("Arial", 11)).grid(row=4, column=0, sticky=tk.W, pady=8)
            ttk.Checkbutton(add_frame, variable=creator_var, text="Да, сделать создателем (только для себя!)").grid(row=4, column=1, sticky=tk.W)
        
        def add_user():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            role = role_var.get()
            
            if not username or not password:
                messagebox.showerror("Ошибка", "Заполните все поля")
                return
            
            if len(password) < 4:
                messagebox.showerror("Ошибка", "Пароль должен содержать минимум 4 символа")
                return
            
            # Проверка прав на создание админов
            if role == "admin" and not (self.current_user['is_super_admin'] or self.current_user['is_creator']):
                messagebox.showerror("Доступ запрещен", "Только супер-админ или создатель могут создавать администраторов")
                return
            
            # Проверка прав на создание супер-админов
            is_super_admin = super_admin_var.get()
            if is_super_admin and not (self.current_user['is_super_admin'] or self.current_user['is_creator']):
                messagebox.showerror("Доступ запрещен", "Только супер-админ или создатель могут создавать других супер-админов")
                return
            
            # Проверка прав на создание создателей
            is_creator = creator_var.get()
            if is_creator and not self.current_user['is_creator']:
                messagebox.showerror("Доступ запрещен", "Только создатель программы может создавать других создателей")
                return
            
            if is_creator and username != self.current_user['username']:
                messagebox.showerror("Ошибка", "Создателем можно сделать ТОЛЬКО себя")
                return
            
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            cursor = self.db_conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, role, is_super_admin, is_creator) 
                    VALUES (?, ?, ?, ?, ?)
                """, (username, pwd_hash, role, is_super_admin, is_creator))
                self.db_conn.commit()
                type_text = "создатель" if is_creator else ("супер-админ" if is_super_admin else role)
                messagebox.showinfo("Успех", f"Пользователь '{username}' добавлен как {type_text}")
                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                load_users()
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка", f"Пользователь '{username}' уже существует")
        
        ttk.Button(add_frame, text="Добавить пользователя", command=add_user, width=25).grid(row=5, column=0, columnspan=2, pady=15)
        
        # === Таблица пользователей ===
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        tree = ttk.Treeview(tree_frame, columns=("id", "username", "role", "type", "created"), 
                          show="headings", yscrollcommand=vsb.set)
        vsb.config(command=tree.yview)
        
        tree.heading("id", text="ID")
        tree.heading("username", text="Логин")
        tree.heading("role", text="Роль")
        tree.heading("type", text="Тип")
        tree.heading("created", text="Добавлен")
        
        tree.column("id", width=50, anchor="center")
        tree.column("username", width=180)
        tree.column("role", width=100, anchor="center")
        tree.column("type", width=120, anchor="center")
        tree.column("created", width=160, anchor="center")
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Контекстное меню для удаления
        context_menu = Menu(self.root, tearoff=0)
        context_menu.add_command(label="Удалить пользователя", command=lambda: delete_user(tree))
        
        def delete_user(tree_widget):
            selected = tree_widget.selection()
            if not selected:
                return
            
            item = tree_widget.item(selected[0])
            user_id = item['values'][0]
            username = item['values'][1]
            role = item['values'][2]
            user_type = item['values'][3]
            
            # === ЗАЩИТА: нельзя удалить себя ===
            if user_id == self.current_user['id']:
                messagebox.showerror("Ошибка", "❌ Нельзя удалить текущего пользователя")
                return
            
            # === ЗАЩИТА: нельзя удалить создателя (вас) ===
            if username == "Archmage1337":
                messagebox.showerror("Ошибка", "❌ Нельзя удалить учётную запись создателя программы (Archmage1337)")
                return
            
            # === НОВАЯ ЛОГИКА: обычные админы НЕ могут удалять других админов ===
            if self.current_user['role'] == 'admin' and not self.current_user['is_super_admin'] and role == "admin":
                messagebox.showerror("Доступ запрещен", "Обычные админы не могут удалять других администраторов")
                return
            
            # === НОВАЯ ЛОГИКА: супер-админы НЕ могут удалять других супер-админов (кроме создателя) ===
            if (self.current_user['is_super_admin'] or self.current_user['is_creator']) and "Супер-админ" in user_type and not self.current_user['is_creator']:
                messagebox.showerror("Доступ запрещен", "Супер-админ не может удалять других супер-админов")
                return
            
            # === ЗАЩИТА: супер-админы НЕ могут удалять создателей ===
            if (self.current_user['is_super_admin'] or self.current_user['is_creator']) and "Создатель" in user_type:
                messagebox.showerror("Ошибка", "❌ Нельзя удалить учётную запись создателя программы")
                return
            
            # Проверка: последний ли это админ?
            cursor = self.db_conn.cursor()
            if role == "admin":
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                if cursor.fetchone()[0] == 1:
                    messagebox.showerror("Ошибка", "Нельзя удалить последнего администратора системы")
                    return
            
            # Проверка: есть ли продажи у пользователя
            cursor.execute("SELECT COUNT(*) FROM sales WHERE cashier_id = ?", (user_id,))
            sales_count = cursor.fetchone()[0]
            
            warning = f"Вы уверены, что хотите удалить пользователя '{username}' ({role})?"
            if sales_count > 0:
                warning += f"\n\n⚠️ У пользователя есть {sales_count} продаж в истории."
                warning += "\nУдаление пользователя не удалит его продажи, но они будут привязаны к 'неизвестному кассиру'."
            
            if messagebox.askyesno("Подтверждение удаления", warning):
                try:
                    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    self.db_conn.commit()
                    messagebox.showinfo("Успех", f"Пользователь '{username}' удалён")
                    load_users()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось удалить пользователя: {str(e)}")
        
        tree.bind("<Button-3>", lambda e: self.show_tree_context_menu(e, tree, context_menu))
        
        def load_users():
            for item in tree.get_children():
                tree.delete(item)
            cursor = self.db_conn.cursor()
            cursor.execute("""
                SELECT id, username, role, is_super_admin, is_creator, strftime('%d.%m.%Y %H:%M', created_at) 
                FROM users 
                ORDER BY is_creator DESC, is_super_admin DESC, role DESC, username
            """)
            for row in cursor.fetchall():
                user_type = "👑 Создатель" if row[4] else ("🔴 Супер-админ" if row[3] else row[2])
                tags = ("creator",) if row[4] else ("super_admin",) if row[3] else ("admin",) if row[2] == "admin" else ()
                tree.insert("", "end", values=(row[0], row[1], row[2], user_type, row[5]), tags=tags)
            tree.tag_configure("creator", background="#f3e5f5", foreground="#6a1b9a", font=("Arial", 10, "bold"))
            tree.tag_configure("super_admin", background="#ffebee", foreground="#c62828")
            tree.tag_configure("admin", background="#e3f2fd", foreground="#1565c0")
        
        load_users()
        
        # === КНОПКИ В ФУТЕРЕ ===
        ttk.Button(self.footer_frame, text="Обновить", command=load_users, width=15).pack(side=tk.LEFT, padx=8)
        if self.current_user['is_creator']:
            ttk.Button(self.footer_frame, text="Очистить тестовые данные", 
                      command=self.clear_test_data, width=25).pack(side=tk.LEFT, padx=8)
            ttk.Button(self.footer_frame, text="Создать супер-админа", 
                      command=self.create_super_admin, width=20).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="Назад", command=self.main_menu, width=15).pack(side=tk.LEFT, padx=8)

    def create_super_admin(self):
        """Создание нового супер-админа (только для создателя)"""
        if not self.current_user['is_creator']:
            messagebox.showerror("Доступ запрещен", "Только создатель программы может создавать супер-админов")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Создать нового супер-админа")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Логин:", font=("Arial", 11)).pack(pady=8)
        username_entry = ttk.Entry(dialog, width=30, font=("Arial", 11))
        username_entry.pack(pady=5)
        username_entry.focus()
        
        ttk.Label(dialog, text="Пароль:", font=("Arial", 11)).pack(pady=8)
        password_entry = ttk.Entry(dialog, width=30, font=("Arial", 11), show="*")
        password_entry.pack(pady=5)
        
        def create():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            
            if not username or not password:
                messagebox.showerror("Ошибка", "Заполните все поля")
                return
            
            if len(password) < 4:
                messagebox.showerror("Ошибка", "Пароль должен содержать минимум 4 символа")
                return
            
            if username == "Archmage1337":
                messagebox.showerror("Ошибка", "Неверный логин. Используйте другое имя.")
                return
            
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            cursor = self.db_conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, role, is_super_admin, is_creator) 
                    VALUES (?, ?, ?, ?, 0)
                """, (username, pwd_hash, "admin", 1))
                self.db_conn.commit()
                messagebox.showinfo("Успех", f"Супер-админ '{username}' создан")
                dialog.destroy()
                # Обновляем таблицу пользователей
                for item in tree.get_children():
                    tree.delete(item)
                cursor.execute("""
                    SELECT id, username, role, is_super_admin, is_creator, strftime('%d.%m.%Y %H:%M', created_at) 
                    FROM users 
                    ORDER BY is_creator DESC, is_super_admin DESC, role DESC, username
                """)
                for row in cursor.fetchall():
                    user_type = "👑 Создатель" if row[4] else ("🔴 Супер-админ" if row[3] else row[2])
                    tags = ("creator",) if row[4] else ("super_admin",) if row[3] else ("admin",) if row[2] == "admin" else ()
                    tree.insert("", "end", values=(row[0], row[1], row[2], user_type, row[5]), tags=tags)
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка", f"Пользователь '{username}' уже существует")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Создать супер-админа", command=create, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy, width=15).pack(side=tk.LEFT, padx=10)
        dialog.wait_window()

    def clear_test_data(self):
        if not self.current_user['is_creator']:
            messagebox.showerror("Доступ запрещен", "Только создатель программы может очищать тестовые данные")
            return
        if not messagebox.askyesno("Очистка тестовых данных", 
            "⚠️ ВНИМАНИЕ! Эта операция удалит ВСЕ продажи и логи сканирования.\n"
            "Товары и пользователи сохранятся.\n"
            "Вы уверены, что хотите продолжить?"):
            return
        cursor = self.db_conn.cursor()
        try:
            cursor.execute("DELETE FROM sales")
            cursor.execute("DELETE FROM scan_logs")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='sales'")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='scan_logs'")
            self.db_conn.commit()
            messagebox.showinfo("Успех", "Все тестовые данные успешно очищены!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось очистить данные: {str(e)}")

    # === КАТАЛОГ ТОВАРОВ ===
    def view_products(self):
        self.create_standard_layout("Каталог товаров")
        search_frame = ttk.Frame(self.content_frame)
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Поиск:", font=("Arial", 10)).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_products())
        ttk.Entry(search_frame, textvariable=self.search_var, width=50, font=("Arial", 11)).pack(side=tk.LEFT, padx=10)
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        self.products_tree = ttk.Treeview(tree_frame, columns=("id", "barcode", "name", "price", "stock", "age18"),
                                        show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.products_tree.yview)
        hsb.config(command=self.products_tree.xview)
        self.products_tree.heading("id", text="ID")
        self.products_tree.heading("barcode", text="Штрих-код")
        self.products_tree.heading("name", text="Название")
        self.products_tree.heading("price", text="Цена, ₽")
        self.products_tree.heading("stock", text="Остаток")
        self.products_tree.heading("age18", text="18+")
        self.products_tree.column("id", width=50, anchor="center")
        self.products_tree.column("barcode", width=130, anchor="center")
        self.products_tree.column("name", width=380)
        self.products_tree.column("price", width=100, anchor="e")
        self.products_tree.column("stock", width=100, anchor="center")
        self.products_tree.column("age18", width=60, anchor="center")
        self.products_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        if self.current_user['role'] == 'admin':
            self.products_tree.bind("<Button-3>", self.show_product_context_menu)
            self.product_context_menu = Menu(self.root, tearoff=0)
            self.product_context_menu.add_command(label="Удалить товар", command=self.delete_selected_product)
            self.product_context_menu.add_command(label="Редактировать остаток", command=self.edit_stock)
        self.load_products_data()
        ttk.Button(self.footer_frame, text="Обновить", command=self.load_products_data, width=15).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="Назад", command=self.main_menu, width=15).pack(side=tk.LEFT, padx=8)
        if self.current_user['role'] in ('admin', 'cashier'):
            ttk.Button(self.footer_frame, text="Добавить товар", command=self.add_product_screen, width=15).pack(side=tk.LEFT, padx=8)
        if self.current_user['role'] == 'admin':
            ttk.Button(self.footer_frame, text="Экспорт в CSV", command=self.export_products_to_csv, width=15).pack(side=tk.LEFT, padx=8)

    def show_product_context_menu(self, event):
        item = self.products_tree.identify_row(event.y)
        if item:
            self.products_tree.selection_set(item)
            self.product_context_menu.post(event.x_root, event.y_root)

    def load_products_data(self):
        for item in self.products_tree.get_children():
            self.products_tree.delete(item)
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT id, barcode, name, price, stock, requires_18plus
            FROM products
            WHERE deleted = 0
            ORDER BY name
        """)
        products = cursor.fetchall()
        for product in products:
            age18_tag = "🔞" if product[5] else ""
            tags = ("age18",) if product[5] else ()
            self.products_tree.insert("", "end", values=product, tags=tags)
        self.products_tree.tag_configure("age18", background="#ffebee", foreground="#c62828")
        total_items = len(products)
        total_stock = sum(p[4] for p in products)
        total_value = sum(p[3] * p[4] for p in products)
        self.stats_label.config(text=f"Всего товаров: {total_items} | Общий остаток: {total_stock} шт | Стоимость остатков: {total_value:.2f}₽")

    def filter_products(self):
        search_term = self.search_var.get().lower()
        for item in self.products_tree.get_children():
            self.products_tree.delete(item)
        cursor = self.db_conn.cursor()
        if search_term:
            cursor.execute("""
                SELECT id, barcode, name, price, stock, requires_18plus
                FROM products
                WHERE deleted = 0 AND (LOWER(barcode) LIKE ? OR LOWER(name) LIKE ?)
                ORDER BY name
            """, (f"%{search_term}%", f"%{search_term}%"))
        else:
            cursor.execute("""
                SELECT id, barcode, name, price, stock, requires_18plus
                FROM products
                WHERE deleted = 0
                ORDER BY name
            """)
        products = cursor.fetchall()
        for product in products:
            age18_tag = "🔞" if product[5] else ""
            tags = ("age18",) if product[5] else ()
            self.products_tree.insert("", "end", values=product, tags=tags)
        total_items = len(products)
        total_stock = sum(p[4] for p in products)
        total_value = sum(p[3] * p[4] for p in products)
        self.stats_label.config(text=f"Найдено: {total_items} | Остаток: {total_stock} шт | Стоимость: {total_value:.2f}₽")

    def delete_selected_product(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может удалять товары")
            return
        selected = self.products_tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Сначала выберите товар для удаления")
            return
        item = self.products_tree.item(selected[0])
        product_id = item['values'][0]
        product_name = item['values'][2]
        product_stock = item['values'][4]
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sales WHERE product_id = ?", (product_id,))
        sales_count = cursor.fetchone()[0]
        if sales_count > 0:
            if not messagebox.askyesno("Внимание",
                f"По товару '{product_name}' есть {sales_count} продаж в истории.\n\n"
                f"Удаление товара НЕ удалит историю продаж, но записи будут помечены как '[УДАЛЁН]'.\n"
                f"Продолжить удаление?"):
                return
        if product_stock > 0:
            if not messagebox.askyesno("Внимание",
                f"Товар '{product_name}' имеет остаток {product_stock} шт.\n"
                f"Удаление приведет к безвозвратной потере товара со склада!\n"
                f"Вы уверены?"):
                return
        if not messagebox.askyesno("Подтверждение удаления",
            f"Вы действительно хотите удалить товар:\n'{product_name}'?\n\n"
            f"⚠️ Товар будет перемещён в раздел 'Удалённые товары'"):
            return
        try:
            cursor.execute("""
                UPDATE products 
                SET deleted = 1, deleted_by = ?, deleted_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (self.current_user['id'], product_id))
            cursor.execute("UPDATE sales SET product_id = NULL, is_deleted_record = 1 WHERE product_id = ?", (product_id,))
            self.db_conn.commit()
            messagebox.showinfo("Успех", f"Товар '{product_name}' перемещён в раздел 'Удалённые товары'")
            self.load_products_data()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось удалить товар: {str(e)}")

    def edit_stock(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может редактировать остатки")
            return
        selected = self.products_tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Сначала выберите товар для редактирования")
            return
        item = self.products_tree.item(selected[0])
        product_id = item['values'][0]
        product_name = item['values'][2]
        current_stock = item['values'][4]
        new_stock = simpledialog.askinteger(
            "Редактировать остаток",
            f"Товар: {product_name}\nТекущий остаток: {current_stock} шт\nВведите новый остаток:",
            initialvalue=current_stock,
            minvalue=0
        )
        if new_stock is None:
            return
        if new_stock < 0:
            messagebox.showerror("Ошибка", "Остаток не может быть отрицательным")
            return
        cursor = self.db_conn.cursor()
        cursor.execute("UPDATE products SET stock = ? WHERE id = ?", (new_stock, product_id))
        self.db_conn.commit()
        messagebox.showinfo("Успех", f"Остаток товара '{product_name}' обновлен до {new_stock} шт")
        self.load_products_data()

    def add_product_screen(self):
        self.create_standard_layout("Добавить новый товар")
        form_frame = ttk.Frame(self.content_frame)
        form_frame.pack(padx=30, pady=20, fill=tk.X)
        fields = [
            ("Штрих-код *", "barcode"),
            ("Название товара *", "name"),
            ("Цена (₽) *", "price"),
            ("Остаток на складе", "stock"),
            ("Вейп-товар (требует 18+)", "requires_18plus")
        ]
        self.product_entries = {}
        row = 0
        for label_text, field_name in fields:
            ttk.Label(form_frame, text=label_text, font=("Arial", 11)).grid(row=row, column=0, sticky=tk.W, pady=12)
            if field_name == "requires_18plus":
                var = tk.BooleanVar(value=False)
                chk = ttk.Checkbutton(form_frame, variable=var)
                chk.grid(row=row, column=1, sticky=tk.W, padx=15, pady=12)
                self.product_entries[field_name] = var
            else:
                entry = ttk.Entry(form_frame, width=45, font=("Arial", 12))
                if field_name == "stock":
                    entry.insert(0, "0")
                entry.grid(row=row, column=1, sticky=tk.W, pady=12, padx=15)
                self.product_entries[field_name] = entry
            row += 1
        ttk.Button(self.footer_frame, text="Добавить товар", command=self.save_new_product, width=20).pack(side=tk.LEFT, padx=10)
        ttk.Button(self.footer_frame, text="Отмена", command=self.main_menu, width=20).pack(side=tk.LEFT, padx=10)

    def save_new_product(self):
        barcode = self.product_entries["barcode"].get().strip()
        name = self.product_entries["name"].get().strip()
        price = self.product_entries["price"].get().strip()
        stock = self.product_entries["stock"].get().strip()
        requires_18plus = self.product_entries["requires_18plus"].get()
        
        if not all([barcode, name, price]):
            messagebox.showerror("Ошибка", "Заполните все обязательные поля (отмечены *)")
            return
        
        try:
            price = float(price)
            stock = int(stock)
            if price <= 0:
                messagebox.showerror("Ошибка", "Цена должна быть больше 0")
                return
            if stock < 0:
                messagebox.showerror("Ошибка", "Остаток не может быть отрицательным")
                return
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректная цена или остаток (используйте числа)")
            return
        
        cursor = self.db_conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO products (barcode, name, price, stock, requires_18plus, deleted) 
                VALUES (?, ?, ?, ?, ?, 0)
            """, (barcode, name, price, stock, requires_18plus))
            self.db_conn.commit()
            msg = f"Товар '{name}' добавлен в каталог"
            if requires_18plus:
                msg += "\n⚠️ Требуется проверка 18+ и маркировка при продаже"
            messagebox.showinfo("Успех", msg)
            self.view_products()
        except sqlite3.IntegrityError:
            messagebox.showerror("Ошибка", f"Штрих-код '{barcode}' уже существует в системе")

    def export_products_to_csv(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может экспортировать данные")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv")],
            title="Сохранить каталог товаров"
        )
        if not filename:
            return
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT barcode, name, price, stock, requires_18plus
            FROM products
            WHERE deleted = 0
            ORDER BY name
        """)
        products = cursor.fetchall()
        cursor.close()
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["Штрих-код", "Название", "Цена, ₽", "Остаток, шт", "Требует 18+"])
            for product in products:
                age18 = "Да" if product[4] else "Нет"
                writer.writerow([product[0], product[1], f"{product[2]:.2f}", product[3], age18])
        messagebox.showinfo("Успех", f"Каталог сохранен в файл:\n{filename}")

    # === ЧЕКИ ===
    def view_receipts(self):
        self.create_standard_layout("🧾 Чеки")
        filter_frame = ttk.Frame(self.content_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        ttk.Label(filter_frame, text="Период:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.period_var = tk.StringVar(value="today")
        periods = [("Сегодня", "today"), ("Вчера", "yesterday"), ("Неделя", "week"),
                  ("Месяц", "month"), ("Все время", "all")]
        for text, value in periods:
            ttk.Radiobutton(filter_frame, text=text, variable=self.period_var, value=value,
                          command=self.load_receipts).pack(side=tk.LEFT, padx=8)
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        self.receipts_tree = ttk.Treeview(tree_frame, columns=("id", "time", "product", "qty", "total", "payment", "cashier"),
                                        show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.receipts_tree.yview)
        hsb.config(command=self.receipts_tree.xview)
        self.receipts_tree.heading("id", text="№ Чека")
        self.receipts_tree.heading("time", text="Дата/Время")
        self.receipts_tree.heading("product", text="Товар")
        self.receipts_tree.heading("qty", text="Кол-во")
        self.receipts_tree.heading("total", text="Сумма, ₽")
        self.receipts_tree.heading("payment", text="Оплата")
        self.receipts_tree.heading("cashier", text="Кассир")
        self.receipts_tree.column("id", width=70, anchor="center")
        self.receipts_tree.column("time", width=130, anchor="center")
        self.receipts_tree.column("product", width=300)
        self.receipts_tree.column("qty", width=70, anchor="center")
        self.receipts_tree.column("total", width=100, anchor="e")
        self.receipts_tree.column("payment", width=90, anchor="center")
        self.receipts_tree.column("cashier", width=110)
        self.receipts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.receipts_tree.bind("<Double-1>", self.show_receipt_details)
        self.load_receipts()
        ttk.Button(self.footer_frame, text="Обновить", command=self.load_receipts, width=15).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="Назад", command=self.main_menu, width=15).pack(side=tk.LEFT, padx=8)
        if self.current_user['role'] == 'admin':
            ttk.Button(self.footer_frame, text="Экспорт в CSV", command=self.export_receipts_to_csv, width=15).pack(side=tk.LEFT, padx=8)

    def load_receipts(self):
        period = self.period_var.get()
        now = datetime.now()
        if period == "today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "yesterday":
            yesterday = now - timedelta(days=1)
            start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif period == "week":
            start_date = now - timedelta(days=7)
        elif period == "month":
            start_date = now - timedelta(days=30)
        for item in self.receipts_tree.get_children():
            self.receipts_tree.delete(item)
        cursor = self.db_conn.cursor()
        if self.current_user['role'] == 'admin':
            if period == "today":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ?
                    ORDER BY s.timestamp DESC
                """, (start_date,))
            elif period == "yesterday":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp BETWEEN ? AND ?
                    ORDER BY s.timestamp DESC
                """, (start_date, end_date))
            elif period in ("week", "month"):
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ?
                    ORDER BY s.timestamp DESC
                """, (start_date,))
            else:
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    ORDER BY s.timestamp DESC
                """)
        else:
            if period == "today":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, self.current_user['id']))
            elif period == "yesterday":
                yesterday = now - timedelta(days=1)
                start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
                end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp BETWEEN ? AND ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, end_date, self.current_user['id']))
            elif period in ("week", "month"):
                start_date = now - timedelta(days=7 if period == "week" else 30)
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, self.current_user['id']))
            else:
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (self.current_user['id'],))
        receipts = cursor.fetchall()
        cursor.close()
        for receipt in receipts:
            receipt_id = receipt[0]
            timestamp = datetime.strptime(receipt[1], '%Y-%m-%d %H:%M:%S').strftime('%d.%m %H:%M')
            product_name = receipt[2] if receipt[2] else f"[УДАЛЁН] ID:{receipt_id}"
            quantity = receipt[3]
            total = receipt[4]
            payment = "Наличные" if receipt[5] == "cash" else "Карта"
            cashier = receipt[6] if self.current_user['role'] == 'admin' else "Я"
            self.receipts_tree.insert("", "end", values=(receipt_id, timestamp, product_name, quantity,
                                                       f"{total:.2f}", payment, cashier))
        total_receipts = len(receipts)
        total_sum = sum(r[4] for r in receipts) if receipts else 0
        self.stats_label.config(text=f"Чеков за период: {total_receipts} | Общая сумма: {total_sum:.2f}₽")

    def show_receipt_details(self, event):
        selected = self.receipts_tree.selection()
        if not selected:
            return
        item = self.receipts_tree.item(selected[0])
        values = item['values']
        receipt_id = values[0]
        timestamp = values[1]
        product_name = values[2]
        quantity = values[3]
        total = values[4]
        payment = values[5]
        cashier = values[6]
        
        # Получаем дополнительные данные из БД
        cursor = self.db_conn.cursor()
        cursor.execute("""
            SELECT s.quantity, s.total, s.payment_type, s.buyer_18verified, s.marking_code_used, s.timestamp
            FROM sales s
            WHERE s.id = ?
        """, (receipt_id,))
        sale_data = cursor.fetchone()
        cursor.close()
        
        if not sale_data:
            messagebox.showerror("Ошибка", "Данные чека не найдены")
            return
        
        is_18plus = bool(sale_data[3])
        marking_code = sale_data[4]
        
        # Диалог с деталями чека
        dialog = tk.Toplevel(self.root)
        dialog.title(f"🧾 Чек №{receipt_id}")
        dialog.geometry("450x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Заголовок чека
        ttk.Label(dialog, text="🧾 ДЕТАЛИ ЧЕКА", font=("Arial", 16, "bold")).pack(pady=10)
        ttk.Separator(dialog, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=5)
        
        # Информация о чеке
        info_frame = ttk.Frame(dialog)
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        details = [
            ("Номер чека:", str(receipt_id)),
            ("Дата и время:", timestamp),
            ("Кассир:", cashier),
            ("Товар:", product_name),
            ("Количество:", str(quantity)),
            ("Сумма:", f"{total} ₽"),
            ("Оплата:", payment),
        ]
        
        if is_18plus:
            details.append(("Возраст:", "✅ Подтверждён 18+ (паспорт проверен)"))
        if marking_code:
            details.append(("Маркировка:", f"...{marking_code[-6:]}"))
        
        for label, value in details:
            row_frame = ttk.Frame(info_frame)
            row_frame.pack(fill=tk.X, pady=3)
            ttk.Label(row_frame, text=label, font=("Arial", 10, "bold"), width=18, anchor="w").pack(side=tk.LEFT)
            ttk.Label(row_frame, text=value, font=("Arial", 10)).pack(side=tk.LEFT)
        
        # Предупреждение для вейп-товаров
        if is_18plus:
            warning_frame = ttk.Frame(dialog, padding=10)
            warning_frame.pack(fill=tk.X, padx=20, pady=10)
            ttk.Label(warning_frame, text="⚠️ Продажа вейп-продуктов несовершеннолетним запрещена!", 
                     font=("Arial", 10, "bold"), foreground="#c62828").pack()
            ttk.Label(warning_frame, text="Статья 19.15 КоАП РФ", 
                     font=("Arial", 9), foreground="#555").pack()
        
        # Кнопки
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(btn_frame, text="Закрыть", command=dialog.destroy, width=15).pack()

    def export_receipts_to_csv(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может экспортировать данные")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv")],
            title="Сохранить чеки в CSV"
        )
        if not filename:
            return
        period = self.period_var.get()
        now = datetime.now()
        cursor = self.db_conn.cursor()
        if period == "today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.buyer_18verified, s.marking_code_used
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp >= ?
                ORDER BY s.timestamp DESC
            """, (start_date,))
        elif period == "yesterday":
            yesterday = now - timedelta(days=1)
            start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.buyer_18verified, s.marking_code_used
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp BETWEEN ? AND ?
                ORDER BY s.timestamp DESC
            """, (start_date, end_date))
        elif period in ("week", "month"):
            start_date = now - timedelta(days=7 if period == "week" else 30)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.buyer_18verified, s.marking_code_used
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp >= ?
                ORDER BY s.timestamp DESC
            """, (start_date,))
        else:
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.buyer_18verified, s.marking_code_used
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                ORDER BY s.timestamp DESC
            """)
        receipts = cursor.fetchall()
        cursor.close()
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["Дата/Время", "Товар", "Количество", "Сумма, ₽", "Оплата", "Кассир", "18+ подтверждён", "Код маркировки"])
            for receipt in receipts:
                timestamp = datetime.strptime(receipt[0], '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y %H:%M')
                product_name = receipt[1] if receipt[1] else f"[УДАЛЁН]"
                payment = "Наличные" if receipt[4] == "cash" else "Карта"
                age18 = "Да" if receipt[6] else "Нет"
                marking_code = receipt[7] or "—"
                writer.writerow([timestamp, product_name, receipt[2], f"{receipt[3]:.2f}", payment, receipt[5], age18, marking_code])
        messagebox.showinfo("Успех", f"Чеки сохранены в файл:\n{filename}")

    # === ИСТОРИЯ ПРОДАЖ ===
    def view_sales_history(self):
        self.create_standard_layout("История продаж")
        period_frame = ttk.Frame(self.content_frame)
        period_frame.pack(fill=tk.X, pady=5)
        ttk.Label(period_frame, text="Период:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        self.period_var = tk.StringVar(value="today")
        periods = [("Сегодня", "today"), ("Вчера", "yesterday"), ("Неделя", "week"),
                  ("Месяц", "month"), ("Все время", "all")]
        for text, value in periods:
            ttk.Radiobutton(period_frame, text=text, variable=self.period_var, value=value,
                          command=self.load_sales_data).pack(side=tk.LEFT, padx=8)
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        self.sales_tree = ttk.Treeview(tree_frame, columns=("id", "time", "product", "qty", "total", "payment", "cashier"),
                                     show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.sales_tree.yview)
        hsb.config(command=self.sales_tree.xview)
        self.sales_tree.heading("id", text="ID")
        self.sales_tree.heading("time", text="Дата/Время")
        self.sales_tree.heading("product", text="Товар")
        self.sales_tree.heading("qty", text="Кол-во")
        self.sales_tree.heading("total", text="Сумма, ₽")
        self.sales_tree.heading("payment", text="Оплата")
        self.sales_tree.heading("cashier", text="Кассир")
        self.sales_tree.column("id", width=50, anchor="center")
        self.sales_tree.column("time", width=140, anchor="center")
        self.sales_tree.column("product", width=350)
        self.sales_tree.column("qty", width=70, anchor="center")
        self.sales_tree.column("total", width=100, anchor="e")
        self.sales_tree.column("payment", width=90, anchor="center")
        self.sales_tree.column("cashier", width=110)
        self.sales_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        if self.current_user['is_super_admin'] or self.current_user['is_creator']:
            self.sales_tree.bind("<Button-3>", self.show_sales_context_menu)
            self.sales_context_menu = Menu(self.root, tearoff=0)
            self.sales_context_menu.add_command(label="Удалить запись (тестовые данные)", 
                                              command=self.delete_sale_record)
        self.load_sales_data()
        ttk.Button(self.footer_frame, text="Обновить", command=self.load_sales_data, width=15).pack(side=tk.LEFT, padx=8)
        ttk.Button(self.footer_frame, text="Назад", command=self.main_menu, width=15).pack(side=tk.LEFT, padx=8)
        if self.current_user['role'] == 'admin':
            ttk.Button(self.footer_frame, text="Экспорт в CSV", command=self.export_sales_to_csv, width=15).pack(side=tk.LEFT, padx=8)

    def show_sales_context_menu(self, event):
        if not (self.current_user['is_super_admin'] or self.current_user['is_creator']):
            return
        item = self.sales_tree.identify_row(event.y)
        if item:
            values = self.sales_tree.item(item)['values']
            if "[УДАЛЁН]" in str(values[2]):
                self.sales_tree.selection_set(item)
                self.sales_context_menu.post(event.x_root, event.y_root)

    def load_sales_data(self):
        period = self.period_var.get()
        now = datetime.now()
        if period == "today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "yesterday":
            yesterday = now - timedelta(days=1)
            start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
        elif period == "week":
            start_date = now - timedelta(days=7)
        elif period == "month":
            start_date = now - timedelta(days=30)
        for item in self.sales_tree.get_children():
            self.sales_tree.delete(item)
        cursor = self.db_conn.cursor()
        if self.current_user['role'] == 'admin':
            if period == "today":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ?
                    ORDER BY s.timestamp DESC
                """, (start_date,))
            elif period == "yesterday":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp BETWEEN ? AND ?
                    ORDER BY s.timestamp DESC
                """, (start_date, end_date))
            elif period in ("week", "month"):
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ?
                    ORDER BY s.timestamp DESC
                """, (start_date,))
            else:
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    ORDER BY s.timestamp DESC
                """)
        else:
            if period == "today":
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, self.current_user['id']))
            elif period == "yesterday":
                yesterday = now - timedelta(days=1)
                start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
                end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp BETWEEN ? AND ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, end_date, self.current_user['id']))
            elif period in ("week", "month"):
                start_date = now - timedelta(days=7 if period == "week" else 30)
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.timestamp >= ? AND s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (start_date, self.current_user['id']))
            else:
                cursor.execute("""
                    SELECT s.id, s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username, s.is_deleted_record
                    FROM sales s
                    LEFT JOIN products p ON s.product_id = p.id
                    LEFT JOIN users u ON s.cashier_id = u.id
                    WHERE s.cashier_id = ?
                    ORDER BY s.timestamp DESC
                """, (self.current_user['id'],))
        sales = cursor.fetchall()
        cursor.close()
        for sale in sales:
            sale_id = sale[0]
            timestamp = datetime.strptime(sale[1], '%Y-%m-%d %H:%M:%S').strftime('%d.%m %H:%M')
            product_name = sale[2] if sale[2] else f"[УДАЛЁН] ID:{sale_id}"
            quantity = sale[3]
            total = sale[4]
            payment = "Наличные" if sale[5] == "cash" else "Карта"
            cashier = sale[6] if self.current_user['role'] == 'admin' else "Я"
            is_deleted = sale[7]
            tags = ("deleted",) if is_deleted else ()
            self.sales_tree.insert("", "end", values=(sale_id, timestamp, product_name, quantity,
                                                    f"{total:.2f}", payment, cashier), tags=tags)
        self.sales_tree.tag_configure("deleted", foreground="#9e9e9e", font=("Arial", 9, "italic"))
        total_sales = len(sales)
        total_sum = sum(s[4] for s in sales) if sales else 0
        self.stats_label.config(text=f"Продаж за период: {total_sales} | Общая сумма: {total_sum:.2f}₽")

    def delete_sale_record(self):
        if not (self.current_user['is_super_admin'] or self.current_user['is_creator']):
            messagebox.showerror("Доступ запрещен", "Только супер-админы и создатель могут удалять записи из истории")
            return
        selected = self.sales_tree.selection()
        if not selected:
            return
        item = self.sales_tree.item(selected[0])
        values = item['values']
        sale_id = values[0]
        product_name = values[2]
        if "[УДАЛЁН]" not in str(product_name):
            messagebox.showwarning("Внимание", 
                "Можно удалять только записи с пометкой '[УДАЛЁН]'\n"
                "Это защита от случайного удаления реальных продаж.")
            return
        if not messagebox.askyesno("Подтверждение удаления",
            f"⚠️ ВНИМАНИЕ! Это действие БЕЗВОЗВРАТНО удалит запись из истории.\n\n"
            f"Вы уверены, что хотите продолжить?\n"
            f"Рекомендуется использовать только для очистки тестовых данных."):
            return
        cursor = self.db_conn.cursor()
        try:
            cursor.execute("DELETE FROM sales WHERE id = ?", (sale_id,))
            self.db_conn.commit()
            messagebox.showinfo("Успех", "Запись успешно удалена из истории")
            self.load_sales_data()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось удалить запись: {str(e)}")

    def export_sales_to_csv(self):
        if self.current_user['role'] != 'admin':
            messagebox.showerror("Доступ запрещен", "Только администратор может экспортировать данные")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV файлы", "*.csv")],
            title="Сохранить историю продаж"
        )
        if not filename:
            return
        period = self.period_var.get()
        now = datetime.now()
        cursor = self.db_conn.cursor()
        if period == "today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp >= ?
                ORDER BY s.timestamp DESC
            """, (start_date,))
        elif period == "yesterday":
            yesterday = now - timedelta(days=1)
            start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp BETWEEN ? AND ?
                ORDER BY s.timestamp DESC
            """, (start_date, end_date))
        elif period in ("week", "month"):
            start_date = now - timedelta(days=7 if period == "week" else 30)
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE s.timestamp >= ?
                ORDER BY s.timestamp DESC
            """, (start_date,))
        else:
            cursor.execute("""
                SELECT s.timestamp, p.name, s.quantity, s.total, s.payment_type, u.username
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                ORDER BY s.timestamp DESC
            """)
        sales = cursor.fetchall()
        cursor.close()
        with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(["Дата/Время", "Товар", "Количество", "Сумма, ₽", "Оплата", "Кассир"])
            for sale in sales:
                timestamp = datetime.strptime(sale[0], '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y %H:%M')
                product_name = sale[1] if sale[1] else f"[УДАЛЁН]"
                payment = "Наличные" if sale[4] == "cash" else "Карта"
                writer.writerow([timestamp, product_name, sale[2], f"{sale[3]:.2f}", payment, sale[5]])
        messagebox.showinfo("Успех", f"История продаж сохранена в файл:\n{filename}")

    # === РАЗДЕЛ УДАЛЁННЫХ ТОВАРОВ ===
    def view_deleted_products(self):
        if not (self.current_user['is_super_admin'] or self.current_user['is_creator']):
            messagebox.showerror("Доступ запрещен", "Только супер-админы и создатель могут просматривать удалённые товары")
            return
        
        self.create_standard_layout("🗑️ Удалённые товары из каталога")
        
        filter_frame = ttk.Frame(self.content_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        ttk.Label(filter_frame, text="Показать за период:", font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        period_var = tk.StringVar(value="all")
        periods = [("Все время", "all"), ("Сегодня", "today"), ("Неделя", "week"), ("Месяц", "month")]
        for text, value in periods:
            ttk.Radiobutton(filter_frame, text=text, variable=period_var, value=value,
                          command=lambda: load_deleted_products(period_var.get())).pack(side=tk.LEFT, padx=8)
        
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree = ttk.Treeview(tree_frame, columns=("id", "barcode", "name", "deleted_by", "deleted_at"),
                          show="headings", yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        tree.heading("id", text="ID")
        tree.heading("barcode", text="Штрих-код")
        tree.heading("name", text="Название")
        tree.heading("deleted_by", text="Удалил")
        tree.heading("deleted_at", text="Дата удаления")
        tree.column("id", width=50, anchor="center")
        tree.column("barcode", width=130, anchor="center")
        tree.column("name", width=380)
        tree.column("deleted_by", width=120)
        tree.column("deleted_at", width=160, anchor="center")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        context_menu = Menu(self.root, tearoff=0)
        context_menu.add_command(label="Восстановить товар", command=lambda: restore_product(tree))
        if self.current_user['is_creator']:
            context_menu.add_separator()
            context_menu.add_command(label="Полностью удалить (безвозвратно)", 
                                   command=lambda: permanently_delete_product(tree), 
                                   foreground="#c62828")
        
        def restore_product(tree_widget):
            selected = tree_widget.selection()
            if not selected:
                return
            item = tree_widget.item(selected[0])
            product_id = item['values'][0]
            product_name = item['values'][2]
            if not messagebox.askyesno("Восстановление товара",
                f"Вы уверены, что хотите восстановить товар '{product_name}' в каталог?\n"
                f"Товар вернётся с нулевым остатком."):
                return
            cursor = self.db_conn.cursor()
            try:
                cursor.execute("""
                    UPDATE products 
                    SET deleted = 0, deleted_by = NULL, deleted_at = NULL, stock = 0 
                    WHERE id = ?
                """, (product_id,))
                self.db_conn.commit()
                messagebox.showinfo("Успех", f"Товар '{product_name}' восстановлен в каталоге")
                load_deleted_products(period_var.get())
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось восстановить товар: {str(e)}")
        
        def permanently_delete_product(tree_widget):
            if not self.current_user['is_creator']:
                messagebox.showerror("Доступ запрещен", "Только создатель программы может полностью удалять товары")
                return
            selected = tree_widget.selection()
            if not selected:
                return
            item = tree_widget.item(selected[0])
            product_id = item['values'][0]
            product_name = item['values'][2]
            confirm = simpledialog.askstring("Подтверждение", 
                "⚠️ ВНИМАНИЕ! Это действие БЕЗВОЗВРАТНО удалит товар из базы данных.\n"
                "Все связанные продажи также будут удалены!\n"
                "Введите 'УДАЛИТЬ' для подтверждения:")
            if confirm != "УДАЛИТЬ":
                messagebox.showwarning("Отмена", "Удаление отменено")
                return
            cursor = self.db_conn.cursor()
            try:
                cursor.execute("DELETE FROM sales WHERE product_id = ?", (product_id,))
                cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
                self.db_conn.commit()
                messagebox.showinfo("Успех", f"Товар '{product_name}' полностью удалён из системы")
                load_deleted_products(period_var.get())
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось удалить товар: {str(e)}")
        
        tree.bind("<Button-3>", lambda e: self.show_tree_context_menu(e, tree, context_menu))
        
        def load_deleted_products(period):
            for item in tree.get_children():
                tree.delete(item)
            cursor = self.db_conn.cursor()
            query = """
                SELECT p.id, p.barcode, p.name, u.username, 
                       strftime('%d.%m.%Y %H:%M', p.deleted_at)
                FROM products p
                LEFT JOIN users u ON p.deleted_by = u.id
                WHERE p.deleted = 1
            """
            if period == "today":
                query += " AND DATE(p.deleted_at) = DATE('now')"
            elif period == "week":
                query += " AND p.deleted_at >= datetime('now', '-7 days')"
            elif period == "month":
                query += " AND p.deleted_at >= datetime('now', '-30 days')"
            query += " ORDER BY p.deleted_at DESC"
            cursor.execute(query)
            products = cursor.fetchall()
            for product in products:
                tree.insert("", "end", values=product)
            count = len(products)
            self.stats_label.config(text=f"Удалённых товаров: {count} | Показан период: {period}")
        
        load_deleted_products("all")
        btn_frame = ttk.Frame(self.footer_frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Обновить", command=lambda: load_deleted_products(period_var.get()), 
                  width=15).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="Назад", command=self.main_menu, width=15).pack(side=tk.LEFT, padx=8)

    def show_tree_context_menu(self, event, tree, menu):
        item = tree.identify_row(event.y)
        if item:
            tree.selection_set(item)
            menu.post(event.x_root, event.y_root)

    # === ОТЧЁТ ЗА ДЕНЬ ===
    def daily_report(self):
        self.create_standard_layout("Отчет за сегодня")
        today = datetime.now().strftime('%Y-%m-%d')
        cursor = self.db_conn.cursor()
        if self.current_user['role'] == 'admin':
            cursor.execute('''
                SELECT p.name, s.quantity, s.total, s.payment_type, u.username, s.timestamp
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                LEFT JOIN users u ON s.cashier_id = u.id
                WHERE DATE(s.timestamp) = ?
                ORDER BY s.timestamp DESC
            ''', (today,))
        else:
            cursor.execute('''
                SELECT p.name, s.quantity, s.total, s.payment_type, s.timestamp
                FROM sales s
                LEFT JOIN products p ON s.product_id = p.id
                WHERE DATE(s.timestamp) = ? AND s.cashier_id = ?
                ORDER BY s.timestamp DESC
            ''', (today, self.current_user['id']))
        sales = cursor.fetchall()
        cursor.execute('''
            SELECT SUM(total), COUNT(*),
            SUM(CASE WHEN payment_type = 'cash' THEN total ELSE 0 END),
            SUM(CASE WHEN payment_type = 'card' THEN total ELSE 0 END)
            FROM sales
            WHERE DATE(timestamp) = ?
        ''' + ('' if self.current_user['role'] == 'admin' else ' AND cashier_id = ?'),
        (today,) if self.current_user['role'] == 'admin' else (today, self.current_user['id']))
        result = cursor.fetchone()
        total_sum = result[0] or 0
        total_count = result[1] or 0
        cash_sum = result[2] or 0
        card_sum = result[3] or 0
        cursor.close()
        tree_frame = ttk.Frame(self.content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        tree = ttk.Treeview(tree_frame, columns=("time", "product", "qty", "total", "payment"),
                          show="headings", yscrollcommand=vsb.set)
        vsb.config(command=tree.yview)
        tree.heading("time", text="Время")
        tree.heading("product", text="Товар")
        tree.heading("qty", text="Кол-во")
        tree.heading("total", text="Сумма, ₽")
        tree.heading("payment", text="Оплата")
        tree.column("time", width=90, anchor="center")
        tree.column("product", width=380)
        tree.column("qty", width=80, anchor="center")
        tree.column("total", width=110, anchor="e")
        tree.column("payment", width=100, anchor="center")
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for sale in sales:
            if self.current_user['role'] == 'admin':
                name, qty, total, payment, cashier, ts = sale
                time = ts.split()[1][:5]
                display_name = name if name else f"[УДАЛЁН]"
                tree.insert("", "end", values=(time, f"{display_name} ({cashier})", qty, f"{total:.2f}",
                                             "Наличные" if payment == "cash" else "Карта"))
            else:
                name, qty, total, payment, ts = sale
                time = ts.split()[1][:5]
                display_name = name if name else f"[УДАЛЁН]"
                tree.insert("", "end", values=(time, display_name, qty, f"{total:.2f}",
                                             "Наличные" if payment == "cash" else "Карта"))
        stats_text = (
            f"Всего продаж: {total_count} шт | "
            f"Общая сумма: {total_sum:.2f}₽ | "
            f"Наличные: {cash_sum:.2f}₽ | "
            f"Карты: {card_sum:.2f}₽"
        )
        self.stats_label.config(text=stats_text)
        ttk.Button(self.footer_frame, text="Назад", command=self.main_menu, width=20).pack(side=tk.LEFT, padx=10)
        if self.current_user['role'] == 'admin':
            ttk.Button(self.footer_frame, text="Экспорт в CSV", command=lambda: self.export_sales_to_csv(), width=20).pack(side=tk.LEFT, padx=10)

# ==================== ЗАПУСК ПРИЛОЖЕНИЯ ====================
if __name__ == "__main__":
    root = tk.Tk()
    app = VapeShopApp(root)
    root.mainloop()