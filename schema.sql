PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS restaurants (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
  tax_number TEXT NOT NULL DEFAULT '', logo_url TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'EGP', tax_rate REAL NOT NULL DEFAULT 14,
  service_rate REAL NOT NULL DEFAULT 12, qr_target TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, restaurant_id TEXT NOT NULL, name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '', price REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(restaurant_id) REFERENCES restaurants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY, restaurant_id TEXT NOT NULL, invoice_no INTEGER NOT NULL,
  business_name_snapshot TEXT NOT NULL, phone_snapshot TEXT NOT NULL DEFAULT '',
  address_snapshot TEXT NOT NULL DEFAULT '', tax_number_snapshot TEXT NOT NULL DEFAULT '',
  date TEXT NOT NULL, created_at TEXT NOT NULL, table_no TEXT NOT NULL DEFAULT '',
  cashier TEXT NOT NULL DEFAULT '', order_type TEXT NOT NULL DEFAULT 'داخل المطعم',
  payment_method TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'paid',
  subtotal REAL NOT NULL, discount REAL NOT NULL DEFAULT 0,
  taxable_base REAL NOT NULL, tax_rate REAL NOT NULL, tax_amount REAL NOT NULL,
  service_rate REAL NOT NULL, service_amount REAL NOT NULL, total REAL NOT NULL,
  notes TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL,
  UNIQUE(restaurant_id, invoice_no),
  FOREIGN KEY(restaurant_id) REFERENCES restaurants(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS invoice_items (
  id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, product_id TEXT,
  name_snapshot TEXT NOT NULL, unit_price REAL NOT NULL, quantity REAL NOT NULL,
  line_total REAL NOT NULL,
  FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY, restaurant_id TEXT NOT NULL, date TEXT NOT NULL,
  amount REAL NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  payment_method TEXT NOT NULL DEFAULT 'نقدي', created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(restaurant_id) REFERENCES restaurants(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS closings (
  id TEXT PRIMARY KEY, restaurant_id TEXT NOT NULL, business_date TEXT NOT NULL,
  invoice_count INTEGER NOT NULL, gross_subtotal REAL NOT NULL,
  discounts REAL NOT NULL, net_sales REAL NOT NULL, tax_total REAL NOT NULL,
  service_total REAL NOT NULL, cash_sales REAL NOT NULL, card_sales REAL NOT NULL,
  other_sales REAL NOT NULL, expenses_total REAL NOT NULL,
  expected_cash REAL NOT NULL, actual_cash REAL NOT NULL, cash_difference REAL NOT NULL,
  notes TEXT NOT NULL DEFAULT '', closed_by TEXT NOT NULL, closed_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'closed',
  FOREIGN KEY(restaurant_id) REFERENCES restaurants(id),
  FOREIGN KEY(closed_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY, restaurant_id TEXT NOT NULL, user_id TEXT NOT NULL,
  action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(restaurant_id) REFERENCES restaurants(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_invoices_rest_date ON invoices(restaurant_id,date);
CREATE INDEX IF NOT EXISTS idx_items_invoice ON invoice_items(invoice_id);
CREATE INDEX IF NOT EXISTS idx_expenses_rest_date ON expenses(restaurant_id,date);
CREATE INDEX IF NOT EXISTS idx_closings_rest_date ON closings(restaurant_id,business_date);
