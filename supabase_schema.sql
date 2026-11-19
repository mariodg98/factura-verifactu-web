-- ============================================================================
-- ESQUEMA CLOUD SUPABASE (PostgreSQL) PARA FACTURA-VERIFACTU.ES
-- Soporta: Multi-usuario, Control de 15 días de prueba, Bloqueo 1 NIF vs Multi-NIF,
-- Facturas encadenadas SHA-256 (RD 1007/2023), Presupuestos, Gastos y Afiliados (35%/45%)
-- ============================================================================

-- 1. Perfiles de Cuenta y Suscripción
CREATE TABLE IF NOT EXISTS public.perfiles_cuenta (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    nombre_titular TEXT,
    plan_tipo TEXT DEFAULT 'single' CHECK (plan_tipo IN ('single', 'multi')),
    estado_suscripcion TEXT DEFAULT 'trial_15d' CHECK (estado_suscripcion IN ('trial_15d', 'active_annual', 'active_monthly', 'expired')),
    fecha_inicio_trial TIMESTAMPTZ DEFAULT NOW(),
    fecha_fin_trial TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '15 days'),
    codigo_afiliado_origen TEXT DEFAULT '',
    mi_codigo_afiliado TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Empresas / NIFs Emisores (1 NIF en plan 'single', ilimitados en plan 'multi')
CREATE TABLE IF NOT EXISTS public.empresas_emisoras (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.perfiles_cuenta(id) ON DELETE CASCADE,
    razon_social TEXT NOT NULL,
    nif_cif TEXT NOT NULL,
    email_facturacion TEXT,
    direccion_fiscal TEXT,
    ciudad_cp TEXT,
    iban_cobros TEXT,
    nif_bloqueado BOOLEAN DEFAULT TRUE,
    cert_vinculado BOOLEAN DEFAULT FALSE,
    cert_nombre_archivo TEXT,
    cert_titular_x509 TEXT,
    cert_valido_hasta TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Libro Registro Inalterable de Facturas VeriFactu (Orden HAC/1177/2024 AEAT)
CREATE TABLE IF NOT EXISTS public.facturas_verifactu (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.perfiles_cuenta(id) ON DELETE CASCADE,
    empresa_id UUID NOT NULL REFERENCES public.empresas_emisoras(id) ON DELETE CASCADE,
    tipo_factura TEXT DEFAULT 'F1' CHECK (tipo_factura IN ('F1', 'F2', 'R1')),
    factura_rectificada_num TEXT DEFAULT '',
    motivo_rectificacion TEXT DEFAULT '',
    serie TEXT NOT NULL,
    correlativo INTEGER NOT NULL,
    numero_oficial TEXT NOT NULL,
    fecha_expedicion DATE NOT NULL,
    cliente_nombre TEXT NOT NULL,
    cliente_nif TEXT NOT NULL,
    cliente_contacto TEXT,
    cliente_direccion TEXT,
    lineas_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    base_imponible NUMERIC(12,2) NOT NULL DEFAULT 0,
    iva_porcentaje NUMERIC(5,2) NOT NULL DEFAULT 21,
    cuota_iva NUMERIC(12,2) NOT NULL DEFAULT 0,
    irpf_porcentaje NUMERIC(5,2) NOT NULL DEFAULT 0,
    cuota_irpf NUMERIC(12,2) NOT NULL DEFAULT 0,
    importe_total NUMERIC(12,2) NOT NULL DEFAULT 0,
    prev_hash_sha256 TEXT NOT NULL,
    current_hash_sha256 TEXT NOT NULL,
    estado_aeat TEXT DEFAULT 'REGISTRO_SHA256',
    csv_aeat TEXT,
    xml_verifactu_aeat TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Presupuestos Desglosados (Convertibles a Factura en 1 Clic)
CREATE TABLE IF NOT EXISTS public.presupuestos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.perfiles_cuenta(id) ON DELETE CASCADE,
    empresa_id UUID NOT NULL REFERENCES public.empresas_emisoras(id) ON DELETE CASCADE,
    codigo_presupuesto TEXT NOT NULL,
    fecha DATE NOT NULL,
    cliente_nombre TEXT NOT NULL,
    cliente_nif TEXT,
    cliente_contacto TEXT,
    lineas_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    base_imponible NUMERIC(12,2) NOT NULL DEFAULT 0,
    iva_porcentaje NUMERIC(5,2) NOT NULL DEFAULT 21,
    irpf_porcentaje NUMERIC(5,2) NOT NULL DEFAULT 0,
    importe_total NUMERIC(12,2) NOT NULL DEFAULT 0,
    estado TEXT DEFAULT 'PENDIENTE' CHECK (estado IN ('PENDIENTE', 'FACTURADO')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Gastos y Facturas Recibidas (IVA Soportado Deducible Modelo 303)
CREATE TABLE IF NOT EXISTS public.gastos_deducibles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.perfiles_cuenta(id) ON DELETE CASCADE,
    empresa_id UUID NOT NULL REFERENCES public.empresas_emisoras(id) ON DELETE CASCADE,
    fecha DATE NOT NULL,
    proveedor TEXT NOT NULL,
    archivo_justificante TEXT,
    base_gasto NUMERIC(12,2) NOT NULL DEFAULT 0,
    iva_porcentaje NUMERIC(5,2) NOT NULL DEFAULT 21,
    cuota_iva_deducible NUMERIC(12,2) NOT NULL DEFAULT 0,
    importe_total NUMERIC(12,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Registro de Afiliados y Colectivos (35% Base / 45% +20 cuentas)
CREATE TABLE IF NOT EXISTS public.afiliados_conversiones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo_afiliado TEXT NOT NULL,
    usuario_referido_id UUID REFERENCES public.perfiles_cuenta(id) ON DELETE SET NULL,
    email_referido TEXT,
    estado TEXT DEFAULT 'TRIAL_15D' CHECK (estado IN ('TRIAL_15D', 'PAGADO')),
    importe_suscripcion NUMERIC(10,2) DEFAULT 0,
    porcentaje_comision NUMERIC(5,2) DEFAULT 35.00,
    comision_eur NUMERIC(10,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Habilitar Row Level Security (RLS) para aislamiento total entre usuarios
ALTER TABLE public.perfiles_cuenta ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.empresas_emisoras ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.facturas_verifactu ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.presupuestos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gastos_deducibles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Usuarios ven su propio perfil" ON public.perfiles_cuenta FOR ALL USING (auth.uid() = id);
CREATE POLICY "Usuarios gestionan sus empresas" ON public.empresas_emisoras FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Usuarios gestionan sus facturas" ON public.facturas_verifactu FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Usuarios gestionan sus presupuestos" ON public.presupuestos FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Usuarios gestionan sus gastos" ON public.gastos_deducibles FOR ALL USING (auth.uid() = user_id);
